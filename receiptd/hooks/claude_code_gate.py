#!/usr/bin/env python3
"""
Receiptd Deterministic PreToolUse Gate for Claude Code.
Reads tool invocation JSON from stdin.
Exit 0 -> Tool allowed + signed Ed25519 receipt appended.
Exit 2 -> Tool HARD BLOCKED (fail-closed) + signed rejection receipt emitted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ..crypto import (
    SigningKey,
    canonical_json,
    get_signing_key,
)
from ..ledger import (
    GENESIS_HASH,
    append_ledger_entry,
    build_signed_checkpoint,
    build_signed_receipt,
    build_unsigned_signing_error_receipt,
    read_ledger_state,
)

# Default high-risk deterministic signatures
DEFAULT_RULES = [
    ("POL-01:ENV_EXFILTRATION", 95, re.compile(r"(\.env|AWS_SECRET|PRIVATE_KEY|curl\s+.*-d|wget\s+.*--post)", re.I)),
    ("POL-02:DESTRUCTIVE_DDL_OR_FS", 90, re.compile(r"(\bDROP\s+TABLE\b|\bTRUNCATE\b|rm\s+-rf\s+[/~*]|mkfs|/etc/passwd)", re.I)),
    ("POL-03:PRIVILEGE_ESCALATION", 85, re.compile(r"(\bsudo\b|chmod\s+777|chown\s+root|\.claude/settings\.json)", re.I)),
]


def canonicalize_jcs(obj) -> str:
    """Deterministic canonical JSON serialization (sorted keys, compact)."""
    return canonical_json(obj).decode("utf-8")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def evaluate_payload(payload: dict) -> tuple[bool, int, list[str]]:
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return True, 100, ["MISSING_REQUIRED_FIELD"]

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return True, 100, ["MISSING_REQUIRED_FIELD"]

    tool_name = tool_name.strip()
    tool_input_jcs = canonicalize_jcs(tool_input)
    combined = f"{tool_name} {tool_input_jcs}"

    score = 10
    triggered = []
    for rule_id, weight, pattern in DEFAULT_RULES:
        if pattern.search(combined):
            score = min(100, score + weight)
            triggered.append(rule_id)

    # Note: POL-03 specifically prevents the agent from editing .claude/settings.json to unhook Receiptd
    blocked = len(triggered) > 0 or score >= 75
    return blocked, score, triggered


def main() -> int:
    t0 = time.perf_counter()
    try:
        raw_stdin = sys.stdin.read()
        if not raw_stdin.strip():
            sys.stderr.write("[RECEIPTD FAIL-CLOSED] Empty stdin frame rejected.\n")
            return 2

        payload = json.loads(raw_stdin)
        if not isinstance(payload, dict):
            sys.stderr.write("[RECEIPTD FAIL-CLOSED] Payload must be a JSON object.\n")
            return 2
        blocked, score, triggered = evaluate_payload(payload)
        decision = "deny" if blocked else "allow"
        reason = f"triggered rules: {', '.join(triggered)}" if blocked else "allowed"

        # Resolve ledger path
        ledger_path = ".receiptd/receipts.jsonl"
        for i, arg in enumerate(sys.argv):
            if arg == "--ledger" and i + 1 < len(sys.argv):
                ledger_path = sys.argv[i + 1]
                break

        if not os.path.exists(ledger_path) and os.path.exists(".birkin/receipts.jsonl"):
            ledger_path = ".birkin/receipts.jsonl"

        # Checkpoint interval
        checkpoint_interval = 100
        for i, arg in enumerate(sys.argv):
            if arg == "--checkpoint-interval" and i + 1 < len(sys.argv):
                try:
                    checkpoint_interval = int(sys.argv[i + 1])
                except ValueError:
                    pass
                break
        if "RECEIPTD_CHECKPOINT_INTERVAL" in os.environ:
            try:
                checkpoint_interval = int(os.environ["RECEIPTD_CHECKPOINT_INTERVAL"])
            except ValueError:
                pass

        # Policy SHA-256
        policy_sha256 = sha256_hex("DEFAULT_RULES:POL-01,POL-02,POL-03")
        for i, arg in enumerate(sys.argv):
            if arg == "--policy" and i + 1 < len(sys.argv):
                p_file = Path(sys.argv[i + 1])
                if p_file.exists():
                    policy_sha256 = sha256_hex(p_file.read_bytes())
                break

        tool_name = str(payload.get("tool_name", ""))
        tool_input = payload.get("tool_input", {})
        args_sha256 = sha256_hex(canonical_json(tool_input))
        session_id = str(payload.get("session_id") or os.environ.get("RECEIPTD_SESSION_ID", "default"))

        # Read existing ledger state
        prev_hash, last_cp_hash, receipt_count, last_cp_seq, uncheckpointed = read_ledger_state(ledger_path)
        seq = receipt_count + 1
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        # Attempt to load signing key
        sk: SigningKey
        try:
            sk = get_signing_key()
        except Exception:
            # Signing failure must fail-closed with exit 2 and write an unsigned deny receipt
            unsigned_receipt = build_unsigned_signing_error_receipt(
                v=1,
                seq=seq,
                ts=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                tool=tool_name,
                args_sha256=args_sha256,
                decision="deny",
                rule_ids=triggered,
                blast_radius=score,
                reason="receiptd: signing unavailable",
                policy_sha256=policy_sha256,
                prev_hash=prev_hash,
                extra_fields={"latency_ms": latency_ms, "tool_input": tool_input},
            )
            append_ledger_entry(ledger_path, unsigned_receipt)
            sys.stderr.write("receiptd: signing unavailable\n")
            return 2

        # Key loaded successfully: construct signed receipt
        receipt = build_signed_receipt(
            sk=sk,
            v=1,
            seq=seq,
            ts=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            tool=tool_name,
            args_sha256=args_sha256,
            decision=decision,
            rule_ids=triggered,
            blast_radius=score,
            reason=reason,
            policy_sha256=policy_sha256,
            prev_hash=prev_hash,
            extra_fields={"latency_ms": latency_ms, "tool_input": tool_input},
        )
        append_ledger_entry(ledger_path, receipt)

        # Write Merkle checkpoint if interval reached
        uncheckpointed_hashes = [r["hash"] for r in uncheckpointed] + [receipt["hash"]]
        if len(uncheckpointed_hashes) >= checkpoint_interval:
            from_seq = last_cp_seq + 1
            to_seq = seq
            cp = build_signed_checkpoint(
                sk=sk,
                from_seq=from_seq,
                to_seq=to_seq,
                leaf_hashes=uncheckpointed_hashes,
                prev_checkpoint_hash=last_cp_hash,
            )
            append_ledger_entry(ledger_path, cp)

        if blocked:
            sys.stderr.write(
                f"\n[RECEIPTD HARD BLOCK] {decision.upper()} in {latency_ms}ms\n"
                f"  ├─ Tool: {tool_name}\n"
                f"  ├─ Blast Score: {score}/100 ({', '.join(triggered)})\n"
                f"  └─ Signed Receipt SHA-256: {receipt['hash'][:24]}...\n"
            )
            return 2  # Exit code 2 deterministically halts Claude Code tool execution

        return 0

    except Exception as exc:
        # Fail-closed guarantee: any parser/IO error halts execution
        sys.stderr.write(f"[RECEIPTD FAIL-CLOSED EXCEPTION] Execution halted: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
