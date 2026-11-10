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
import threading
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


# Hook deadline. Claude Code lets the tool call through when a PreToolUse hook
# times out, so the gate must decide (and exit 2) before that can happen.
# Keep the deadline below the hook "timeout" written by `receiptd init`.
DEFAULT_DEADLINE_MS = 5000
MIN_DEADLINE_MS = 100
MAX_DEADLINE_MS = 30000
# After the deadline fires, the watchdog gets this long to write a deny
# receipt before the process is killed with exit 2 regardless.
DEADLINE_GRACE_S = 1.0

# Held for every ledger write so the watchdog never cuts a write in half.
_LEDGER_LOCK = threading.Lock()
# What the watchdog needs to write a deny receipt. "finished" is set under
# _LEDGER_LOCK in the same block as the final ledger write.
_CTX: dict = {"finished": False}


def resolve_deadline_ms(environ=None) -> int:
    """Read RECEIPTD_HOOK_DEADLINE_MS, clamped. Bad values use the default."""
    environ = os.environ if environ is None else environ
    raw = environ.get("RECEIPTD_HOOK_DEADLINE_MS")
    if raw is None:
        return DEFAULT_DEADLINE_MS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_DEADLINE_MS
    return max(MIN_DEADLINE_MS, min(MAX_DEADLINE_MS, value))


def _resolve_ledger_path(argv: list[str]) -> str:
    ledger_path = ".receiptd/receipts.jsonl"
    for i, arg in enumerate(argv):
        if arg == "--ledger" and i + 1 < len(argv):
            ledger_path = argv[i + 1]
            break
    if not os.path.exists(ledger_path) and os.path.exists(".birkin/receipts.jsonl"):
        ledger_path = ".birkin/receipts.jsonl"
    return ledger_path


def _write_deadline_receipt(deadline_ms: int) -> None:
    """Append an unsigned deny receipt. Unsigned because key loading may be what hung."""
    ledger_path = _CTX["ledger_path"]
    prev_hash, _, receipt_count, _, _ = read_ledger_state(ledger_path)
    tool_input = _CTX.get("tool_input", {})
    receipt = build_unsigned_signing_error_receipt(
        v=1,
        seq=receipt_count + 1,
        ts=datetime.now(timezone.utc).isoformat(),
        session_id=_CTX.get("session_id", "default"),
        tool=_CTX.get("tool_name", ""),
        args_sha256=sha256_hex(canonical_json(tool_input)),
        decision="deny",
        rule_ids=["HOOK_DEADLINE_EXCEEDED"],
        blast_radius=100,
        reason=f"receiptd: hook deadline exceeded ({deadline_ms}ms)",
        policy_sha256=_CTX.get("policy_sha256", ""),
        prev_hash=prev_hash,
        extra_fields={"latency_ms": deadline_ms, "tool_input": tool_input},
    )
    append_ledger_entry(ledger_path, receipt)


def _on_deadline(deadline_ms: int) -> None:
    """Watchdog: deny when the gate has not decided in time."""
    killer = threading.Timer(DEADLINE_GRACE_S, os._exit, args=(2,))
    killer.daemon = True
    killer.start()
    try:
        if _LEDGER_LOCK.acquire(timeout=DEADLINE_GRACE_S / 2):
            if _CTX["finished"]:
                # The gate decided and recorded it just in time; let it return.
                killer.cancel()
                _LEDGER_LOCK.release()
                return
            sys.stderr.write(
                f"[RECEIPTD FAIL-CLOSED] Hook exceeded {deadline_ms}ms deadline; denying.\n"
            )
            sys.stderr.flush()
            if _CTX.get("ledger_path"):
                _write_deadline_receipt(deadline_ms)
        else:
            sys.stderr.write(
                f"[RECEIPTD FAIL-CLOSED] Hook exceeded {deadline_ms}ms deadline; denying.\n"
            )
            sys.stderr.flush()
    except Exception:
        pass
    os._exit(2)


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
    deadline_ms = resolve_deadline_ms()
    _CTX.clear()
    _CTX["finished"] = False
    watchdog = threading.Timer(deadline_ms / 1000.0, _on_deadline, args=(deadline_ms,))
    watchdog.daemon = True
    watchdog.start()
    try:
        return _run()
    finally:
        if _LEDGER_LOCK.acquire(timeout=DEADLINE_GRACE_S):
            _CTX["finished"] = True
            _LEDGER_LOCK.release()
        watchdog.cancel()


def _run() -> int:
    t0 = time.perf_counter()
    try:
        _CTX["ledger_path"] = _resolve_ledger_path(sys.argv)
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

        ledger_path = _CTX["ledger_path"]

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
        _CTX.update(
            tool_name=tool_name,
            tool_input=tool_input,
            session_id=session_id,
            policy_sha256=policy_sha256,
        )

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
            with _LEDGER_LOCK:
                append_ledger_entry(ledger_path, unsigned_receipt)
                _CTX["finished"] = True
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
        # Receipt, checkpoint, and "finished" go in one locked block so the
        # watchdog sees either nothing written or the whole decision.
        with _LEDGER_LOCK:
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
            _CTX["finished"] = True

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
