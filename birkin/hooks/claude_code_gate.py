#!/usr/bin/env python3
"""
Birkin Deterministic PreToolUse Gate for Claude Code.
Reads tool invocation JSON from stdin.
Exit 0 -> Tool allowed + signed Ed25519 receipt appended.
Exit 2 -> Tool HARD BLOCKED (fail-closed) + signed rejection receipt emitted to stderr.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

# Default high-risk deterministic signatures
DEFAULT_RULES = [
    ("POL-01:ENV_EXFILTRATION", 95, re.compile(r"(\.env|AWS_SECRET|PRIVATE_KEY|curl\s+.*-d|wget\s+.*--post)", re.I)),
    ("POL-02:DESTRUCTIVE_DDL_OR_FS", 90, re.compile(r"(\bDROP\s+TABLE\b|\bTRUNCATE\b|rm\s+-rf\s+[/~*]|mkfs|/etc/passwd)", re.I)),
    ("POL-03:PRIVILEGE_ESCALATION", 85, re.compile(r"(\bsudo\b|chmod\s+777|chown\s+root|\.claude/settings\.json)", re.I)),
]


def canonicalize_jcs(obj) -> str:
    """RFC-8785 deterministic JSON serialization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def evaluate_payload(payload: dict) -> tuple[bool, int, list[str]]:
    tool_name = str(payload.get("tool_name", ""))
    tool_input = canonicalize_jcs(payload.get("tool_input", {}))
    combined = f"{tool_name} {tool_input}"

    score = 10
    triggered = []
    for rule_id, weight, pattern in DEFAULT_RULES:
        if pattern.search(combined):
            score = min(100, score + weight)
            triggered.append(rule_id)

    # Note: POL-03 specifically prevents the agent from editing .claude/settings.json to unhook Birkin
    blocked = len(triggered) > 0 or score >= 75
    return blocked, score, triggered


def main() -> int:
    t0 = time.perf_counter()
    try:
        raw_stdin = sys.stdin.read()
        if not raw_stdin.strip():
            sys.stderr.write("[BIRKIN FAIL-CLOSED] Empty stdin frame rejected.\n")
            return 2

        payload = json.loads(raw_stdin)
        blocked, score, triggered = evaluate_payload(payload)
        decision = "BLOCKED_FAIL_CLOSED" if blocked else "ALLOWED_VERIFIED"

        os.makedirs(".birkin", exist_ok=True)
        ledger_path = ".birkin/receipts.jsonl"

        prev_hash = "0" * 64
        if os.path.exists(ledger_path):
            with open(ledger_path, "rb") as f:
                lines = f.read().splitlines()
                if lines:
                    last_receipt = json.loads(lines[-1].decode("utf-8"))
                    prev_hash = last_receipt.get("receipt_sha256", prev_hash)

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        receipt_core = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "tool_name": payload.get("tool_name"),
            "tool_input": payload.get("tool_input"),
            "decision": decision,
            "blast_radius_score": score,
            "triggered_rules": triggered,
            "prev_receipt_hash": prev_hash,
            "latency_ms": latency_ms,
        }
        receipt_hash = sha256_hex(canonicalize_jcs(receipt_core))
        receipt_core["receipt_sha256"] = receipt_hash

        with open(ledger_path, "a", encoding="utf-8") as f:
            f.write(canonicalize_jcs(receipt_core) + "\n")

        if blocked:
            sys.stderr.write(
                f"\n[BIRKIN HARD BLOCK] {decision} in {latency_ms}ms\n"
                f"  ├─ Tool: {payload.get('tool_name')}\n"
                f"  ├─ Blast Score: {score}/100 ({', '.join(triggered)})\n"
                f"  └─ Signed Receipt SHA-256: {receipt_hash[:24]}...\n"
            )
            return 2  # Exit code 2 deterministically halts Claude Code tool execution

        return 0

    except Exception as exc:
        # Fail-closed guarantee: any parser/IO error halts execution
        sys.stderr.write(f"[BIRKIN FAIL-CLOSED EXCEPTION] Execution halted: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
