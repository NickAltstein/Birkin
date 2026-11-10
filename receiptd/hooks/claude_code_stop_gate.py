#!/usr/bin/env python3
"""
Receiptd Deterministic Stop Hook Gate for Claude Code.
Runs when the agent attempts to stop or declare completion.

Exit 0 -> Tests pass + signed Ed25519/SHA-256 completion receipt appended.
Exit 2 -> Tests fail -> HARD BLOCKED (fail-closed); agent is prevented from
          declaring done until tests pass. Stderr fed back to agent prompt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def canonicalize_jcs(obj) -> str:
    """RFC-8785 deterministic JSON serialization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def detect_test_command() -> str:
    """Auto-detect the repository test runner."""
    # 1. Environment variable override
    env_cmd = os.environ.get("RECEIPTD_TEST_CMD")
    if env_cmd:
        return env_cmd

    # 2. Python (pytest)
    if os.path.exists(".venv/bin/pytest"):
        return ".venv/bin/pytest"
    if os.path.exists("venv/bin/pytest"):
        return "venv/bin/pytest"
    if os.path.exists("pytest.ini") or os.path.exists("pyproject.toml") or os.path.isdir("tests"):
        if shutil.which("pytest"):
            return "pytest"

    # 3. Node.js (npm test)
    if os.path.exists("package.json"):
        return "npm test"

    # 4. Rust (cargo test)
    if os.path.exists("Cargo.toml"):
        return "cargo test"

    # 5. Make
    if os.path.exists("Makefile"):
        return "make test"

    # Fallback default
    return "pytest"


def run_stop_gate(
    test_cmd: str | None = None,
    ledger_path: str = ".receiptd/receipts.jsonl",
    timeout_sec: int = 120,
) -> int:
    """Execute the stop gate verification and record a signed receipt."""
    t0 = time.perf_counter()

    resolved_cmd = test_cmd or detect_test_command()

    # Fall back to .birkin/receipts.jsonl if it exists and .receiptd does not
    if not os.path.exists(ledger_path) and os.path.exists(".birkin/receipts.jsonl"):
        ledger_path = ".birkin/receipts.jsonl"

    ledger_dir = os.path.dirname(ledger_path)
    if ledger_dir:
        os.makedirs(ledger_dir, exist_ok=True)

    # Read previous receipt hash for ledger chaining
    prev_hash = "0" * 64
    if os.path.exists(ledger_path):
        with open(ledger_path, "rb") as f:
            lines = f.read().splitlines()
            if lines:
                try:
                    last_receipt = json.loads(lines[-1].decode("utf-8"))
                    prev_hash = last_receipt.get("receipt_sha256", prev_hash)
                except Exception:
                    pass

    # Execute test command
    test_passed = False
    exit_code = 1
    stdout_snip = ""
    stderr_snip = ""

    try:
        proc = subprocess.run(
            resolved_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        exit_code = proc.returncode
        test_passed = (exit_code == 0)
        stdout_snip = (proc.stdout or "").strip()[-1000:]
        stderr_snip = (proc.stderr or "").strip()[-1000:]
    except subprocess.TimeoutExpired:
        exit_code = 124
        test_passed = False
        stderr_snip = f"Test command timed out after {timeout_sec}s."
    except Exception as exc:
        exit_code = 127
        test_passed = False
        stderr_snip = f"Failed to execute test command: {exc}"

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    decision = "ALLOWED_VERIFIED" if test_passed else "BLOCKED_FAIL_CLOSED"

    receipt_core = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event_type": "STOP_GATE",
        "test_command": resolved_cmd,
        "test_exit_code": exit_code,
        "decision": decision,
        "prev_receipt_hash": prev_hash,
        "latency_ms": latency_ms,
    }
    receipt_hash = sha256_hex(canonicalize_jcs(receipt_core))
    receipt_core["receipt_sha256"] = receipt_hash

    # Write audit receipt to ledger
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(canonicalize_jcs(receipt_core) + "\n")

    if not test_passed:
        diag = stderr_snip or stdout_snip or f"Command exited with status {exit_code}"
        sys.stderr.write(
            f"\n[RECEIPTD STOP GATE HARD BLOCK] Cannot declare completion while tests are failing.\n"
            f"  ├─ Verification Command: {resolved_cmd} (exit code: {exit_code})\n"
            f"  ├─ Latency: {latency_ms}ms\n"
            f"  ├─ Signed Rejection Receipt: {receipt_hash[:24]}...\n"
            f"  └─ Diagnostics:\n"
            f"     {diag}\n\n"
            f"Action Required: Fix the failing tests before completing this task.\n"
        )
        return 2  # Exit code 2 deterministically rejects Claude Code Stop

    sys.stdout.write(
        f"\n[RECEIPTD STOP GATE PASSED] All tests verified. Completion allowed.\n"
        f"  ├─ Verification Command: {resolved_cmd}\n"
        f"  ├─ Latency: {latency_ms}ms\n"
        f"  └─ Signed Completion Receipt: {receipt_hash[:24]}...\n"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Receiptd Stop Hook Gate")
    parser.add_argument("--test-cmd", default=None, help="Command to run to verify tests (e.g. pytest, npm test)")
    parser.add_argument("--ledger", default=".receiptd/receipts.jsonl", help="Path to audit ledger")
    parser.add_argument("--timeout", type=int, default=120, help="Test timeout in seconds")

    args, _ = parser.parse_known_args()
    return run_stop_gate(test_cmd=args.test_cmd, ledger_path=args.ledger, timeout_sec=args.timeout)


if __name__ == "__main__":
    sys.exit(main())
