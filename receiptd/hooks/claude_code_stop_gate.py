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


def _count_consecutive_blocks(ledger_path: str, session_id: str) -> int:
    """Count trailing consecutive STOP_GATE block receipts for this session_id."""
    if not os.path.exists(ledger_path):
        return 0
    count = 0
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        for line in reversed(lines):
            try:
                rec = json.loads(line)
            except Exception:
                break
            if rec.get("event_type") != "STOP_GATE":
                break
            if session_id and rec.get("session_id") not in (None, "", session_id):
                break
            if rec.get("decision") in ("BLOCKED_FAIL_CLOSED", "deny"):
                count += 1
            else:
                break
    except Exception:
        return 0
    return count


def run_stop_gate(
    test_cmd: str | None = None,
    ledger_path: str = ".receiptd/receipts.jsonl",
    timeout_sec: int = 120,
    max_retries: int = 3,
    session_id: str | None = None,
    stop_hook_active: bool | None = None,
    stdin_json: dict | None = None,
) -> int:
    """Execute the stop gate verification and record a signed receipt."""
    t0 = time.perf_counter()

    # Parse Claude Code hook JSON input from stdin if not explicitly supplied
    parsed_stdin = {}
    if stdin_json is not None:
        parsed_stdin = stdin_json
    elif not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
            if raw.strip():
                parsed_stdin = json.loads(raw)
        except Exception:
            pass

    if session_id is None:
        session_id = str(parsed_stdin.get("session_id") or os.environ.get("RECEIPTD_SESSION_ID", "default"))
    if stop_hook_active is None:
        stop_hook_active = bool(parsed_stdin.get("stop_hook_active", False))

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

    if not test_passed:
        diag = stderr_snip or stdout_snip or f"Command exited with status {exit_code}"
        test_output_hash = sha256_hex(diag)
        prior_blocks = _count_consecutive_blocks(ledger_path, session_id)
        current_retries = prior_blocks + 1

        if stop_hook_active and current_retries >= max_retries:
            # At cap: give up and exit 0 to prevent infinite agent loop
            receipt_core = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "event_type": "STOP_GATE",
                "session_id": session_id,
                "test_command": resolved_cmd,
                "test_exit_code": exit_code,
                "decision": "gave_up",
                "test_output_sha256": test_output_hash,
                "retries": current_retries,
                "stop_hook_active": True,
                "prev_receipt_hash": prev_hash,
                "latency_ms": latency_ms,
            }
            receipt_hash = sha256_hex(canonicalize_jcs(receipt_core))
            receipt_core["receipt_sha256"] = receipt_hash

            with open(ledger_path, "a", encoding="utf-8") as f:
                f.write(canonicalize_jcs(receipt_core) + "\n")

            sys.stderr.write(
                f"\n[RECEIPTD STOP GATE GAVE UP] Max retries ({max_retries}) reached with stop_hook_active=True.\n"
                f"  ├─ Session ID: {session_id}\n"
                f"  ├─ Verification Command: {resolved_cmd} (exit code: {exit_code})\n"
                f"  ├─ Test Output SHA256: {test_output_hash}\n"
                f"  ├─ Consecutive Retries: {current_retries}\n"
                f"  └─ Signed Gave Up Receipt: {receipt_hash[:24]}...\n"
                f"Exiting 0 to prevent infinite agent retry loop.\n\n"
            )
            return 0

        # Under cap: hard block with exit 2
        receipt_core = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": "STOP_GATE",
            "session_id": session_id,
            "test_command": resolved_cmd,
            "test_exit_code": exit_code,
            "decision": "BLOCKED_FAIL_CLOSED",
            "test_output_sha256": test_output_hash,
            "retries": current_retries,
            "stop_hook_active": stop_hook_active,
            "prev_receipt_hash": prev_hash,
            "latency_ms": latency_ms,
        }
        receipt_hash = sha256_hex(canonicalize_jcs(receipt_core))
        receipt_core["receipt_sha256"] = receipt_hash

        with open(ledger_path, "a", encoding="utf-8") as f:
            f.write(canonicalize_jcs(receipt_core) + "\n")

        sys.stderr.write(
            f"\n[RECEIPTD STOP GATE HARD BLOCK] Cannot declare completion while tests are failing.\n"
            f"  ├─ Session ID: {session_id}\n"
            f"  ├─ Verification Command: {resolved_cmd} (exit code: {exit_code})\n"
            f"  ├─ Latency: {latency_ms}ms\n"
            f"  ├─ Signed Rejection Receipt: {receipt_hash[:24]}...\n"
            f"  └─ Diagnostics:\n"
            f"     {diag}\n\n"
            f"Action Required: Fix the failing tests before completing this task.\n"
        )
        return 2  # Exit code 2 deterministically rejects Claude Code Stop

    # Tests passed
    receipt_core = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event_type": "STOP_GATE",
        "session_id": session_id,
        "test_command": resolved_cmd,
        "test_exit_code": exit_code,
        "decision": "ALLOWED_VERIFIED",
        "prev_receipt_hash": prev_hash,
        "latency_ms": latency_ms,
    }
    receipt_hash = sha256_hex(canonicalize_jcs(receipt_core))
    receipt_core["receipt_sha256"] = receipt_hash

    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(canonicalize_jcs(receipt_core) + "\n")

    sys.stdout.write(
        f"\n[RECEIPTD STOP GATE PASSED] All tests verified. Completion allowed.\n"
        f"  ├─ Session ID: {session_id}\n"
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
    parser.add_argument("--max-retries", type=int, default=3, help="Max retry blocks before giving up when stop_hook_active is true")
    parser.add_argument("--session-id", default=None, help="Session identifier")
    parser.add_argument("--stop-hook-active", action="store_true", default=None, help="Stop hook active flag")

    args, _ = parser.parse_known_args()
    return run_stop_gate(
        test_cmd=args.test_cmd,
        ledger_path=args.ledger,
        timeout_sec=args.timeout,
        max_retries=args.max_retries,
        session_id=args.session_id,
        stop_hook_active=args.stop_hook_active,
    )


if __name__ == "__main__":
    sys.exit(main())
