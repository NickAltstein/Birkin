#!/usr/bin/env python3
"""
Receiptd Deterministic Stop Hook Gate for Claude Code.
Runs when the agent attempts to stop or declare completion.

Exit 0 -> Tests pass + signed Ed25519 completion receipt + Merkle checkpoint appended.
Exit 2 -> Tests fail -> HARD BLOCKED (fail-closed); agent is prevented from
          declaring done until tests pass. Stderr fed back to agent prompt.
Exit 0 -> Tests fail but stop_hook_active=True and retries exceed max_retries
          -> gives up to break loop, appends signed 'gave_up' receipt.
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


def canonicalize_jcs(obj) -> str:
    """Canonical JSON (sorted keys, compact separators). Not full RFC 8785."""
    return canonical_json(obj).decode("utf-8")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def detect_test_command() -> str:
    """Auto-detect the repository test runner."""
    env_cmd = os.environ.get("RECEIPTD_TEST_CMD")
    if env_cmd:
        return env_cmd

    if os.path.exists(".venv/bin/pytest"):
        return ".venv/bin/pytest"
    if os.path.exists("venv/bin/pytest"):
        return "venv/bin/pytest"
    if os.path.exists("pytest.ini") or os.path.exists("pyproject.toml") or os.path.isdir("tests"):
        if shutil.which("pytest"):
            return "pytest"

    if os.path.exists("package.json"):
        return "npm test"

    if os.path.exists("Cargo.toml"):
        return "cargo test"

    if os.path.exists("Makefile"):
        return "make test"

    return "pytest"


def get_stop_gate_state_path(ledger_path: str | None = None, explicit_path: str | None = None) -> Path:
    if explicit_path:
        return Path(explicit_path)
    if os.environ.get("RECEIPTD_STOP_GATE_STATE"):
        return Path(os.environ["RECEIPTD_STOP_GATE_STATE"])
    if ledger_path:
        ledger_dir = Path(ledger_path).resolve().parent
        if "tmp" in str(ledger_dir).lower() or "pytest" in str(ledger_dir).lower():
            return ledger_dir / "stop_gate_state.json"
    key_dir = Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
    return key_dir / "stop_gate_state.json"


def load_state(state_file: Path) -> dict:
    if state_file.exists():
        try:
            return json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            return {"sessions": {}}
    return {"sessions": {}}


def save_state(state_file: Path, state: dict) -> None:
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(state_file, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def run_stop_gate(
    test_cmd: str | None = None,
    ledger_path: str = ".receiptd/receipts.jsonl",
    timeout_sec: int = 120,
    max_retries: int = 3,
    session_id: str | None = None,
    stop_hook_active: bool | None = None,
    stdin_json: dict | None = None,
    state_file_path: str | None = None,
) -> int:
    """Execute the stop gate verification, enforce retry ceilings, and record a signed receipt."""
    t0 = time.perf_counter()

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

    if not os.path.exists(ledger_path) and os.path.exists(".birkin/receipts.jsonl"):
        ledger_path = ".birkin/receipts.jsonl"

    state_file = get_stop_gate_state_path(ledger_path=ledger_path, explicit_path=state_file_path)
    state = load_state(state_file)
    sessions = state.setdefault("sessions", {})
    session_info = sessions.setdefault(session_id, {"retries": 0, "updated_at": ""})

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
    diag = stderr_snip or stdout_snip or f"Command exited with status {exit_code}"
    test_output_hash = sha256_hex(diag)

    # Read ledger state
    prev_hash, last_cp_hash, receipt_count, last_cp_seq, uncheckpointed = read_ledger_state(ledger_path)
    seq = receipt_count + 1

    sk: SigningKey | None = None
    try:
        sk = get_signing_key()
    except Exception:
        sk = None

    if test_passed:
        # Reset retry counter on success
        if session_id in sessions:
            sessions.pop(session_id, None)
            save_state(state_file, state)

        decision = "ALLOWED_VERIFIED"
        reason = f"All tests verified: {resolved_cmd}"

        extra = {
            "event_type": "STOP_GATE",
            "test_command": resolved_cmd,
            "test_exit_code": exit_code,
            "retries": 0,
            "stop_hook_active": stop_hook_active,
            "latency_ms": latency_ms,
        }

        if sk is None:
            receipt = build_unsigned_signing_error_receipt(
                v=1,
                seq=seq,
                ts=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                tool="stop_gate",
                args_sha256=sha256_hex(resolved_cmd),
                decision="deny",
                rule_ids=["RULE:TESTS_PASS"],
                blast_radius=0,
                reason="receiptd: signing unavailable",
                policy_sha256=sha256_hex(resolved_cmd),
                prev_hash=prev_hash,
                extra_fields=extra,
            )
            append_ledger_entry(ledger_path, receipt)
            sys.stderr.write("receiptd: signing unavailable\n")
            return 2

        receipt = build_signed_receipt(
            sk=sk,
            v=1,
            seq=seq,
            ts=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            tool="stop_gate",
            args_sha256=sha256_hex(resolved_cmd),
            decision=decision,
            rule_ids=["RULE:TESTS_PASS"],
            blast_radius=0,
            reason=reason,
            policy_sha256=sha256_hex(resolved_cmd),
            prev_hash=prev_hash,
            extra_fields=extra,
        )
        append_ledger_entry(ledger_path, receipt)

        # Seal ledger with signed Merkle checkpoint at session completion
        uncheckpointed_hashes = [r["hash"] for r in uncheckpointed] + [receipt["hash"]]
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

        sys.stdout.write(
            f"\n[RECEIPTD STOP GATE PASSED] All tests verified. Completion allowed.\n"
            f"  ├─ Session ID: {session_id}\n"
            f"  ├─ Verification Command: {resolved_cmd}\n"
            f"  ├─ Latency: {latency_ms}ms\n"
            f"  └─ Signed Completion Receipt: {receipt['hash'][:24]}...\n"
        )
        return 0

    # Tests failed
    current_retries = session_info.get("retries", 0) + 1
    session_info["retries"] = current_retries
    session_info["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_state(state_file, state)

    is_gave_up = bool(stop_hook_active and current_retries >= max_retries)
    decision = "gave_up" if is_gave_up else "BLOCKED_FAIL_CLOSED"
    reason = (
        f"Max retries ({max_retries}) reached with stop_hook_active=True: {diag[:200]}"
        if is_gave_up
        else f"Tests failed ({exit_code}): {diag[:200]}"
    )

    extra = {
        "event_type": "STOP_GATE",
        "test_command": resolved_cmd,
        "test_exit_code": exit_code,
        "test_output_sha256": test_output_hash,
        "retries": current_retries,
        "stop_hook_active": stop_hook_active,
        "latency_ms": latency_ms,
    }

    if sk is None:
        receipt = build_unsigned_signing_error_receipt(
            v=1,
            seq=seq,
            ts=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            tool="stop_gate",
            args_sha256=sha256_hex(resolved_cmd),
            decision="deny",
            rule_ids=["RULE:TESTS_PASS"],
            blast_radius=100,
            reason="receiptd: signing unavailable",
            policy_sha256=sha256_hex(resolved_cmd),
            prev_hash=prev_hash,
            extra_fields=extra,
        )
        append_ledger_entry(ledger_path, receipt)
        sys.stderr.write("receiptd: signing unavailable\n")
        return 2

    receipt = build_signed_receipt(
        sk=sk,
        v=1,
        seq=seq,
        ts=datetime.now(timezone.utc).isoformat(),
        session_id=session_id,
        tool="stop_gate",
        args_sha256=sha256_hex(resolved_cmd),
        decision=decision,
        rule_ids=["RULE:TESTS_PASS"],
        blast_radius=100,
        reason=reason,
        policy_sha256=sha256_hex(resolved_cmd),
        prev_hash=prev_hash,
        extra_fields=extra,
    )
    append_ledger_entry(ledger_path, receipt)

    if is_gave_up:
        # Seal ledger with signed Merkle checkpoint on give-up
        uncheckpointed_hashes = [r["hash"] for r in uncheckpointed] + [receipt["hash"]]
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

        sys.stderr.write(
            f"\n[RECEIPTD STOP GATE GAVE UP] Max retries ({max_retries}) reached with stop_hook_active=True.\n"
            f"  ├─ Session ID: {session_id}\n"
            f"  ├─ Verification Command: {resolved_cmd} (exit code: {exit_code})\n"
            f"  ├─ Test Output SHA256: {test_output_hash}\n"
            f"  ├─ Consecutive Retries: {current_retries}\n"
            f"  └─ Signed Gave Up Receipt: {receipt['hash'][:24]}...\n"
            f"Exiting 0 to prevent infinite agent retry loop.\n\n"
        )
        return 0

    sys.stderr.write(
        f"\n[RECEIPTD STOP GATE HARD BLOCK] Cannot declare completion while tests are failing.\n"
        f"  ├─ Session ID: {session_id}\n"
        f"  ├─ Verification Command: {resolved_cmd} (exit code: {exit_code})\n"
        f"  ├─ Latency: {latency_ms}ms\n"
        f"  ├─ Signed Rejection Receipt: {receipt['hash'][:24]}...\n"
        f"  └─ Diagnostics:\n"
        f"     {diag}\n\n"
        f"Action Required: Fix the failing tests before completing this task.\n"
    )
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Receiptd Stop Hook Gate")
    parser.add_argument("--test-cmd", default=None, help="Command to run to verify tests (e.g. pytest, npm test)")
    parser.add_argument("--ledger", default=".receiptd/receipts.jsonl", help="Path to audit ledger")
    parser.add_argument("--timeout", type=int, default=120, help="Test timeout in seconds")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retry blocks before giving up when stop_hook_active is true")
    parser.add_argument("--session-id", default=None, help="Session identifier")
    parser.add_argument("--stop-hook-active", action="store_true", default=None, help="Stop hook active flag")
    parser.add_argument("--state-file", default=None, help="Path to stop gate state file")

    args, _ = parser.parse_known_args()
    return run_stop_gate(
        test_cmd=args.test_cmd,
        ledger_path=args.ledger,
        timeout_sec=args.timeout,
        max_retries=args.max_retries,
        session_id=args.session_id,
        stop_hook_active=args.stop_hook_active,
        state_file_path=args.state_file,
    )


if __name__ == "__main__":
    sys.exit(main())
