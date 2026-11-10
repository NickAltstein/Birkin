"""
Hook deadline tests.

Claude Code lets a tool call through when a PreToolUse hook times out, so the
gate has its own deadline and must deny (exit 2) when it cannot decide in time.
Hangs are produced with named pipes (a read with no writer blocks forever), so
the gate needs no test-only switches.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from receiptd.hooks.claude_code_gate import (
    DEFAULT_DEADLINE_MS,
    MAX_DEADLINE_MS,
    MIN_DEADLINE_MS,
    resolve_deadline_ms,
)

needs_fifo = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX")

MODULES = ["receiptd.hooks.claude_code_gate", "birkin.hooks.claude_code_gate"]
# A call the policy allows, so a deny can only come from the deadline.
SAFE_PAYLOAD = {"tool_name": "Read", "tool_input": {"file_path": "README.md"}}


def _env(tmp_path: Path, deadline_ms: int) -> dict:
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "RECEIPTD_KEY_DIR": str(tmp_path / "keys"),
        "RECEIPTD_HOOK_DEADLINE_MS": str(deadline_ms),
    }
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)
    return env


def _run_gate(module: str, ledger: Path, env: dict, cwd: Path) -> tuple[subprocess.CompletedProcess, float]:
    t0 = time.monotonic()
    res = subprocess.run(
        [sys.executable, "-m", module, "--ledger", str(ledger)],
        input=json.dumps(SAFE_PAYLOAD),
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=20,
    )
    return res, time.monotonic() - t0


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, DEFAULT_DEADLINE_MS),
        ("2500", 2500),
        ("not-a-number", DEFAULT_DEADLINE_MS),
        ("0", MIN_DEADLINE_MS),
        ("-5", MIN_DEADLINE_MS),
        ("999999", MAX_DEADLINE_MS),
    ],
)
def test_resolve_deadline_ms(raw, expected):
    environ = {} if raw is None else {"RECEIPTD_HOOK_DEADLINE_MS": raw}
    assert resolve_deadline_ms(environ) == expected


def test_max_deadline_below_claude_code_default_timeout():
    # Claude Code's default command-hook timeout is 60s; the gate must decide first.
    assert MAX_DEADLINE_MS < 60_000


def test_init_hook_timeout_above_default_deadline(tmp_path: Path):
    res = subprocess.run(
        [sys.executable, "-m", "receiptd", "init"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "HOME": str(tmp_path)},
        timeout=60,
    )
    assert res.returncode == 0, res.stderr
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    gate = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    assert gate["timeout"] * 1000 > DEFAULT_DEADLINE_MS


@needs_fifo
@pytest.mark.parametrize("module", MODULES)
def test_hang_in_key_load_denies_with_receipt(tmp_path: Path, module: str):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_pipe = key_dir / "receiptd_ed25519.pem"
    os.mkfifo(key_pipe)
    ledger = tmp_path / "receipts.jsonl"
    env = _env(tmp_path, deadline_ms=300)

    res, elapsed = _run_gate(module, ledger, env, tmp_path)

    assert res.returncode == 2
    assert "deadline" in res.stderr
    assert elapsed < 10

    lines = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    receipt = lines[0]
    assert receipt["decision"] == "deny"
    assert receipt["rule_ids"] == ["HOOK_DEADLINE_EXCEEDED"]
    assert receipt["tool"] == "Read"

    # verify also reads the key dir; drop the pipe so it doesn't hang too.
    key_pipe.unlink()
    verify = subprocess.run(
        [sys.executable, "-m", "receiptd", "verify", "--ledger", str(ledger)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
        timeout=60,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr


@needs_fifo
@pytest.mark.parametrize("module", MODULES)
def test_hang_in_ledger_read_still_denies(tmp_path: Path, module: str):
    # The watchdog's own receipt write hangs on the same pipe; the hard kill
    # after the grace period must still exit 2.
    ledger = tmp_path / "receipts.jsonl"
    os.mkfifo(ledger)
    env = _env(tmp_path, deadline_ms=300)

    res, elapsed = _run_gate(module, ledger, env, tmp_path)

    assert res.returncode == 2
    assert "deadline" in res.stderr
    assert elapsed < 10


@pytest.mark.parametrize("module", MODULES)
def test_fast_safe_call_still_allowed(tmp_path: Path, module: str):
    ledger = tmp_path / "receipts.jsonl"
    env = _env(tmp_path, deadline_ms=DEFAULT_DEADLINE_MS)

    res, _ = _run_gate(module, ledger, env, tmp_path)

    assert res.returncode == 0, res.stderr
    lines = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["decision"] == "allow"
