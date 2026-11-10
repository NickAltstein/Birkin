"""Tests for birkin backward-compatibility shim."""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_LEDGER = REPO_ROOT / ".receiptd" / "receipts.jsonl"


def test_birkin_crypto_resolves_to_receiptd_crypto():
    import birkin.crypto
    import receiptd.crypto

    assert birkin.crypto is receiptd.crypto


def test_birkin_hooks_claude_code_gate_invalid_json(tmp_path: Path):
    repo_ledger_before = REPO_LEDGER.read_bytes() if REPO_LEDGER.exists() else None
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "RECEIPTD_KEY_DIR": str(tmp_path / "keys"),
    }
    res = subprocess.run(
        [sys.executable, "-m", "birkin.hooks.claude_code_gate"],
        input="invalid json",
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    assert res.returncode == 2
    repo_ledger_after = REPO_LEDGER.read_bytes() if REPO_LEDGER.exists() else None
    assert repo_ledger_after == repo_ledger_before


def test_birkin_hooks_claude_code_gate_rm_rf_denied(tmp_path: Path):
    repo_ledger_before = REPO_LEDGER.read_bytes() if REPO_LEDGER.exists() else None
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "RECEIPTD_KEY_DIR": str(tmp_path / "keys"),
    }
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    res = subprocess.run(
        [sys.executable, "-m", "birkin.hooks.claude_code_gate"],
        input=payload,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    assert res.returncode == 2
    repo_ledger_after = REPO_LEDGER.read_bytes() if REPO_LEDGER.exists() else None
    assert repo_ledger_after == repo_ledger_before
