"""Tests for birkin backward-compatibility shim."""

import json
import subprocess
import sys


def test_birkin_crypto_resolves_to_receiptd_crypto():
    import birkin.crypto
    import receiptd.crypto

    assert birkin.crypto is receiptd.crypto


def test_birkin_hooks_claude_code_gate_invalid_json():
    res = subprocess.run(
        [sys.executable, "-m", "birkin.hooks.claude_code_gate"],
        input="invalid json",
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2


def test_birkin_hooks_claude_code_gate_rm_rf_denied():
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    res = subprocess.run(
        [sys.executable, "-m", "birkin.hooks.claude_code_gate"],
        input=payload,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
