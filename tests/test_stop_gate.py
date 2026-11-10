import json
import os
import tempfile
import pytest
from typer.testing import CliRunner
from receiptd.cli import app
from receiptd.hooks.claude_code_stop_gate import run_stop_gate

runner = CliRunner()


def test_stop_gate_pass_records_receipt():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = os.path.join(tmpdir, "receipts.jsonl")
        # Run passing command
        code = run_stop_gate(test_cmd="true", ledger_path=ledger)
        assert code == 0

        assert os.path.exists(ledger)
        with open(ledger, "r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == 1
            receipt = json.loads(lines[0])
            assert receipt["event_type"] == "STOP_GATE"
            assert receipt["decision"] == "ALLOWED_VERIFIED"
            assert receipt["test_exit_code"] == 0
            assert "receipt_sha256" in receipt


def test_stop_gate_fail_halts_with_exit_2():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = os.path.join(tmpdir, "receipts.jsonl")
        # Run failing command
        code = run_stop_gate(test_cmd="false", ledger_path=ledger)
        assert code == 2

        assert os.path.exists(ledger)
        with open(ledger, "r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == 1
            receipt = json.loads(lines[0])
            assert receipt["event_type"] == "STOP_GATE"
            assert receipt["decision"] == "BLOCKED_FAIL_CLOSED"
            assert receipt["test_exit_code"] != 0


def test_cli_stop_gate_command():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = os.path.join(tmpdir, "receipts.jsonl")
        result = runner.invoke(app, ["stop-gate", "--test-cmd", "true", "--ledger", ledger])
        assert result.exit_code == 0
        assert "RECEIPTD STOP GATE PASSED" in result.stdout

        result_fail = runner.invoke(app, ["stop-gate", "--test-cmd", "false", "--ledger", ledger])
        assert result_fail.exit_code == 2
