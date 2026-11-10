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


def test_stop_gate_active_under_cap_exits_2():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = os.path.join(tmpdir, "receipts.jsonl")
        # 1st try with stop_hook_active=True, max_retries=3 -> exit 2
        code1 = run_stop_gate(
            test_cmd="false",
            ledger_path=ledger,
            max_retries=3,
            session_id="sess-test",
            stop_hook_active=True,
        )
        assert code1 == 2

        # 2nd try with stop_hook_active=True, max_retries=3 -> exit 2
        code2 = run_stop_gate(
            test_cmd="false",
            ledger_path=ledger,
            max_retries=3,
            session_id="sess-test",
            stop_hook_active=True,
        )
        assert code2 == 2

        with open(ledger, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 2
        assert lines[0]["decision"] == "BLOCKED_FAIL_CLOSED"
        assert lines[0]["retries"] == 1
        assert lines[1]["decision"] == "BLOCKED_FAIL_CLOSED"
        assert lines[1]["retries"] == 2


def test_stop_gate_active_at_cap_exits_0_gave_up_receipt():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = os.path.join(tmpdir, "receipts.jsonl")
        # 1st try: under cap
        assert run_stop_gate(
            test_cmd="false",
            ledger_path=ledger,
            max_retries=3,
            session_id="sess-test",
            stop_hook_active=True,
        ) == 2

        # 2nd try: under cap
        assert run_stop_gate(
            test_cmd="false",
            ledger_path=ledger,
            max_retries=3,
            session_id="sess-test",
            stop_hook_active=True,
        ) == 2

        # 3rd try: reaches cap (3 >= 3) -> gives up, exits 0
        code3 = run_stop_gate(
            test_cmd="false",
            ledger_path=ledger,
            max_retries=3,
            session_id="sess-test",
            stop_hook_active=True,
        )
        assert code3 == 0

        with open(ledger, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 3
        gave_up_receipt = lines[2]
        assert gave_up_receipt["event_type"] == "STOP_GATE"
        assert gave_up_receipt["decision"] == "gave_up"
        assert gave_up_receipt["retries"] == 3
        assert gave_up_receipt["session_id"] == "sess-test"
        assert "test_output_sha256" in gave_up_receipt
        assert len(gave_up_receipt["test_output_sha256"]) == 64
        assert "receipt_sha256" in gave_up_receipt


def test_stop_gate_stdin_json_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = os.path.join(tmpdir, "receipts.jsonl")
        stdin_payload = {"session_id": "sess-from-stdin", "stop_hook_active": True}
        code = run_stop_gate(
            test_cmd="false",
            ledger_path=ledger,
            max_retries=1,
            stdin_json=stdin_payload,
        )
        # With max_retries=1, 1st failure with stop_hook_active=True reaches cap immediately
        assert code == 0
        with open(ledger, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 1
        assert lines[0]["decision"] == "gave_up"
        assert lines[0]["session_id"] == "sess-from-stdin"
