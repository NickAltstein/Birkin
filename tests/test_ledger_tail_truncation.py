"""Tests verifying detection of ledger tail truncation and empty ledger state."""
from __future__ import annotations

import json
import os
from pathlib import Path

from typer.testing import CliRunner

from receiptd.cli import app
from receiptd.crypto import SigningKey, canonical_json, sha256_hex
from receiptd.ledger import (
    GENESIS_HASH,
    append_ledger_entry,
    build_signed_receipt,
    record_ledger_anchor,
)

runner = CliRunner()


def test_delete_last_receipt_detected_and_allow_unanchored(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    # Create receipt #1
    r1 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test",
        tool="Read",
        args_sha256=sha256_hex(canonical_json({"file": "a.txt"})),
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, r1)

    # Create receipt #2
    r2 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=2,
        ts="2026-11-10T12:00:01Z",
        session_id="test",
        tool="Bash",
        args_sha256=sha256_hex(canonical_json({"cmd": "echo 1"})),
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=r1["hash"],
    )
    append_ledger_entry(ledger, r2)
    # Record anchor at seq 2
    record_ledger_anchor(2, r2["hash"], key_dir=key_dir)

    pub_pem = sk.public_pem_bytes.decode("ascii")

    # Both receipts present -> verify passes
    res = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
    assert res.exit_code == 0
    assert "✓ VERDICT: AUTHENTIC" in res.output

    # Delete the last receipt (receipt #2) so ledger only contains receipt #1
    ledger.write_text(json.dumps(r1) + "\n", encoding="utf-8")

    # Without --allow-unanchored: verify MUST fail with exit 2, naming sequence #2
    res_trunc = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
    assert res_trunc.exit_code == 2
    assert "sequence #2" in res_trunc.output
    assert "tail truncation detected" in res_trunc.output or "TAMPER DETECTED" in res_trunc.output

    # With --allow-unanchored: verify passes
    res_unanchored = runner.invoke(
        app,
        ["verify", "--ledger", str(ledger), "--pubkey", pub_pem, "--allow-unanchored"],
    )
    assert res_unanchored.exit_code == 0
    assert "✓ VERDICT: AUTHENTIC" in res_unanchored.output


def test_empty_ledger_with_anchor_fails(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    ledger = tmp_path / "receipts.jsonl"
    ledger.write_text("", encoding="utf-8")

    # Record anchor state indicating sequence #1 was previously written
    record_ledger_anchor(1, "a" * 64, key_dir=key_dir)

    # Without --allow-unanchored: MUST fail with exit 2 naming sequence #1
    res = runner.invoke(app, ["verify", "--ledger", str(ledger)])
    assert res.exit_code == 2
    assert "sequence #1" in res.output
    assert "TAMPER DETECTED" in res.output

    # With --allow-unanchored: passes (treats empty ledger as fresh)
    res_unanchored = runner.invoke(app, ["verify", "--ledger", str(ledger), "--allow-unanchored"])
    assert res_unanchored.exit_code == 0
    assert "Ledger is empty" in res_unanchored.output


def test_end_to_end_gate_anchor_and_tail_truncation(tmp_path: Path, monkeypatch):
    import subprocess
    import sys

    key_dir = tmp_path / "keys"
    ledger = tmp_path / "receipts.jsonl"
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "RECEIPTD_KEY_DIR": str(key_dir),
    }

    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "test.txt"},
        "session_id": "s-1",
    }
    # Run the real gate hook via subprocess
    proc = subprocess.run(
        [sys.executable, "-m", "receiptd.hooks.claude_code_gate", "--ledger", str(ledger)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    assert proc.returncode == 0

    # Ensure state file was recorded under RECEIPTD_KEY_DIR
    state_file = key_dir / "ledger_state.json"
    assert state_file.exists()
    state_data = json.loads(state_file.read_text(encoding="utf-8"))
    assert state_data["last_seq"] == 1

    # Verify ledger passes
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    res = runner.invoke(app, ["verify", "--ledger", str(ledger)])
    assert res.exit_code == 0

    # Truncate ledger to empty
    ledger.write_text("", encoding="utf-8")

    # Verify fails with exit 2
    res_fail = runner.invoke(app, ["verify", "--ledger", str(ledger)])
    assert res_fail.exit_code == 2
    assert "sequence #1" in res_fail.output

    # With --allow-unanchored passes
    res_unanchored = runner.invoke(app, ["verify", "--ledger", str(ledger), "--allow-unanchored"])
    assert res_unanchored.exit_code == 0
