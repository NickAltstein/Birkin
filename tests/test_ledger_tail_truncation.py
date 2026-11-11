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
    record_ledger_anchor(2, r2["hash"], ledger_path=ledger, key_dir=key_dir, sk=sk)

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
    sk = SigningKey.generate()
    record_ledger_anchor(1, "a" * 64, ledger_path=ledger, key_dir=key_dir, sk=sk)
    pub_pem = sk.public_pem_bytes.decode("ascii")

    # Without --allow-unanchored: MUST fail with exit 2 naming sequence #1
    res = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
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


def test_rewrite_allow_as_unsigned_deny_update_anchor_fails(tmp_path: Path, monkeypatch):
    """Rewrite last allow as unsigned signing_error deny and update anchor hash -> exit 2."""
    from receiptd.ledger import build_unsigned_signing_error_receipt

    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    # Create legitimate allow receipt
    allow_receipt = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test",
        tool="Bash",
        args_sha256="0" * 64,
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, allow_receipt)
    record_ledger_anchor(1, allow_receipt["hash"], ledger_path=ledger, key_dir=key_dir, sk=sk)

    pub_pem = sk.public_pem_bytes.decode("ascii")

    # Legitimate ledger passes
    res_ok = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
    assert res_ok.exit_code == 0

    # Attacker rewrites receipt as an unsigned deny with signing_error: true
    forged_deny = build_unsigned_signing_error_receipt(
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test",
        tool="Bash",
        args_sha256="0" * 64,
        decision="deny",
        rule_ids=["ATTACK"],
        blast_radius=100,
        reason="rewritten deny",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    ledger.write_text(json.dumps(forged_deny) + "\n", encoding="utf-8")

    # Attacker also updates anchor hash to match forged_deny["hash"]
    state_file = key_dir / "ledger_state.json"
    anchor = json.loads(state_file.read_text(encoding="utf-8"))
    norm = str(ledger.resolve())
    if "ledgers" in anchor and norm in anchor["ledgers"]:
        anchor["ledgers"][norm]["last_hash"] = forged_deny["hash"]
    if norm in anchor and isinstance(anchor[norm], dict):
        anchor[norm]["last_hash"] = forged_deny["hash"]
    anchor["last_hash"] = forged_deny["hash"]
    state_file.write_text(json.dumps(anchor), encoding="utf-8")

    # Signature on anchor is now invalid because it was signed over original hash!
    res_fail = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
    assert res_fail.exit_code == 2
    assert "Invalid Ed25519 signature on ledger anchor" in res_fail.output or "TAMPER DETECTED" in res_fail.output


def test_delete_anchor_and_last_receipt_fails(tmp_path: Path, monkeypatch):
    """Delete the anchor + the last receipt -> exit 2."""
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test",
        tool="Read",
        args_sha256="0" * 64,
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, r1)

    r2 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=2,
        ts="2026-11-10T12:00:01Z",
        session_id="test",
        tool="Bash",
        args_sha256="0" * 64,
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=r1["hash"],
    )
    append_ledger_entry(ledger, r2)
    record_ledger_anchor(2, r2["hash"], ledger_path=ledger, key_dir=key_dir, sk=sk)

    pub_pem = sk.public_pem_bytes.decode("ascii")

    # Delete receipt #2 from ledger (leaving receipt #1)
    ledger.write_text(json.dumps(r1) + "\n", encoding="utf-8")

    # Delete anchor state file completely
    state_file = key_dir / "ledger_state.json"
    state_file.unlink()

    # Verify must fail with exit 2 because ledger has 1 receipt but anchor is missing
    res = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
    assert res.exit_code == 2
    assert "Missing signed ledger anchor" in res.output or "TAMPER DETECTED" in res.output


def test_corrupt_anchor_fails(tmp_path: Path, monkeypatch):
    """Corrupt the anchor -> exit 2."""
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test",
        tool="Read",
        args_sha256="0" * 64,
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, r1)
    record_ledger_anchor(1, r1["hash"], ledger_path=ledger, key_dir=key_dir, sk=sk)

    pub_pem = sk.public_pem_bytes.decode("ascii")

    # Corrupt anchor file with invalid JSON
    state_file = key_dir / "ledger_state.json"
    state_file.write_text("{corrupt: json not valid", encoding="utf-8")

    res = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", pub_pem])
    assert res.exit_code == 2
    assert "Unreadable or corrupted ledger anchor" in res.output or "TAMPER DETECTED" in res.output


def test_allow_unanchored_passes_copied_ledger(tmp_path: Path, monkeypatch):
    """--allow-unanchored still passes a copied ledger."""
    import shutil

    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test",
        tool="Read",
        args_sha256="0" * 64,
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="ok",
        policy_sha256="0" * 64,
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, r1)
    record_ledger_anchor(1, r1["hash"], ledger_path=ledger, key_dir=key_dir, sk=sk)

    pub_pem = sk.public_pem_bytes.decode("ascii")

    # Copy ledger to a different location (different path, no local anchor matching it)
    copied_ledger = tmp_path / "copied_receipts.jsonl"
    shutil.copy(ledger, copied_ledger)

    # Without --allow-unanchored: fails due to path mismatch or missing anchor
    res_fail = runner.invoke(app, ["verify", "--ledger", str(copied_ledger), "--pubkey", pub_pem])
    assert res_fail.exit_code == 2

    # With --allow-unanchored: passes
    res_pass = runner.invoke(app, ["verify", "--ledger", str(copied_ledger), "--pubkey", pub_pem, "--allow-unanchored"])
    assert res_pass.exit_code == 0
    assert "✓ VERDICT: AUTHENTIC" in res_pass.output


def test_gate_denies_if_anchor_write_fails(tmp_path: Path):
    """If writing the anchor fails, the gate denies (exit 2)."""
    import subprocess
    import sys

    key_dir = tmp_path / "keys"
    ledger = tmp_path / "receipts.jsonl"
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "RECEIPTD_KEY_DIR": str(key_dir),
    }

    key_dir.mkdir(parents=True, exist_ok=True)
    sk = SigningKey.generate()
    (key_dir / "receiptd_ed25519.pem").write_bytes(sk.pem_bytes)
    (key_dir / "receiptd_ed25519.pub.pem").write_bytes(sk.public_pem_bytes)

    # Create ledger_state.json as a directory so writing to it as a file fails
    (key_dir / "ledger_state.json").mkdir()

    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "test.txt"},
        "session_id": "s-anchor-fail",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "receiptd.hooks.claude_code_gate", "--ledger", str(ledger)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    # Must deny with exit 2
    assert proc.returncode == 2


def test_multi_project_shared_keydir_independent_anchors(tmp_path: Path):
    """Gate runs in project A then project B with a shared RECEIPTD_KEY_DIR,

    then verify A and verify B both exit 0; truncating A still exits 2.
    """
    import subprocess
    import sys

    shared_key_dir = tmp_path / "shared_keys"
    proj_a = tmp_path / "project_a"
    proj_a.mkdir()
    ledger_a = proj_a / "receipts.jsonl"

    proj_b = tmp_path / "project_b"
    proj_b.mkdir()
    ledger_b = proj_b / "receipts.jsonl"

    env = {
        **os.environ,
        "RECEIPTD_KEY_DIR": str(shared_key_dir),
        "HOME": str(tmp_path),
    }

    payload_a = {
        "tool_name": "Read",
        "tool_input": {"file_path": "a.txt"},
        "session_id": "session-a",
    }
    payload_b = {
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "session_id": "session-b",
    }

    # 1. Run gate in Project A
    proc_a = subprocess.run(
        [sys.executable, "-m", "receiptd.hooks.claude_code_gate", "--ledger", str(ledger_a)],
        input=json.dumps(payload_a),
        capture_output=True,
        text=True,
        cwd=proj_a,
        env=env,
    )
    assert proc_a.returncode == 0

    # 2. Run gate in Project B (overwriting shared state if not keyed by ledger path!)
    proc_b = subprocess.run(
        [sys.executable, "-m", "receiptd.hooks.claude_code_gate", "--ledger", str(ledger_b)],
        input=json.dumps(payload_b),
        capture_output=True,
        text=True,
        cwd=proj_b,
        env=env,
    )
    assert proc_b.returncode == 0

    # 3. Verify Project A and Project B both exit 0
    ver_a = subprocess.run(
        [sys.executable, "-m", "receiptd", "verify", "--ledger", str(ledger_a)],
        capture_output=True,
        text=True,
        cwd=proj_a,
        env=env,
    )
    assert ver_a.returncode == 0, f"Verify A failed: {ver_a.stdout}\n{ver_a.stderr}"
    assert "✓ VERDICT: AUTHENTIC" in ver_a.stdout

    ver_b = subprocess.run(
        [sys.executable, "-m", "receiptd", "verify", "--ledger", str(ledger_b)],
        capture_output=True,
        text=True,
        cwd=proj_b,
        env=env,
    )
    assert ver_b.returncode == 0, f"Verify B failed: {ver_b.stdout}\n{ver_b.stderr}"
    assert "✓ VERDICT: AUTHENTIC" in ver_b.stdout

    # 4. Truncating A still exits 2
    ledger_a.write_text("", encoding="utf-8")
    ver_a_trunc = subprocess.run(
        [sys.executable, "-m", "receiptd", "verify", "--ledger", str(ledger_a)],
        capture_output=True,
        text=True,
        cwd=proj_a,
        env=env,
    )
    assert ver_a_trunc.returncode == 2
    assert "TAMPER DETECTED" in ver_a_trunc.stdout

    # Verify B still exits 0
    ver_b_still_ok = subprocess.run(
        [sys.executable, "-m", "receiptd", "verify", "--ledger", str(ledger_b)],
        capture_output=True,
        text=True,
        cwd=proj_b,
        env=env,
    )
    assert ver_b_still_ok.returncode == 0


def _build_chain(sk, n):
    prev = GENESIS_HASH
    out = []
    for i in range(1, n + 1):
        r = build_signed_receipt(
            sk=sk, v=1, seq=i, ts=f"2026-11-10T12:00:0{i}Z", session_id="t", tool="Read",
            args_sha256="0" * 64, decision="allow", rule_ids=[], blast_radius=0,
            reason="ok", policy_sha256="0" * 64, prev_hash=prev,
        )
        prev = r["hash"]
        out.append(r)
    return out


def test_anchor_command_adopts_pre_upgrade_ledger(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    from receiptd.crypto import get_signing_key

    sk = get_signing_key(key_dir=key_dir)
    ledger = tmp_path / "receipts.jsonl"
    for r in _build_chain(sk, 3):
        append_ledger_entry(ledger, r)

    # Pre-upgrade: no anchor -> verify fails
    assert runner.invoke(app, ["verify", "--ledger", str(ledger)]).exit_code == 2

    res = runner.invoke(app, ["anchor", "--ledger", str(ledger)])
    assert res.exit_code == 0, res.output
    assert "sequence #3" in res.output

    assert runner.invoke(app, ["verify", "--ledger", str(ledger)]).exit_code == 0

    # Existing anchor -> refuse, unless --force-reanchor
    assert runner.invoke(app, ["anchor", "--ledger", str(ledger)]).exit_code == 2
    assert runner.invoke(app, ["anchor", "--ledger", str(ledger), "--force-reanchor"]).exit_code == 0


def test_anchor_command_refuses_tampered_ledger(tmp_path: Path, monkeypatch):
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(key_dir))
    from receiptd.crypto import get_signing_key

    sk = get_signing_key(key_dir=key_dir)
    ledger = tmp_path / "receipts.jsonl"
    chain = _build_chain(sk, 3)
    for r in chain:
        append_ledger_entry(ledger, r)

    lines = ledger.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["blast_radius"] = 99
    lines[1] = json.dumps(tampered)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = runner.invoke(app, ["anchor", "--ledger", str(ledger)])
    assert res.exit_code == 2
    assert not (key_dir / "ledger_state.json").exists()
