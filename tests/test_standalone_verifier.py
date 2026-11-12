"""The standalone ledger checker agrees with receiptd verify."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from receiptd.cli import app
from receiptd.crypto import SigningKey, sha256_hex
from receiptd.ledger import (
    GENESIS_HASH,
    append_ledger_entry,
    build_signed_checkpoint,
    build_signed_receipt,
    record_ledger_anchor,
)

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
STANDALONE = ROOT / "tools" / "verify_standalone.py"
POLICY_LABEL = "DEFAULT_RULES:POL-01,POL-02,POL-03"


def _write_ledger(tmp_path: Path) -> tuple[Path, str, Path]:
    """Two signed receipts and one checkpoint, under a throwaway key."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()
    constant = sha256_hex(POLICY_LABEL.encode("utf-8"))
    first = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-12T12:00:00+00:00",
        session_id="standalone-test",
        tool="Bash",
        args_sha256=sha256_hex(b"{}"),
        decision="allow",
        rule_ids=[],
        blast_radius=10,
        reason="allowed",
        policy_sha256=constant,
        prev_hash=GENESIS_HASH,
    )
    second = build_signed_receipt(
        sk=sk,
        v=1,
        seq=2,
        ts="2026-11-12T12:00:01+00:00",
        session_id="standalone-test",
        tool="Bash",
        args_sha256=sha256_hex(b'{"command":"true"}'),
        decision="allow",
        rule_ids=[],
        blast_radius=10,
        reason="also-ok",
        policy_sha256=sha256_hex(b"other-bytes"),
        prev_hash=first["hash"],
    )
    append_ledger_entry(ledger, first)
    append_ledger_entry(ledger, second)
    checkpoint = build_signed_checkpoint(
        sk=sk,
        from_seq=1,
        to_seq=2,
        leaf_hashes=[first["hash"], second["hash"]],
        prev_checkpoint_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, checkpoint)
    record_ledger_anchor(second["seq"], second["hash"], ledger_path=ledger, key_dir=key_dir, sk=sk)
    return ledger, sk.public_pem_bytes.decode("ascii"), key_dir


def _tamper_one_byte(source: Path, dest: Path) -> None:
    text = source.read_text(encoding="utf-8")
    old = '"reason":"allowed"'
    new = '"reason":"bllowed"'
    assert old in text
    assert len(old) == len(new)
    dest.write_text(text.replace(old, new, 1), encoding="utf-8")


def _run_standalone(ledger: Path, pubkey: str, key_dir: Path, allow_unanchored: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(STANDALONE),
        "--ledger",
        str(ledger),
        "--pubkey",
        pubkey,
        "--key-dir",
        str(key_dir),
    ]
    if allow_unanchored:
        cmd.append("--allow-unanchored")
    env = os.environ.copy()
    env["RECEIPTD_KEY_DIR"] = str(key_dir)
    env.pop("RECEIPTD_PUBLIC_KEY", None)
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(key_dir))


def _run_receiptd(ledger: Path, pubkey: str, key_dir: Path, allow_unanchored: bool = False) -> object:
    args = ["verify", "--ledger", str(ledger), "--pubkey", pubkey]
    if allow_unanchored:
        args.append("--allow-unanchored")
    env = {
        "RECEIPTD_KEY_DIR": str(key_dir),
    }
    # CliRunner does not pass os.environ through unless we patch it. The
    # verifier reads RECEIPTD_KEY_DIR from the process environment.
    previous = os.environ.get("RECEIPTD_KEY_DIR")
    os.environ["RECEIPTD_KEY_DIR"] = str(key_dir)
    try:
        return runner.invoke(app, args, env=env)
    finally:
        if previous is None:
            os.environ.pop("RECEIPTD_KEY_DIR", None)
        else:
            os.environ["RECEIPTD_KEY_DIR"] = previous


def test_source_does_not_import_receiptd():
    import ast

    tree = ast.parse(STANDALONE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
            assert all(not name.startswith("receiptd") for name in names)
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("receiptd")


def test_clean_and_one_byte_tamper_agree(tmp_path: Path):
    ledger, pubkey, key_dir = _write_ledger(tmp_path)
    clean_ref = _run_receiptd(ledger, pubkey, key_dir)
    clean_own = _run_standalone(ledger, pubkey, key_dir)
    assert clean_ref.exit_code == 0
    assert clean_own.returncode == 0
    assert clean_own.returncode == clean_ref.exit_code
    assert "VERDICT: AUTHENTIC" in clean_own.stdout
    assert "fixed label hash" in clean_own.stdout
    assert POLICY_LABEL in clean_own.stdout
    assert "policy text was not checked" in clean_own.stdout
    assert "claimed digest only" in clean_own.stdout
    lowered = clean_own.stdout.lower()
    assert "policy verified" not in lowered
    assert "policy version verified" not in lowered

    tampered = tmp_path / "tampered.jsonl"
    _tamper_one_byte(ledger, tampered)
    # The anchor still names the clean ledger path, so compare the portable
    # check (same bytes, no anchor for the copy) and the anchored path.
    tamper_ref = _run_receiptd(tampered, pubkey, key_dir, allow_unanchored=True)
    tamper_own = _run_standalone(tampered, pubkey, key_dir, allow_unanchored=True)
    assert tamper_ref.exit_code == 2
    assert tamper_own.returncode == 2
    assert "TAMPER DETECTED" in tamper_own.stdout
    assert "sequence #1" in tamper_own.stdout
    assert "policy verified" not in tamper_own.stdout.lower()

    # Same file the anchor was written for: one-byte edit still exits 2.
    original = ledger.read_text(encoding="utf-8")
    ledger.write_text(tampered.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        anchored_ref = _run_receiptd(ledger, pubkey, key_dir)
        anchored_own = _run_standalone(ledger, pubkey, key_dir)
    finally:
        ledger.write_text(original, encoding="utf-8")
    assert anchored_ref.exit_code == 2
    assert anchored_own.returncode == 2
    assert json.loads(original.splitlines()[0])["reason"] == "allowed"
