"""Tests enforcing that receiptd verify --ledger rejects unsigned receipts

unless they have signing_error: true and decision == 'deny'.
"""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from receiptd.cli import app
from receiptd.crypto import (
    SigningKey,
    canonical_json,
    canonical_json_subset,
    sha256_hex,
)
from receiptd.ledger import (
    GENESIS_HASH,
    SIGNABLE_RECEIPT_FIELDS,
    append_ledger_entry,
    build_signed_receipt,
    build_unsigned_signing_error_receipt,
)

runner = CliRunner()


def _recompute_hash(entry: dict) -> dict:
    """Strip hash/receipt_sha256 and recompute canonical hash."""
    entry_copy = {k: v for k, v in entry.items() if k not in ("hash", "receipt_sha256")}
    h = sha256_hex(canonical_json(entry_copy))
    entry["hash"] = h
    entry["receipt_sha256"] = h
    return entry


def test_strip_sig_from_signed_receipt_fails_verify(tmp_path: Path, monkeypatch):
    """1. Strip sig from a signed receipt and re-hash the chain -> exit 2 naming seq."""
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test-session",
        tool="Read",
        args_sha256=sha256_hex(canonical_json({"file_path": "README.md"})),
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="safe file read",
        policy_sha256=sha256_hex(b"test-policy"),
        prev_hash=GENESIS_HASH,
    )

    # Strip signature and recompute payload hash so hash integrity check passes
    del r1["sig"]
    _recompute_hash(r1)
    append_ledger_entry(ledger, r1)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii")])
    assert result.exit_code == 2
    assert "sequence #1" in result.output
    assert "TAMPER DETECTED" in result.output
    assert "missing Ed25519 signature" in result.output


def test_rewrite_deny_as_allow_no_sig_fails_verify(tmp_path: Path, monkeypatch):
    """2. Rewrite a deny as an allow with no sig and a re-hashed chain -> exit 2."""
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    # Create genuine deny receipt (signed)
    deny_receipt = build_signed_receipt(
        sk=sk,
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test-session",
        tool="Bash",
        args_sha256=sha256_hex(canonical_json({"command": "rm -rf /"})),
        decision="deny",
        rule_ids=["BASH_DESTRUCTIVE"],
        blast_radius=100,
        reason="blocked rm -rf",
        policy_sha256=sha256_hex(b"test-policy"),
        prev_hash=GENESIS_HASH,
    )

    # Attacker rewrites deny -> allow and removes signature, recalculating hash
    deny_receipt["decision"] = "allow"
    deny_receipt["blast_radius"] = 0
    deny_receipt["rule_ids"] = []
    deny_receipt["reason"] = "allowed by adversary"
    del deny_receipt["sig"]
    _recompute_hash(deny_receipt)
    append_ledger_entry(ledger, deny_receipt)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii")])
    assert result.exit_code == 2
    assert "sequence #1" in result.output
    assert "TAMPER DETECTED" in result.output


def test_unsigned_signing_error_deny_accepted(tmp_path: Path, monkeypatch):
    """3. Unsigned signing_error deny -> exit 0 with accepted count printed."""
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    # Construct unsigned signing_error deny receipt
    unsigned_deny = build_unsigned_signing_error_receipt(
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test-session",
        tool="Bash",
        args_sha256=sha256_hex(canonical_json({"command": "malicious"})),
        decision="deny",
        rule_ids=["HOOK_DEADLINE_EXCEEDED"],
        blast_radius=100,
        reason="receiptd: hook deadline exceeded (5000ms)",
        policy_sha256=sha256_hex(b"test-policy"),
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, unsigned_deny)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii")])
    assert result.exit_code == 0
    assert "✓ VERDICT: AUTHENTIC" in result.output
    assert "Unsigned deny receipts accepted: 1" in result.output


def test_unsigned_signing_error_allow_fails_verify(tmp_path: Path, monkeypatch):
    """4. Unsigned signing_error allow -> exit 2 naming seq."""
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    # Create unsigned receipt claiming signing_error: true but decision == "allow"
    forged_allow = build_unsigned_signing_error_receipt(
        v=1,
        seq=1,
        ts="2026-11-10T12:00:00Z",
        session_id="test-session",
        tool="Read",
        args_sha256=sha256_hex(canonical_json({"file_path": "secret.txt"})),
        decision="allow",
        rule_ids=[],
        blast_radius=0,
        reason="forged allow claiming signing error",
        policy_sha256=sha256_hex(b"test-policy"),
        prev_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, forged_allow)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii")])
    assert result.exit_code == 2
    assert "sequence #1" in result.output
    assert "TAMPER DETECTED" in result.output
