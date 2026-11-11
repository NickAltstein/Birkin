"""
tests/test_hook_signing_and_checkpoints.py
==========================================

Unit tests verifying:
1. Signed receipts verify offline with Ed25519.
2. 1-byte mutated sig fails verify with exit != 0 naming sequence number.
3. Forged signature with different Ed25519 key rejected.
4. Deleted/reordered/edited receipt breaks chain.
5. Checkpoint root mismatch detected.
6. Truncated tail after last checkpoint reported (unproven missing receipts statement).
7. Signing failure leads to exit 2 deny and unsigned deny receipt marked signing_error.
8. Stop gate exit 0 after retry cap with gave_up receipt and Merkle checkpoint.
9. Symlink cycle denied.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from receiptd.cli import _verify_ledger_file, app
from receiptd.crypto import (
    SigningKey,
    canonical_json,
    canonical_json_subset,
    get_pubkey_id,
    merkle_root,
    sha256_hex,
    verify_ed25519,
)
from receiptd.hooks.claude_code_gate import evaluate_payload, main as gate_main
from receiptd.hooks.claude_code_stop_gate import run_stop_gate
from receiptd.ledger import (
    CHECKPOINT_SIGNABLE_FIELDS,
    GENESIS_HASH,
    SIGNABLE_RECEIPT_FIELDS,
    append_ledger_entry,
    build_signed_checkpoint,
    build_signed_receipt,
    build_unsigned_signing_error_receipt,
    read_ledger_state,
)

runner = CliRunner()


def _make_dummy_signed_receipt(sk: SigningKey, seq: int, prev_hash: str, tool: str = "Bash") -> dict:
    return build_signed_receipt(
        sk=sk,
        v=1,
        seq=seq,
        ts="2026-11-10T12:00:00Z",
        session_id="test-session",
        tool=tool,
        args_sha256=sha256_hex(b"{}"),
        decision="allow",
        rule_ids=[],
        blast_radius=10,
        reason="allowed",
        policy_sha256=sha256_hex(b"policy"),
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# 1. Verify signed receipts
# ---------------------------------------------------------------------------
def test_verify_signed_receipts(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    append_ledger_entry(ledger, r1)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])
    append_ledger_entry(ledger, r2)

    # Checkpoint covering 1..2
    cp = build_signed_checkpoint(
        sk=sk,
        from_seq=1,
        to_seq=2,
        leaf_hashes=[r1["hash"], r2["hash"]],
        prev_checkpoint_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, cp)

    ok = _verify_ledger_file(ledger, pubkey=sk.public_pem_bytes.decode("ascii"), allow_unanchored=True)
    assert ok is True


# ---------------------------------------------------------------------------
# 2. 1-byte mutated sig fails verify with exit != 0 naming sequence number
# ---------------------------------------------------------------------------
def test_one_byte_mutated_sig_fails_verify_naming_seq(tmp_path: Path, capsys):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    append_ledger_entry(ledger, r1)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])

    # Mutate 1 character of base64 signature in receipt #2
    raw_sig = r2["sig"]
    mutated_char = "B" if raw_sig[5] != "B" else "C"
    r2["sig"] = raw_sig[:5] + mutated_char + raw_sig[6:]
    # Recompute hash so the hash check doesn't trip first; test specifically targets signature failure
    r2_copy = {k: v for k, v in r2.items() if k not in ("hash", "receipt_sha256")}
    r2["hash"] = sha256_hex(canonical_json(r2_copy))
    r2["receipt_sha256"] = r2["hash"]
    append_ledger_entry(ledger, r2)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii"), "--allow-unanchored"])
    assert result.exit_code != 0
    # Must explicitly name sequence #2
    assert "sequence #2" in result.output or "sequence 2" in result.output
    assert "Invalid Ed25519 signature" in result.output


# ---------------------------------------------------------------------------
# 3. Forged signature with different Ed25519 key rejected
# ---------------------------------------------------------------------------
def test_forged_signature_with_different_key_rejected(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    genuine_key = SigningKey.generate()
    attacker_key = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(genuine_key, 1, GENESIS_HASH)
    append_ledger_entry(ledger, r1)

    # Receipt #2 signed with attacker key instead of genuine key
    r2 = _make_dummy_signed_receipt(attacker_key, 2, r1["hash"])
    append_ledger_entry(ledger, r2)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", genuine_key.public_pem_bytes.decode("ascii")])
    assert result.exit_code != 0
    assert "Invalid Ed25519 signature at receipt sequence #2" in result.output


# ---------------------------------------------------------------------------
# 4. Deleted / Reordered / Edited receipt breaks chain
# ---------------------------------------------------------------------------
def test_deleted_receipt_breaks_chain(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])
    r3 = _make_dummy_signed_receipt(sk, 3, r2["hash"])

    # Write only r1 and r3 (r2 deleted)
    append_ledger_entry(ledger, r1)
    append_ledger_entry(ledger, r3)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii"), "--allow-unanchored"])
    assert result.exit_code != 0
    assert "Hash Chain Break" in result.output


def test_reordered_receipt_breaks_chain(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])
    r3 = _make_dummy_signed_receipt(sk, 3, r2["hash"])

    # Reorder r1, r3, r2
    append_ledger_entry(ledger, r1)
    append_ledger_entry(ledger, r3)
    append_ledger_entry(ledger, r2)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii"), "--allow-unanchored"])
    assert result.exit_code != 0
    assert "Hash Chain Break" in result.output


def test_edited_receipt_breaks_chain(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])
    append_ledger_entry(ledger, r1)

    # Tamper payload without updating hash
    r2["tool"] = "MaliciousTool"
    append_ledger_entry(ledger, r2)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii"), "--allow-unanchored"])
    assert result.exit_code != 0
    assert "Payload Mutation Detected" in result.output


# ---------------------------------------------------------------------------
# 5. Checkpoint root mismatch detected
# ---------------------------------------------------------------------------
def test_checkpoint_root_mismatch_detected(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])
    append_ledger_entry(ledger, r1)
    append_ledger_entry(ledger, r2)

    # Checkpoint with intentionally forged root
    fake_root = "f" * 64
    cp_record = {
        "type": "checkpoint",
        "from_seq": 1,
        "to_seq": 2,
        "merkle_root": fake_root,
        "prev_checkpoint_hash": GENESIS_HASH,
    }
    canonical_bytes = canonical_json_subset(cp_record, CHECKPOINT_SIGNABLE_FIELDS)
    cp_record["sig"] = sk.sign(canonical_bytes)
    cp_record["pubkey_id"] = get_pubkey_id(sk)
    cp_record["hash"] = sha256_hex(canonical_json(cp_record))
    append_ledger_entry(ledger, cp_record)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii"), "--allow-unanchored"])
    assert result.exit_code != 0
    assert "Checkpoint Merkle root mismatch" in result.output


# ---------------------------------------------------------------------------
# 6. Truncated tail after last checkpoint reported
# ---------------------------------------------------------------------------
def test_truncated_tail_reported_with_unproven_disclaimer(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    sk = SigningKey.generate()

    r1 = _make_dummy_signed_receipt(sk, 1, GENESIS_HASH)
    r2 = _make_dummy_signed_receipt(sk, 2, r1["hash"])
    append_ledger_entry(ledger, r1)
    append_ledger_entry(ledger, r2)

    # Checkpoint sealing 1..2
    cp = build_signed_checkpoint(
        sk=sk,
        from_seq=1,
        to_seq=2,
        leaf_hashes=[r1["hash"], r2["hash"]],
        prev_checkpoint_hash=GENESIS_HASH,
    )
    append_ledger_entry(ledger, cp)

    # Receipt #3 added after last checkpoint (truncated tail)
    r3 = _make_dummy_signed_receipt(sk, 3, r2["hash"])
    append_ledger_entry(ledger, r3)

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--pubkey", sk.public_pem_bytes.decode("ascii"), "--allow-unanchored"])
    assert result.exit_code == 0
    assert "Uncheckpointed tail: receipts 3 to 3" in result.output
    assert "Missing receipts after the last checkpoint cannot be proven." in result.output


# ---------------------------------------------------------------------------
# 7. Signing failure leads to exit 2 deny and unsigned deny receipt
# ---------------------------------------------------------------------------
def test_signing_failure_leads_to_exit_2_deny(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"

    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo safe"}})

    with patch("receiptd.hooks.claude_code_gate.get_signing_key", side_effect=RuntimeError("signing unavailable")):
        with patch.object(sys, "argv", ["claude_code_gate", "--ledger", str(ledger)]):
            with patch("sys.stdin.read", return_value=payload):
                exit_code = gate_main()
                assert exit_code == 2

    assert ledger.exists()
    lines = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    receipt = lines[0]
    assert receipt["decision"] == "deny"
    assert receipt["signing_error"] is True
    assert "sig" not in receipt or receipt.get("sig") is None
    assert receipt["reason"] == "receiptd: signing unavailable"


# ---------------------------------------------------------------------------
# 8. Stop gate exit 0 after retry cap with gave_up receipt and checkpoint
# ---------------------------------------------------------------------------
def test_stop_gate_exit_0_after_retry_cap_with_gave_up_receipt(tmp_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    state_file = tmp_path / "stop_gate_state.json"

    # Tries 1 and 2 fail closed (exit 2)
    for expected_retries in (1, 2):
        code = run_stop_gate(
            test_cmd="false",
            ledger_path=str(ledger),
            max_retries=3,
            session_id="session-retry-test",
            stop_hook_active=True,
            state_file_path=str(state_file),
        )
        assert code == 2

    # Try 3 reaches cap (3 >= 3) -> gives up, exits 0
    code3 = run_stop_gate(
        test_cmd="false",
        ledger_path=str(ledger),
        max_retries=3,
        session_id="session-retry-test",
        stop_hook_active=True,
        state_file_path=str(state_file),
    )
    assert code3 == 0

    lines = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    receipts = [line for line in lines if line.get("type") != "checkpoint"]
    checkpoints = [line for line in lines if line.get("type") == "checkpoint"]

    assert len(receipts) == 3
    assert len(checkpoints) == 1

    gave_up_receipt = receipts[2]
    assert gave_up_receipt["decision"] == "gave_up"
    assert gave_up_receipt["retries"] == 3
    assert "sig" in gave_up_receipt

    # Checkpoint must seal receipts 1..3
    cp = checkpoints[0]
    assert cp["from_seq"] == 1
    assert cp["to_seq"] == 3
    assert cp["merkle_root"] == merkle_root([r["hash"] for r in receipts])


# ---------------------------------------------------------------------------
# 9. Symlink cycle denied
# ---------------------------------------------------------------------------
def test_symlink_cycle_denied(tmp_path: Path):
    from receiptd import Engine, NullAgentAdapter, SigningKey, PolicySpec

    link_a = tmp_path / "link_a"
    link_b = tmp_path / "link_b"
    link_a.symlink_to(link_b)
    link_b.symlink_to(link_a)

    policy_dict = {
        "name": "symlink_policy",
        "version": "1.0.0",
        "rules": [
            {
                "id": "fs.sandbox.allow",
                "match": {"tool": "fs.write", "path_prefix": [str(tmp_path)]},
                "decision": "allow",
                "risk_score": 10,
            },
            {
                "id": "fs.default.deny",
                "match": {"tool": "fs.write"},
                "decision": "deny",
                "risk_score": 90,
            },
        ],
    }
    policy = PolicySpec.from_dict(policy_dict)
    sk = SigningKey.generate()
    adapter = NullAgentAdapter()
    engine = Engine(birkin_signing_key=sk, policy=policy, adapter=adapter)
    identity = adapter.make_identity(agent_id="test-agent", policy_ref=policy.ref)
    engine.start_session(identity)

    req = adapter.build_action_request(tool="fs.write", args={"path": str(link_a / "cycle.txt")})
    receipt = engine.attempt_action(identity, req)
    assert receipt.decision == "deny"
