"""
receiptd.ledger
===============

On-disk append-only ledger management with Ed25519 signing and Merkle checkpoints.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .crypto import (
    SigningKey,
    canonical_json,
    canonical_json_subset,
    get_pubkey_id,
    get_signing_key,
    merkle_root,
    sha256_hex,
)

GENESIS_HASH = "0" * 64

SIGNABLE_RECEIPT_FIELDS = (
    "args_sha256",
    "blast_radius",
    "decision",
    "policy_sha256",
    "prev_hash",
    "reason",
    "rule_ids",
    "session_id",
    "tool",
    "ts",
    "v",
)

CHECKPOINT_SIGNABLE_FIELDS = (
    "from_seq",
    "merkle_root",
    "prev_checkpoint_hash",
    "to_seq",
)


def read_ledger_state(ledger_path: str | Path) -> tuple[str, str, int, int, list[dict]]:
    """Scan the ledger and return:

    (last_receipt_hash, last_checkpoint_hash, total_receipts, last_checkpointed_to_seq, uncheckpointed_receipts)
    """
    path = Path(ledger_path)
    if not path.exists():
        return GENESIS_HASH, GENESIS_HASH, 0, 0, []

    last_receipt_hash = GENESIS_HASH
    last_checkpoint_hash = GENESIS_HASH
    receipt_count = 0
    last_checkpointed_to_seq = 0
    all_receipts: list[dict] = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue

                if entry.get("type") == "checkpoint":
                    cp_hash = entry.get("hash") or entry.get("checkpoint_hash") or ""
                    if cp_hash:
                        last_checkpoint_hash = cp_hash
                    to_seq = entry.get("to_seq", 0)
                    if to_seq > last_checkpointed_to_seq:
                        last_checkpointed_to_seq = to_seq
                else:
                    receipt_count += 1
                    r_hash = entry.get("hash") or entry.get("receipt_sha256") or ""
                    if r_hash:
                        last_receipt_hash = r_hash
                    seq = entry.get("seq", receipt_count)
                    all_receipts.append({"seq": seq, "hash": r_hash, "entry": entry})
    except OSError:
        pass

    uncheckpointed = [r for r in all_receipts if r["seq"] > last_checkpointed_to_seq]
    return last_receipt_hash, last_checkpoint_hash, receipt_count, last_checkpointed_to_seq, uncheckpointed


def build_signed_receipt(
    *,
    sk: SigningKey,
    v: int = 1,
    seq: int,
    ts: str,
    session_id: str,
    tool: str,
    args_sha256: str,
    decision: str,
    rule_ids: list[str],
    blast_radius: int,
    reason: str,
    policy_sha256: str,
    prev_hash: str,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct and Ed25519-sign an authorization receipt over RFC-8785 canonical bytes."""
    receipt: dict[str, Any] = {
        "v": v,
        "ts": ts,
        "session_id": session_id,
        "tool": tool,
        "args_sha256": args_sha256,
        "decision": decision,
        "rule_ids": rule_ids,
        "blast_radius": blast_radius,
        "reason": reason,
        "policy_sha256": policy_sha256,
        "prev_hash": prev_hash,
    }

    # Ed25519 signature over canonical JSON of the 11 specification fields
    canonical_bytes = canonical_json_subset(receipt, SIGNABLE_RECEIPT_FIELDS)
    sig = sk.sign(canonical_bytes)
    pubkey_id = get_pubkey_id(sk)

    receipt["sig"] = sig
    receipt["pubkey_id"] = pubkey_id
    receipt["seq"] = seq

    # Backward-compatible metadata
    receipt["tool_name"] = tool
    receipt["blast_radius_score"] = blast_radius
    receipt["triggered_rules"] = rule_ids
    receipt["prev_receipt_hash"] = prev_hash

    if extra_fields:
        for k, val in extra_fields.items():
            if k not in receipt:
                receipt[k] = val

    # Compute receipt hash as SHA-256 of canonical receipt including sig
    h = sha256_hex(canonical_json(receipt))
    receipt["hash"] = h
    receipt["receipt_sha256"] = h

    return receipt


def build_unsigned_signing_error_receipt(
    *,
    v: int = 1,
    seq: int,
    ts: str,
    session_id: str,
    tool: str,
    args_sha256: str,
    decision: str = "deny",
    rule_ids: list[str],
    blast_radius: int,
    reason: str = "receiptd: signing unavailable",
    policy_sha256: str,
    prev_hash: str,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct an unsigned deny receipt when Ed25519 signing fails."""
    receipt: dict[str, Any] = {
        "v": v,
        "ts": ts,
        "session_id": session_id,
        "tool": tool,
        "args_sha256": args_sha256,
        "decision": decision,
        "rule_ids": rule_ids,
        "blast_radius": blast_radius,
        "reason": reason,
        "policy_sha256": policy_sha256,
        "prev_hash": prev_hash,
        "signing_error": True,
        "seq": seq,
        "tool_name": tool,
        "blast_radius_score": blast_radius,
        "triggered_rules": rule_ids,
        "prev_receipt_hash": prev_hash,
    }
    if extra_fields:
        for k, val in extra_fields.items():
            if k not in receipt:
                receipt[k] = val

    h = sha256_hex(canonical_json(receipt))
    receipt["hash"] = h
    receipt["receipt_sha256"] = h
    return receipt


def build_signed_checkpoint(
    *,
    sk: SigningKey,
    from_seq: int,
    to_seq: int,
    leaf_hashes: list[str],
    prev_checkpoint_hash: str,
) -> dict[str, Any]:
    """Construct and Ed25519-sign a Merkle checkpoint record."""
    root = merkle_root(leaf_hashes)
    cp_core = {
        "from_seq": from_seq,
        "to_seq": to_seq,
        "merkle_root": root,
        "prev_checkpoint_hash": prev_checkpoint_hash,
    }
    canonical_bytes = canonical_json_subset(cp_core, CHECKPOINT_SIGNABLE_FIELDS)
    sig = sk.sign(canonical_bytes)
    pubkey_id = get_pubkey_id(sk)

    cp_record = {
        "type": "checkpoint",
        "from_seq": from_seq,
        "to_seq": to_seq,
        "merkle_root": root,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "sig": sig,
        "pubkey_id": pubkey_id,
    }
    h = sha256_hex(canonical_json(cp_record))
    cp_record["hash"] = h
    cp_record["checkpoint_hash"] = h
    return cp_record


def append_ledger_entry(ledger_path: str | Path, entry: dict[str, Any]) -> None:
    path = Path(ledger_path)
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(canonical_json(entry).decode("utf-8") + "\n")


def record_ledger_anchor(
    seq: int,
    r_hash: str,
    ledger_path: str | Path | None = None,
    key_dir: Path | None = None,
    sk: SigningKey | None = None,
) -> None:
    """Record the highest sequence number, hash, and Ed25519 signature in ledger_state.json.

    Maintains per-ledger signed state in data["ledgers"][norm_path] and top-level.
    Uses an atomic write via a temporary file and os.replace with 0600 permissions,
    protected by an exclusive file lock to prevent concurrent worker updates from colliding.
    """
    import fcntl
    import time

    kd = key_dir or Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
    kd.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(kd, 0o700)
    except OSError:
        pass

    if sk is None:
        sk = get_signing_key(key_dir=kd)

    norm_path = str(Path(ledger_path).resolve()) if ledger_path else ""
    signable = {
        "last_hash": str(r_hash),
        "last_seq": int(seq),
        "ledger_path": norm_path,
    }
    canonical_bytes = canonical_json(signable)
    sig = sk.sign(canonical_bytes)

    payload = {
        "ledger_path": norm_path,
        "last_seq": int(seq),
        "last_hash": str(r_hash),
        "sig": sig,
    }

    state_file = kd / "ledger_state.json"
    lock_file_path = kd / ".ledger_state.lock"

    with open(lock_file_path, "a+", encoding="utf-8") as lock_file:
        try:
            os.chmod(lock_file_path, 0o600)
        except OSError:
            pass
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            data: dict[str, Any] = {}
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                except Exception:
                    data = {}

            ledgers = data.get("ledgers")
            if not isinstance(ledgers, dict):
                ledgers = {}
                if data.get("ledger_path"):
                    ledgers[data["ledger_path"]] = {
                        "ledger_path": data["ledger_path"],
                        "last_seq": data.get("last_seq", 0),
                        "last_hash": data.get("last_hash", ""),
                        "sig": data.get("sig", ""),
                    }
                data["ledgers"] = ledgers

            if norm_path:
                data["ledgers"][norm_path] = dict(payload)
                data[norm_path] = dict(payload)

            # Also keep top-level in sync with most recent anchor for backward compatibility
            data["ledger_path"] = norm_path
            data["last_seq"] = int(seq)
            data["last_hash"] = str(r_hash)
            data["sig"] = sig

            temp_file = kd / f".ledger_state.tmp.{os.getpid()}.{time.time_ns()}"
            try:
                temp_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                try:
                    os.chmod(temp_file, 0o600)
                except OSError:
                    pass
                os.replace(temp_file, state_file)
            finally:
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                    except OSError:
                        pass
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def read_ledger_anchor(
    ledger_path: str | Path | None = None,
    key_dir: Path | None = None,
) -> dict[str, Any] | None:
    """Read the signed ledger anchor state dictionary from local state under RECEIPTD_KEY_DIR."""
    kd = key_dir or Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
    for name in ("ledger_state.json", "state.json"):
        state_file = kd / name
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                if ledger_path:
                    norm = str(Path(ledger_path).resolve())
                    ledgers = data.get("ledgers")
                    if isinstance(ledgers, dict) and norm in ledgers:
                        return ledgers[norm]
                    if norm in data and isinstance(data[norm], dict):
                        return data[norm]
                    if data.get("ledger_path") == norm:
                        return data
                    return None
                return data
            except Exception:
                pass
    return None

