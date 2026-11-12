#!/usr/bin/env python3
"""Offline checker for a Receiptd JSONL ledger.

Follows docs/receipt-format.md. Uses the standard library and the
`cryptography` package. Does not import the receiptd package.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS_HASH = "0" * 64

# UTF-8 label hashed into policy_sha256 when the PreToolUse hook does not
# hash a policy document. See docs/receipt-format.md, Limitations.
POLICY_LABEL = "DEFAULT_RULES:POL-01,POL-02,POL-03"
CONSTANT_POLICY_SHA256 = hashlib.sha256(POLICY_LABEL.encode("utf-8")).hexdigest()

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


def canonical_json(obj) -> bytes:
    """Canonical JSON (sorted keys), as specified for this ledger."""
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_subset(obj: dict, fields: tuple[str, ...]) -> bytes:
    subset = {name: obj[name] for name in fields if name in obj}
    return canonical_json(subset)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    """Binary SHA-256 tree over raw 32-byte digests. Odd nodes are not duplicated."""
    if not leaf_hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(leaf) for leaf in leaf_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        index = 0
        while index < len(level):
            left = level[index]
            if index + 1 < len(level):
                nxt.append(hashlib.sha256(left + level[index + 1]).digest())
                index += 2
            else:
                nxt.append(left)
                index += 1
        level = nxt
    return level[0].hex()


def verify_ed25519(public_key: str, signature: str, message: bytes) -> bool:
    """True when signature is Ed25519 over message under public_key.

    public_key is PEM when it contains BEGIN, otherwise standard Base64 of
    the raw 32-byte key. signature is standard Base64.
    """
    try:
        if "BEGIN" in public_key:
            loaded = serialization.load_pem_public_key(public_key.encode("utf-8"))
        else:
            loaded = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
        if not isinstance(loaded, Ed25519PublicKey):
            return False
        loaded.verify(base64.b64decode(signature), message)
        return True
    except Exception:
        return False


def policy_report(seq, claimed) -> str:
    """State the claimed policy_sha256. Never treats it as a checked policy."""
    if claimed == CONSTANT_POLICY_SHA256:
        return (
            f"policy_sha256 seq #{seq}: {claimed}\n"
            f'  fixed label hash of "{POLICY_LABEL}"; policy text was not checked'
        )
    if claimed:
        return (
            f"policy_sha256 seq #{seq}: {claimed}\n"
            "  claimed digest only; policy text was not checked"
        )
    return f"policy_sha256 seq #{seq}: absent; policy text was not checked"


def resolve_pubkey(explicit: str | None, key_dir: Path) -> str | None:
    if explicit:
        return explicit.strip()
    env_pub = os.environ.get("RECEIPTD_PUBLIC_KEY")
    if env_pub:
        return env_pub.strip()
    pub_path = key_dir / "receiptd_ed25519.pub.pem"
    if pub_path.is_file():
        return pub_path.read_text(encoding="utf-8").strip()
    return None


def default_ledger_path() -> Path | None:
    receiptd = Path(".receiptd/receipts.jsonl")
    if receiptd.exists():
        return receiptd
    birkin = Path(".birkin/receipts.jsonl")
    if birkin.exists():
        return birkin
    return None


def _anchor_for_empty(raw: dict, norm_ledger: str) -> dict | None:
    """Lookup used only for an empty file. Does not check the signature."""
    ledgers = raw.get("ledgers")
    if isinstance(ledgers, dict) and norm_ledger in ledgers:
        found = ledgers[norm_ledger]
        return found if isinstance(found, dict) else None
    if raw.get("ledger_path") == norm_ledger:
        return raw
    return None


def _anchor_for_ledger(raw: dict, norm_ledger: str) -> dict | None:
    ledgers = raw.get("ledgers")
    if isinstance(ledgers, dict) and norm_ledger in ledgers and isinstance(ledgers[norm_ledger], dict):
        return ledgers[norm_ledger]
    direct = raw.get(norm_ledger)
    if isinstance(direct, dict):
        return direct
    if raw.get("ledger_path") == norm_ledger:
        return raw
    if "last_seq" in raw and not raw.get("ledger_path"):
        return raw
    return None


def _state_file(key_dir: Path) -> Path:
    current = key_dir / "ledger_state.json"
    if current.exists():
        return current
    legacy = key_dir / "state.json"
    if legacy.exists():
        return legacy
    return current


def _fail(reason: str) -> int:
    print("=" * 65)
    print(f"✗ TAMPER DETECTED: {reason}")
    print("=" * 65)
    print("Audit failed. Ledger cryptographic integrity invalidated.")
    return 2


def verify_ledger(
    ledger_path: Path,
    pubkey: str | None = None,
    allow_unanchored: bool = False,
    key_dir: Path | None = None,
) -> int:
    """Return 0 when the ledger matches the spec, 2 when it does not."""
    if not ledger_path.exists():
        print(f"Error: Ledger file not found at {ledger_path}", file=sys.stderr)
        return 2

    print(f"Auditing cryptographic ledger: {ledger_path}...\n")
    entries: list[dict] = []
    with ledger_path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[-] Malformed JSON on line {line_num}: {exc}", file=sys.stderr)
                return 2
            if not isinstance(parsed, dict):
                print(f"[-] Malformed JSON on line {line_num}: line is not an object", file=sys.stderr)
                return 2
            entries.append(parsed)

    kd = key_dir or Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))

    if not entries:
        if not allow_unanchored:
            state_file = _state_file(kd)
            if state_file.exists():
                try:
                    raw = json.loads(state_file.read_text(encoding="utf-8"))
                    anchor = _anchor_for_empty(raw, str(ledger_path.resolve()))
                    if anchor is not None and int(anchor.get("last_seq", 0)) > 0:
                        return _fail(
                            "Ledger is empty, but recorded state expects "
                            f"sequence #{int(anchor.get('last_seq', 0))}"
                        )
                except Exception:
                    pass
        print("Ledger is empty. No execution frames recorded.")
        return 0

    pubkey_target = resolve_pubkey(pubkey, kd)
    expected_prev_hash = GENESIS_HASH
    expected_prev_cp_hash = GENESIS_HASH
    receipts_by_seq: dict[int, dict] = {}
    receipt_count = 0
    checkpoint_count = 0
    unsigned_deny_count = 0
    last_checkpointed_seq = 0
    policy_lines: list[str] = []
    tamper_reason = ""

    for entry in entries:
        if entry.get("type") == "checkpoint":
            checkpoint_count += 1
            from_seq = entry.get("from_seq", 0)
            to_seq = entry.get("to_seq", 0)
            stored_root = entry.get("merkle_root", "")
            stored_prev_cp = entry.get("prev_checkpoint_hash", "")
            stored_cp_hash = entry.get("hash") or entry.get("checkpoint_hash", "")
            cp_sig = entry.get("sig", "")

            if stored_prev_cp != expected_prev_cp_hash:
                tamper_reason = (
                    f"Checkpoint Hash Chain Break at checkpoint #{checkpoint_count}: "
                    f"Expected prev_checkpoint_hash {expected_prev_cp_hash[:16]}..., "
                    f"got {str(stored_prev_cp)[:16]}..."
                )
                break

            if cp_sig and pubkey_target:
                message = canonical_json_subset(entry, CHECKPOINT_SIGNABLE_FIELDS)
                if not verify_ed25519(pubkey_target, cp_sig, message):
                    tamper_reason = (
                        f"Invalid Ed25519 signature on checkpoint (range {from_seq}..{to_seq})"
                    )
                    break

            range_hashes: list[str] = []
            missing: list[int] = []
            for seq in range(from_seq, to_seq + 1):
                if seq in receipts_by_seq:
                    range_hashes.append(receipts_by_seq[seq]["hash"])
                else:
                    missing.append(seq)
            if missing:
                tamper_reason = (
                    f"Checkpoint range {from_seq}..{to_seq} references "
                    f"missing receipt sequence #{missing[0]}"
                )
                break
            try:
                recomputed_root = merkle_root(range_hashes)
            except ValueError:
                tamper_reason = (
                    f"Checkpoint Merkle root mismatch for range {from_seq}..{to_seq}: "
                    "a receipt hash is not hex"
                )
                break
            if recomputed_root != stored_root:
                tamper_reason = (
                    f"Checkpoint Merkle root mismatch for range {from_seq}..{to_seq}: "
                    f"Stored {str(stored_root)[:16]}... != Recomputed {recomputed_root[:16]}..."
                )
                break

            cp_copy = {key: value for key, value in entry.items() if key not in ("hash", "checkpoint_hash")}
            recomputed_cp_hash = sha256_hex(canonical_json(cp_copy))
            if stored_cp_hash and recomputed_cp_hash != stored_cp_hash:
                tamper_reason = f"Checkpoint record mutation detected (range {from_seq}..{to_seq})"
                break

            expected_prev_cp_hash = stored_cp_hash or recomputed_cp_hash
            last_checkpointed_seq = max(last_checkpointed_seq, to_seq)
            continue

        receipt_count += 1
        seq = entry.get("seq", receipt_count)
        policy_lines.append(policy_report(seq, entry.get("policy_sha256") or ""))
        stored_hash = entry.get("hash") or entry.get("receipt_sha256", "")
        stored_prev = entry.get("prev_hash") or entry.get("prev_receipt_hash", "")
        sig = entry.get("sig")
        is_signing_error = bool(entry.get("signing_error", False))

        if stored_prev != expected_prev_hash:
            tamper_reason = (
                f"Hash Chain Break at Frame sequence #{seq} (T+{receipt_count - 1}): "
                f"Expected prev_hash {expected_prev_hash[:16]}..., got {str(stored_prev)[:16]}..."
            )
            break

        rec_copy = {key: value for key, value in entry.items() if key not in ("hash", "receipt_sha256")}
        recomputed_hash = sha256_hex(canonical_json(rec_copy))
        if stored_hash and recomputed_hash != stored_hash:
            tamper_reason = (
                f"Payload Mutation Detected at Frame sequence #{seq} (T+{receipt_count - 1}): "
                f"Stored hash {str(stored_hash)[:16]}... != Recomputed {recomputed_hash[:16]}..."
            )
            break

        if sig:
            if not pubkey_target:
                tamper_reason = (
                    f"Receipt at sequence #{seq} is signed but no public key "
                    "available to verify signature"
                )
                break
            message = canonical_json_subset(entry, SIGNABLE_RECEIPT_FIELDS)
            if not verify_ed25519(pubkey_target, sig, message):
                tamper_reason = f"Invalid Ed25519 signature at receipt sequence #{seq}"
                break
        else:
            decision = entry.get("decision", "UNKNOWN")
            if is_signing_error and decision == "deny":
                unsigned_deny_count += 1
            elif is_signing_error and decision != "deny":
                tamper_reason = (
                    f"Unsigned receipt at sequence #{seq} has decision '{decision}' "
                    "(only deny allowed with signing_error: true)"
                )
                break
            else:
                tamper_reason = f"Unsigned receipt at sequence #{seq} (missing Ed25519 signature)"
                break

        link = stored_hash or recomputed_hash
        expected_prev_hash = link
        receipts_by_seq[seq] = {"hash": link}

    for line in policy_lines:
        print(line)

    if not tamper_reason and not allow_unanchored:
        tamper_reason = _check_anchor(
            ledger_path=ledger_path,
            key_dir=kd,
            pubkey_target=pubkey_target,
            receipt_count=receipt_count,
            receipts_by_seq=receipts_by_seq,
        )

    if tamper_reason:
        return _fail(tamper_reason)

    if last_checkpointed_seq < receipt_count and receipt_count > 0:
        tail_start = last_checkpointed_seq + 1
        print(
            f"Warning: Uncheckpointed tail: receipts {tail_start} to {receipt_count} "
            "have not been sealed in a Merkle checkpoint. "
            "Missing receipts after the last checkpoint cannot be proven.\n"
        )

    print("=" * 65)
    print(
        f"✓ VERDICT: AUTHENTIC — {receipt_count} receipts, {checkpoint_count} "
        "checkpoints verified, 0 chain breaks."
    )
    print(f"Unsigned deny receipts accepted: {unsigned_deny_count}")
    print("=" * 65)
    return 0


def _check_anchor(
    ledger_path: Path,
    key_dir: Path,
    pubkey_target: str | None,
    receipt_count: int,
    receipts_by_seq: dict[int, dict],
) -> str:
    state_file = _state_file(key_dir)
    if not state_file.exists():
        if receipt_count > 0:
            return (
                f"Missing signed ledger anchor: ledger has {receipt_count} receipts "
                f"but anchor state file {state_file} not found"
            )
        return ""

    try:
        anchor_data = json.loads(state_file.read_text(encoding="utf-8"))
    except Exception as exc:
        return f"Unreadable or corrupted ledger anchor in {state_file}: {exc}"
    if not isinstance(anchor_data, dict):
        return f"Unreadable or corrupted ledger anchor in {state_file}: not an object"

    norm_ledger = str(ledger_path.resolve())
    ledger_anchor = _anchor_for_ledger(anchor_data, norm_ledger)
    if ledger_anchor is None:
        if receipt_count > 0:
            return (
                f"Missing signed ledger anchor for {norm_ledger}: "
                "anchor state file exists but contains no anchor for this ledger path"
            )
        return ""

    sig = ledger_anchor.get("sig")
    if not sig:
        return f"Ledger anchor in {state_file} is unsigned (missing Ed25519 signature)"

    signable = {
        "last_hash": str(ledger_anchor.get("last_hash", "")),
        "last_seq": int(ledger_anchor.get("last_seq", 0)),
        "ledger_path": str(ledger_anchor.get("ledger_path", "")),
    }
    if not pubkey_target or not verify_ed25519(pubkey_target, sig, canonical_json(signable)):
        return f"Invalid Ed25519 signature on ledger anchor in {state_file}"

    anchor_path = ledger_anchor.get("ledger_path")
    if anchor_path and anchor_path != norm_ledger:
        return f"Ledger anchor path mismatch: recorded {anchor_path}, verifying {norm_ledger}"

    anchor_seq = int(ledger_anchor.get("last_seq", 0))
    anchor_hash = str(ledger_anchor.get("last_hash", ""))
    if receipt_count < anchor_seq:
        return (
            f"Ledger tail truncation detected: ledger ends at sequence #{receipt_count}, "
            f"but recorded state expects sequence #{anchor_seq}"
        )
    if receipt_count == 0 and anchor_seq > 0:
        return f"Ledger is empty, but recorded state expects sequence #{anchor_seq}"
    if receipt_count > 0 and anchor_seq in receipts_by_seq:
        actual_hash = receipts_by_seq[anchor_seq]["hash"]
        if actual_hash != anchor_hash:
            return (
                f"Ledger anchor hash mismatch at sequence #{anchor_seq}: "
                f"expected hash {anchor_hash[:16]}..., got {actual_hash[:16]}..."
            )
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a Receiptd JSONL ledger offline. Does not import receiptd.",
    )
    parser.add_argument("--ledger", default=None, help="Path to the JSONL receipt ledger.")
    parser.add_argument(
        "--pubkey",
        default=None,
        help="Ed25519 public key PEM or standard Base64 of the raw 32-byte key.",
    )
    parser.add_argument(
        "--allow-unanchored",
        action="store_true",
        help="Skip the local ledger_state.json anchor check.",
    )
    parser.add_argument(
        "--key-dir",
        default=None,
        help="Directory for the public key and ledger anchor. Default: RECEIPTD_KEY_DIR or ~/.receiptd.",
    )
    args = parser.parse_args(argv)

    if args.ledger:
        ledger_path = Path(args.ledger)
    else:
        found = default_ledger_path()
        if found is None:
            print("error: Provide --ledger <path>", file=sys.stderr)
            return 2
        ledger_path = found

    key_dir = Path(args.key_dir) if args.key_dir else None
    return verify_ledger(
        ledger_path,
        pubkey=args.pubkey,
        allow_unanchored=args.allow_unanchored,
        key_dir=key_dir,
    )


if __name__ == "__main__":
    sys.exit(main())
