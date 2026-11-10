"""
birkin.crypto
=============

Cryptographic primitives for Birkin.

Everything Birkin proves about an agent run is rooted in this module:

* Ed25519 signing keys (one for the Birkin control plane, one per agent identity).
* Deterministic canonical JSON encoding so that signatures are reproducible
  across processes, languages, and time.
* SHA-256 hashing for the audit ledger's event chain and Merkle checkpoints.

Design notes
------------
* We deliberately use Ed25519 (not RSA, not ECDSA-with-SHA) because it is
  deterministic, small, fast to verify, and hard to misuse. A receipt signed
  today will verify in 2035 with no parameter drift.
* ``canonical_json`` is the single source of truth for what bytes get signed.
  Adding a new field to a model does NOT retroactively invalidate old
  signatures because signing uses an explicit ``fields`` list at the call site.
* All hashes are SHA-256 hex strings, lowercase, no prefix. Merkle leaves are
  event hashes; the checkpoint root is the standard binary-tree hash where
  the empty tree has root = sha256(b""). We do NOT duplicate odd nodes
  (simpler, deterministic, auditable).
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# --------------------------------------------------------------------------- #
# Canonical JSON
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> bytes:
    """Encode ``obj`` as deterministic JSON bytes.

    Rules:
    * keys sorted lexicographically (UTF-8 byte order)
    * no extraneous whitespace
    * ``ensure_ascii=False`` so non-ASCII payloads hash the same everywhere
    * separators are ``,`` and ``:`` (no spaces)
    """
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_subset(obj: dict, fields: Iterable[str]) -> bytes:
    """Encode only the given ``fields`` of ``obj`` as canonical JSON.

    This is the function that gets fed into the signer. By making the field
    set explicit at every call site, we ensure that adding a new field to a
    model does NOT retroactively break old signatures.
    """
    subset = {f: obj.get(f) for f in fields if f in obj}
    return canonical_json(subset)


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    """Compute the Merkle root for an ordered list of leaf hashes.

    Each leaf is a hex sha256 string. Internal nodes are
    ``sha256(left_bytes + right_bytes)`` where ``left_bytes`` and
    ``right_bytes`` are the raw bytes of the child hash (we hash the raw
    32-byte digest, not the hex string, to stay standard).

    Empty list -> sha256(b"").
    Odd levels -> last node is carried up unchanged (no duplication).
    """
    if not leaf_hashes:
        return sha256_hex(b"")

    level: list[bytes] = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        i = 0
        while i < len(level):
            left = level[i]
            if i + 1 < len(level):
                right = level[i + 1]
                next_level.append(hashlib.sha256(left + right).digest())
                i += 2
            else:
                # Odd node: carry up unchanged.
                next_level.append(left)
                i += 1
        level = next_level
    return level[0].hex()


# --------------------------------------------------------------------------- #
# Ed25519 keys & signing
# --------------------------------------------------------------------------- #
class SigningKey:
    """An Ed25519 signing key with serialization helpers."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._priv = private_key
        self._pub = private_key.public_key()

    # --- construction -----------------------------------------------------
    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "SigningKey":
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def from_private_b64(cls, b64: str) -> "SigningKey":
        return cls.from_private_bytes(base64.b64decode(b64))

    # --- public accessors -------------------------------------------------
    @property
    def private_bytes(self) -> bytes:
        return self._priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def private_b64(self) -> str:
        return base64.b64encode(self.private_bytes).decode("ascii")

    @property
    def public_b64(self) -> str:
        raw = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._pub

    # --- signing ----------------------------------------------------------
    def sign(self, message: bytes) -> str:
        """Return a base64 Ed25519 signature over ``message``."""
        sig = self._priv.sign(message)
        return base64.b64encode(sig).decode("ascii")


def verify_signature(public_b64: str, signature_b64: str, message: bytes) -> bool:
    """Verify a base64 Ed25519 signature against a base64 public key."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
        pub.verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_b64_to_bytes(public_b64: str) -> bytes:
    return base64.b64decode(public_b64)


__all__ = [
    "SigningKey",
    "verify_signature",
    "canonical_json",
    "canonical_json_subset",
    "sha256_hex",
    "merkle_root",
    "public_b64_to_bytes",
]
