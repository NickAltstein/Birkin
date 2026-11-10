"""Ed25519 key handling for signed receipts.

The Trifecta Card signs card.json with Ed25519. Since this repository (as
found on this machine) has no pre-existing key-handling code, this module
*is* the Receiptd key API and is kept minimal and stable:

    get_key_pair()  -> (private_pem, public_pem)
    sign_bytes(priv, data) -> bytes
    verify_bytes(pub, data, signature) -> bool

Keys are generated on first use and stored under ~/.receiptd/ (0600) so
verification is reproducible across runs. All of it is pure local crypto
via the `cryptography` package - zero network.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def _get_key_paths():
    key_dir = Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
    return key_dir, key_dir / "receiptd_ed25519.pem", key_dir / "receiptd_ed25519.pub.pem"


def _generate_key_pair():
    private = Ed25519PrivateKey.generate()
    return private


def _load_or_create_key():
    """The process-wide Ed25519 private key (created on first use)."""
    key_dir, private_key_path, public_key_path = _get_key_paths()
    key_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(key_dir, 0o700)
    except OSError:
        pass
    if private_key_path.exists():
        blob = private_key_path.read_bytes()
        return serialization.load_pem_private_key(blob, password=None)
    private = _generate_key_pair()
    private_key_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(private_key_path, 0o600)
    public_key_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private


# ---------------------------------------------------------------------------
# key API (stable surface used by card signing and future receipts)
# ---------------------------------------------------------------------------


def get_key_pair():
    """(private_pem, public_pem) for the Receiptd signing key."""
    private = _load_or_create_key()
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def sign_bytes(private_pem: bytes, data: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.sign(data)


def verify_bytes(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = serialization.load_pem_public_key(public_pem)
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(signature, data)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# canonical JSON (RFC 8785 subset sufficient for our string/number/int data)
# ---------------------------------------------------------------------------


def canonical_json(data) -> str:
    """RFC 8785 / JCS canonical serialization.

    Implements the JSON Canonicalization Scheme subset we need: sorted keys,
    no insignificant whitespace, minimal float form, and escaping per the
    RFC's string serialization rules. Our payloads contain only strings,
    booleans, nulls, ints and lists of those - so this is exact.
    """
    return _canonical(data)


def _canonical(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonical_float(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _canonical_string(kv[0]))
        return "{" + ",".join(f"{_canonical_string(k)}:{_canonical(v)}" for k, v in items) + "}"
    raise TypeError(f"cannot canonicalize {type(value)!r}")


_ESCAPE_MAP = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _canonical_string(text: str) -> str:
    out = ['"']
    for char in text:
        escape = _ESCAPE_MAP.get(char)
        if escape is not None:
            out.append(escape)
        elif char < " " or ord(char) >= 0x7F:
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _canonical_float(value: float) -> str:
    """RFC 8785 number serialization for ECMAScript-compatible doubles."""
    if value != value:  # NaN
        raise ValueError("NaN is not canonicalizable")
    if value in (float("inf"), float("-inf")):
        raise ValueError("Infinity is not canonicalizable")
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    return repr(value).upper().replace("E-0", "E-").replace("E+0", "E+")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# card.json payload assembly, signing, verification
# ---------------------------------------------------------------------------


def build_card_payload(report, generated_at: str) -> dict:
    """Unsigned card payload (verdict, rules version, evidence, sessions)."""
    return {
        "verdict": {
            "level": report.level,
            "ordered": report.ordered,
            "counts": {c: report.counts[c] for c in ("PRIVATE", "UNTRUSTED", "EGRESS")},
        },
        "rules_version": report.rules_version,
        "redacted": report.redacted,
        "generated_at": generated_at,
        "sessions": [
            {
                "source_format": s.source_format,
                "file_name": s.file_name,
                "session_id": s.session_id,
                "started": s.started,
                "ended": s.ended,
                "tool_calls": s.tool_calls,
            }
            for s in report.sessions
        ],
        "evidence": [
            {
                "category": h.category,
                "index": h.index,
                "tool": h.tool,
                "target": h.target,
                "timestamp": h.timestamp,
                "rule": h.rule,
            }
            for h in report.hits
        ],
    }


def sign_card_payload(payload: dict) -> dict:
    """Return the signed card document: payload + digest + signature.

    The signature covers exactly the canonical serialization of the payload;
    `digest` is the SHA-256 of the same bytes, so any single-byte change to
    the payload invalidates both.
    """
    canonical = canonical_json(payload).encode("utf-8")
    private_pem, _public_pem = get_key_pair()
    signature = sign_bytes(private_pem, canonical)
    import base64

    return {
        **payload,
        "digest": digest_bytes(canonical),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": _public_pem.decode("ascii"),
    }


def write_signed_card(report, path) -> dict:
    """Write the signed card JSON; returns the document that was written."""
    from datetime import datetime, timezone

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = build_card_payload(report, generated_at)
    document = sign_card_payload(payload)
    Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return document


def verify_card_file(path, expected_pubkey_id: str | None = None):
    """(ok, message). VALID iff the payload's canonical bytes verify under
    the embedded public key AND match the recorded digest."""
    import base64

    try:
        document = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return False, "TAMPERED (unreadable or invalid JSON)"

    if not isinstance(document, dict):
        return False, "TAMPERED (not a JSON object)"

    signature_field = document.get("signature")
    public_key_field = document.get("public_key")
    digest_field = document.get("digest")
    if not signature_field or not public_key_field or not digest_field:
        return False, "TAMPERED (missing signature fields)"

    from receiptd.crypto import get_pubkey_id

    try:
        actual_id = get_pubkey_id(public_key_field)
    except Exception:
        return False, "TAMPERED (invalid embedded public key)"

    if expected_pubkey_id is not None and actual_id != expected_pubkey_id.strip():
        return False, f"UNTRUSTED SIGNER (key {actual_id} != expected {expected_pubkey_id.strip()})"

    payload = {
        key: value
        for key, value in document.items()
        if key not in ("signature", "public_key", "digest")
    }
    canonical = canonical_json(payload).encode("utf-8")

    if digest_bytes(canonical) != digest_field:
        return False, "TAMPERED (digest mismatch)"

    try:
        signature = base64.b64decode(signature_field)
    except Exception:
        return False, "TAMPERED (bad signature encoding)"

    if not verify_bytes(public_key_field.encode("ascii"), canonical, signature):
        return False, "TAMPERED (signature does not verify)"

    level = payload.get("verdict", {}).get("level", "?")
    return True, f"VALID ({level})"
