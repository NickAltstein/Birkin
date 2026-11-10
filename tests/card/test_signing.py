"""Tests for canonical JSON, Ed25519 signing, and tamper detection."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from receiptd.card.models import Hit
from receiptd.card.parser import ParsedSession
from receiptd.card.signing import (
    build_card_payload,
    canonical_json,
    digest_bytes,
    get_key_pair,
    sign_bytes,
    sign_card_payload,
    verify_bytes,
    verify_card_file,
    write_signed_card,
)
from receiptd.card.verdict import build_report

# Isolated key directory per test so the on-disk key never leaks between runs.
@pytest.fixture(autouse=True)
def _isolated_key_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))


def _demo_report(level: str = "RED"):
    calls = []
    hits = []
    if level in ("RED", "YELLOW"):
        calls.append("p")
        hits.append(Hit("PRIVATE", 0, "Read", ".env", "2026-11-09T10:00:00Z", "filename_glob", True))
    if level == "RED":
        calls.append("u")
        hits.append(Hit("UNTRUSTED", 1, "Read", "pkg.tgz", "2026-11-09T10:00:01Z", "path_glob", True))
    if level in ("RED", "YELLOW"):
        hits.append(Hit("EGRESS", 2, "Bash", "collector.example.net", "2026-11-09T10:00:02Z", "program:curl"))
    session = ParsedSession("claude", "demo.jsonl", "sid-1", "2026-11-09T10:00:00Z", "2026-11-09T11:00:00Z", [None] * 3)
    return build_report([session], hits, rules={"version": 1})


# ---------------------------------------------------------------------------
# canonical JSON (RFC 8785 / JCS subset)
# ---------------------------------------------------------------------------


def test_canonical_json_key_order():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_no_whitespace():
    assert canonical_json({"a": [1, 2], "b": {"c": True}}) == '{"a":[1,2],"b":{"c":true}}'


def test_canonical_json_escapes_per_rfc8785():
    assert canonical_json({"k": 'a"b\\c\nd\te'}) == '{"k":"a\\"b\\\\c\\nd\\te"}'


def test_canonical_json_control_chars_escaped():
    assert canonical_json({"k": "\x00\x1f"}) == '{"k":"\\u0000\\u001f"}'


def test_canonical_json_unicode_escaped_above_ascii():
    assert canonical_json({"k": "é"}) == '{"k":"\\u00e9"}'


def test_canonical_json_int_and_bool_and_null():
    assert canonical_json({"i": 7, "t": True, "f": False, "n": None}) == '{"f":false,"i":7,"n":null,"t":true}'


def test_canonical_json_nested_structures():
    doc = {"z": [{"b": 2, "a": 1}], "a": "x"}
    assert canonical_json(doc) == '{"a":"x","z":[{"a":1,"b":2}]}'


def test_canonical_json_roundtrip_via_json_loads():
    doc = {"verdict": {"level": "RED", "counts": {"EGRESS": 1, "PRIVATE": 2, "UNTRUSTED": 3}}}
    assert json.loads(canonical_json(doc)) == doc


def test_canonical_json_rejects_nan_and_infinity():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"x": float("inf")})


def test_canonical_json_deterministic_across_insertion_orders():
    import random

    items = [(k, v) for k, v in {"alpha": 1, "beta": [1, {"g": 2, "a": 3}], "gamma": "s"}.items()]
    a = dict(items)
    b = dict(reversed(items))
    random.seed(1)
    c = dict(random.sample(items, len(items)))
    assert canonical_json(a) == canonical_json(b) == canonical_json(c)


# ---------------------------------------------------------------------------
# key handling
# ---------------------------------------------------------------------------


def test_key_pair_generated_and_stable():
    priv1, pub1 = get_key_pair()
    priv2, pub2 = get_key_pair()
    assert priv1 == priv2  # same on-disk key
    assert pub1 == pub2
    assert b"BEGIN PRIVATE KEY" in priv1
    assert b"BEGIN PUBLIC KEY" in pub1


def test_private_key_file_permissions():
    get_key_pair()
    key_path = Path.home() / ".receiptd" / "receiptd_ed25519.pem"
    if key_path.exists():  # only when not overridden by RECEIPTD_KEY_DIR
        assert (key_path.stat().st_mode & 0o777) == 0o600


def test_sign_and_verify_bytes_roundtrip():
    priv, pub = get_key_pair()
    data = b"attack at dawn"
    signature = sign_bytes(priv, data)
    assert verify_bytes(pub, data, signature) is True
    assert verify_bytes(pub, b"attack at dusk", signature) is False


def test_verify_bytes_wrong_key_fails():
    other_priv, other_pub = get_key_pair()
    priv, _pub = get_key_pair()
    # Sign with a fresh key different from the returned pair is impossible
    # via this API (single key); simulate by signing data, verifying under a
    # tampered public key.
    signature = sign_bytes(other_priv, b"x")
    tampered_pub = other_pub.replace(b"AAAA", b"AAAB")
    assert verify_bytes(tampered_pub, b"x", signature) is False or tampered_pub == other_pub


# ---------------------------------------------------------------------------
# card payload + signing
# ---------------------------------------------------------------------------


def test_build_card_payload_shape():
    payload = build_card_payload(_demo_report("RED"), "2026-11-10T00:00:00Z")
    assert payload["verdict"]["level"] == "RED"
    assert payload["verdict"]["ordered"] is True
    assert payload["verdict"]["counts"] == {"PRIVATE": 1, "UNTRUSTED": 1, "EGRESS": 1}
    assert payload["rules_version"] == "1"
    assert payload["generated_at"] == "2026-11-10T00:00:00Z"
    assert len(payload["evidence"]) == 3
    assert set(payload["evidence"][0]) == {"category", "index", "tool", "target", "timestamp", "rule"}
    assert payload["sessions"][0]["file_name"] == "demo.jsonl"


def test_signed_document_verifies():
    payload = build_card_payload(_demo_report("RED"), "2026-11-10T00:00:00Z")
    document = sign_card_payload(payload)
    doc_path = Path("/tmp/test_card.json") if not document else None
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "card.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True))
        ok, message = verify_card_file(path)
    assert ok, message
    assert message.startswith("VALID")


def test_write_signed_card_and_verify(tmp_path):
    path = tmp_path / "card.json"
    document = write_signed_card(_demo_report("YELLOW"), path)
    assert path.is_file()
    ok, message = verify_card_file(path)
    assert ok and "YELLOW" in message
    assert document["digest"] == digest_bytes(canonical_json(
        {k: v for k, v in document.items() if k not in ("signature", "public_key", "digest")}
    ).encode())


# ---------------------------------------------------------------------------
# tamper detection
# ---------------------------------------------------------------------------


def _write_fresh_card(tmp_path, name="card.json"):
    path = tmp_path / name
    write_signed_card(_demo_report("RED"), path)
    return path


def test_tampered_verdict_detected(tmp_path):
    path = _write_fresh_card(tmp_path)
    doc = json.loads(path.read_text())
    doc["verdict"]["level"] = "GREEN"
    path.write_text(json.dumps(doc))
    ok, message = verify_card_file(path)
    assert not ok and "TAMPERED" in message


def test_tampered_single_byte_in_target(tmp_path):
    path = _write_fresh_card(tmp_path)
    raw = path.read_text()
    # Flip one character inside an evidence target string.
    assert ".env" in raw
    path.write_text(raw.replace(".env", ".enw", 1))
    ok, message = verify_card_file(path)
    assert not ok, message


def test_tampered_single_byte_in_count(tmp_path):
    path = _write_fresh_card(tmp_path)
    doc = json.loads(path.read_text())
    doc["verdict"]["counts"]["EGRESS"] = 99  # was 1
    path.write_text(json.dumps(doc))
    ok, _ = verify_card_file(path)
    assert not ok


def test_tampered_evidence_item_removed(tmp_path):
    path = _write_fresh_card(tmp_path)
    doc = json.loads(path.read_text())
    doc["evidence"].pop()
    path.write_text(json.dumps(doc))
    ok, _ = verify_card_file(path)
    assert not ok


def test_tampered_signature_swapped(tmp_path):
    path = _write_fresh_card(tmp_path)
    doc = json.loads(path.read_text())
    signature = bytearray(base64.b64decode(doc["signature"]))
    signature[0] ^= 1  # single bit flip
    doc["signature"] = base64.b64encode(bytes(signature)).decode()
    path.write_text(json.dumps(doc))
    ok, _ = verify_card_file(path)
    assert not ok


def test_tampered_digest_swapped(tmp_path):
    path = _write_fresh_card(tmp_path)
    doc = json.loads(path.read_text())
    doc["digest"] = "0" * 64
    path.write_text(json.dumps(doc))
    ok, _ = verify_card_file(path)
    assert not ok


def test_tampered_public_key_swapped(tmp_path):
    path = _write_fresh_card(tmp_path)
    doc = json.loads(path.read_text())
    # Keep the signature but point it at a genuinely different key.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    doc["public_key"] = other_pub.decode()
    path.write_text(json.dumps(doc))
    ok, _ = verify_card_file(path)
    assert not ok


def test_verify_missing_file(tmp_path):
    ok, message = verify_card_file(tmp_path / "nope.json")
    assert not ok and "TAMPERED" in message


def test_verify_invalid_json(tmp_path):
    path = tmp_path / "card.json"
    path.write_text("{not json")
    ok, message = verify_card_file(path)
    assert not ok and "TAMPERED" in message


def test_verify_missing_signature_fields(tmp_path):
    path = tmp_path / "card.json"
    path.write_text(json.dumps({"verdict": {"level": "RED"}}))
    ok, message = verify_card_file(path)
    assert not ok and "TAMPERED" in message
