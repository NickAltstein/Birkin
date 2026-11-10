"""
Smoke tests for the Birkin vertical slice.

These tests exercise:

* Crypto primitives (signing, hashing, Merkle root, canonical JSON).
* AgentIdentity self-signing.
* AuthorizationReceipt signing + verification.
* AuditEvent hash-chaining + sealing.
* PolicySpec loading + evaluation (all three decisions).
* Engine end-to-end → export → birkin verify == AUTHENTIC.
* Tamper detection (mutate event payload, expect TAMPERED).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from receiptd import (
    AgentIdentity,
    AuthorizationReceipt,
    AuditEvent,
    Engine,
    HermesAdapter,
    PolicySpec,
    RunPackage,
    SigningKey,
    load_default_policy,
    make_passport,
    merkle_root,
    sha256_hex,
    verify_package,
)
from receiptd.crypto import canonical_json, canonical_json_subset
from receiptd.verify import _coerce_package


# --------------------------------------------------------------------------- #
# Crypto
# --------------------------------------------------------------------------- #
def test_signing_and_verify_roundtrip():
    sk = SigningKey.generate()
    msg = b"hello birkin"
    sig = sk.sign(msg)
    from receiptd.crypto import verify_signature
    assert verify_signature(sk.public_b64, sig, msg)
    assert not verify_signature(sk.public_b64, sig, b"tampered")


def test_canonical_json_is_deterministic():
    a = {"b": 2, "a": 1, "c": [3, 2, 1]}
    b = {"a": 1, "b": 2, "c": [3, 2, 1]}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_subset_excludes_other_keys():
    obj = {"a": 1, "b": 2, "c": 3, "secret": "x"}
    encoded = canonical_json_subset(obj, ["a", "b", "c"])
    assert b"secret" not in encoded


def test_merkle_root_empty_and_single():
    assert merkle_root([]) == sha256_hex(b"")
    h = sha256_hex(b"leaf")
    assert merkle_root([h]) == h


def test_merkle_root_two_nodes():
    a = sha256_hex(b"a")
    b = sha256_hex(b"b")
    expected = sha256_hex(bytes.fromhex(a) + bytes.fromhex(b))
    assert merkle_root([a, b]) == expected


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
def test_agent_identity_sign_and_verify():
    sk = SigningKey.generate()
    ident = make_passport(
        agent_id="test-agent",
        runtime="hermes-0.1",
        policy="default@1.0.0",
        agent_signing_key=sk,
    )
    assert ident.verify()


def test_authorization_receipt_sign_and_verify():
    sk = SigningKey.generate()
    r = AuthorizationReceipt(
        agent_id="a1",
        agent_public_key=sk.public_b64,
        session_id="s1",
        intent_hash=sha256_hex(b"intent"),
        action="tool.invoke",
        tool="fs.write",
        args_hash=sha256_hex(b"{}"),
        decision="allow",
        policy="default@1.0.0",
        rule="fs.write.sandbox.allow",
        risk_score=20,
        reason="sandbox write",
        prior_event_hash="0" * 64,
    )
    r.sign(sk)
    assert r.verify(sk.public_b64)
    # tamper the decision -> signature no longer matches the signed material
    r2 = r.model_copy(update={"decision": "deny"})
    assert not r2.verify(sk.public_b64)
    # tamper the agent_public_key -> signature no longer matches
    r3 = r.model_copy(update={"agent_public_key": SigningKey.generate().public_b64})
    assert not r3.verify(sk.public_b64)
    # tamper the prior_event_hash -> signature no longer matches
    r4 = r.model_copy(update={"prior_event_hash": "a" * 64})
    assert not r4.verify(sk.public_b64)


def test_audit_event_seal_and_verify_hash():
    sk = SigningKey.generate()
    ev = AuditEvent(
        sequence=1,
        type="session.start",
        actor="a1",
        session_id="s1",
        prev_hash="0" * 64,
        payload={"hello": "world"},
    )
    ev.seal(sk)
    assert ev.verify_hash()
    assert ev.verify_signature(sk.public_b64)
    # Tamper the payload after sealing
    ev2 = ev.model_copy(update={"payload": {"hello": "TAMPERED"}})
    # event_hash on ev2 was copied from ev, so it no longer matches the recomputed hash
    assert ev2.event_hash == ev.event_hash
    assert not ev2.verify_hash()


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
def test_default_policy_loads():
    p = load_default_policy()
    assert p.name == "default"
    assert p.version == "1.0.0"
    assert len(p.rules) >= 5


def test_policy_evaluates_each_decision():
    p = load_default_policy()
    assert p.evaluate(tool="shell.exec", args={"cmd": "ls"}).decision == "deny"
    assert p.evaluate(
        tool="fs.write", args={"path": "/tmp/birkin/x", "data": "x"}
    ).decision == "allow"
    assert p.evaluate(
        tool="fs.write", args={"path": "/etc/passwd", "data": "x"}
    ).decision == "deny"
    assert p.evaluate(
        tool="fs.write", args={"path": "/home/u/x", "data": "x"}
    ).decision == "require_approval"
    # Unknown tool -> default deny
    assert p.evaluate(tool="unknown.tool", args={}).decision == "deny"


# --------------------------------------------------------------------------- #
# End-to-end
# --------------------------------------------------------------------------- #
def _make_engine() -> tuple[Engine, HermesAdapter]:
    sk = SigningKey.generate()
    p = load_default_policy()
    adapter = HermesAdapter()
    return Engine(birkin_signing_key=sk, policy=p, adapter=adapter), adapter


def test_engine_end_to_end_authentic(tmp_path):
    engine, adapter = _make_engine()
    identity = adapter.make_identity(agent_id="t1", policy_ref=engine.policy.ref)
    engine.start_session(identity)
    # The default policy allows fs.write only under the /tmp/birkin/ sandbox
    # prefix; ensure the sandbox dir exists so the write succeeds on a clean box.
    Path("/tmp/birkin").mkdir(parents=True, exist_ok=True)
    req = adapter.build_action_request(
        tool="fs.write", args={"path": "/tmp/birkin/x.txt", "data": "ok"}
    )
    r = engine.attempt_action(identity, req)
    assert r.decision == "allow"
    res, _ = engine.execute(identity, req, r)
    assert res.ok
    engine.checkpoint()
    engine.end_session(identity)
    pkg = engine.export(identity=identity)
    report = verify_package(pkg)
    assert report.verdict == "AUTHENTIC", [c.model_dump() for c in report.checks]


def test_engine_deny_and_require_approval(tmp_path):
    engine, adapter = _make_engine()
    identity = adapter.make_identity(agent_id="t2", policy_ref=engine.policy.ref)
    engine.start_session(identity)

    # shell.exec -> deny
    r1 = engine.attempt_action(
        identity,
        adapter.build_action_request(tool="shell.exec", args={"cmd": "rm -rf /"}),
    )
    assert r1.decision == "deny"
    res1, _ = engine.execute(identity, r1.request if False else adapter.build_action_request(tool="shell.exec", args={"cmd": "rm -rf /"}), r1)
    assert res1 is None  # refused by receipt

    # /home write -> require_approval (never executed)
    r2 = engine.attempt_action(
        identity,
        adapter.build_action_request(
            tool="fs.write", args={"path": "/home/u/.bashrc", "data": "x"}
        ),
    )
    assert r2.decision == "require_approval"

    engine.checkpoint()
    engine.end_session(identity)
    pkg = engine.export(identity=identity)
    report = verify_package(pkg)
    assert report.verdict == "AUTHENTIC"


def test_tampered_event_detected(tmp_path):
    engine, adapter = _make_engine()
    identity = adapter.make_identity(agent_id="t3", policy_ref=engine.policy.ref)
    engine.start_session(identity)
    req = adapter.build_action_request(
        tool="fs.write", args={"path": "/tmp/birkin/x", "data": "y"}
    )
    r = engine.attempt_action(identity, req)
    engine.execute(identity, req, r)
    engine.checkpoint()
    engine.end_session(identity)
    pkg = engine.export(identity=identity)
    # Tamper: mutate one event payload without resealing
    pkg_dict = json.loads(pkg.model_dump_json())
    for ev in pkg_dict["events"]:
        if ev["type"] == "tool.executed":
            ev["payload"]["output"] = "TAMPERED"
            break
    pkg_tampered = _coerce_package(pkg_dict)
    report = verify_package(pkg_tampered)
    assert report.verdict == "TAMPERED"
    # The "Event chain valid" check should fail
    chain_check = next(c for c in report.checks if c.name == "Event chain valid")
    assert not chain_check.ok


def test_tampered_receipt_detected():
    engine, adapter = _make_engine()
    identity = adapter.make_identity(agent_id="t4", policy_ref=engine.policy.ref)
    engine.start_session(identity)
    req = adapter.build_action_request(
        tool="fs.write", args={"path": "/tmp/birkin/x", "data": "y"}
    )
    r = engine.attempt_action(identity, req)
    engine.execute(identity, req, r)
    engine.checkpoint()
    engine.end_session(identity)
    pkg = engine.export(identity=identity)
    pkg_dict = json.loads(pkg.model_dump_json())
    # Mutate a receipt's risk_score (without re-signing)
    pkg_dict["receipts"][0]["risk_score"] = 5
    pkg_tampered = _coerce_package(pkg_dict)
    report = verify_package(pkg_tampered)
    assert report.verdict == "TAMPERED"
    sig_check = next(c for c in report.checks if c.name == "Signatures valid")
    assert not sig_check.ok
