"""
Second-adapter proof: NullAgent runs through the *same* Birkin control
plane and produces AUTHENTIC packages via the *same* offline verifier.

If this test passes, the ``AgentAdapter`` Protocol is a real seam, not a
one-customer interface. Hermes is one implementation; NullAgent is another;
the engine, ledger, receipt signer, and verifier are unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from receiptd import (
    Engine,
    NullAgentAdapter,
    SigningKey,
    load_default_policy,
    verify_package,
)


def test_null_agent_runs_through_birkin_and_verifies_authentic():
    sk = SigningKey.generate()
    policy = load_default_policy()
    adapter = NullAgentAdapter()
    engine = Engine(birkin_signing_key=sk, policy=policy, adapter=adapter)

    identity = adapter.make_identity(
        agent_id="null-agent-01",
        policy_ref=policy.ref,
        ttl_seconds=600,
    )
    assert identity.runtime == "null-0.1.0", (
        f"NullAgent must record its own runtime string in the passport; "
        f"got {identity.runtime}"
    )

    engine.start_session(identity)
    engine.declare_intent(
        identity,
        adapter.declare_intent(identity, "prove the AgentAdapter seam"),
    )

    # null.ping is allowed by policy -> receipt.decision == "allow"
    req = adapter.build_action_request(
        tool="null.ping",
        args={"echo": "hello seam"},
        justification="prove second adapter works",
    )
    r = engine.attempt_action(identity, req)
    assert r.decision == "allow", r.reason
    assert r.agent_public_key == identity.public_key
    assert r.tool == "null.ping"
    result, _ = engine.execute(identity, req, r)
    assert result.ok
    assert result.output == {"echo": {"echo": "hello seam"}}

    # The same engine that gates Hermes gates NullAgent. shell.exec would
    # be denied by the same policy.
    bad_req = adapter.build_action_request(
        tool="shell.exec", args={"cmd": "rm -rf /"}
    )
    bad_r = engine.attempt_action(identity, bad_req)
    assert bad_r.decision == "deny"

    engine.checkpoint()
    engine.end_session(identity)

    pkg = engine.export(identity=identity)
    report = verify_package(pkg)
    assert report.verdict == "AUTHENTIC", [c.model_dump() for c in report.checks]


def test_null_agent_and_hermes_produce_compatible_packages():
    """Two different adapters, same engine, same verifier, both AUTHENTIC.

    The verifier does not branch on adapter type. The receipt schema, the
    audit event schema, and the checkpoint schema are identical regardless
    of which adapter produced them.
    """
    from receiptd import HermesAdapter

    results = []
    for AdapterCls, tool, args in [
        (HermesAdapter, "fs.write", {"path": "/tmp/birkin/x", "data": "y"}),
        (NullAgentAdapter, "null.ping", {"echo": "hi"}),
    ]:
        sk = SigningKey.generate()
        policy = load_default_policy()
        adapter = AdapterCls()
        engine = Engine(birkin_signing_key=sk, policy=policy, adapter=adapter)
        ident = adapter.make_identity(
            agent_id=f"{adapter.name}-agent", policy_ref=policy.ref
        )
        engine.start_session(ident)
        engine.declare_intent(
            ident, adapter.declare_intent(ident, "cross-adapter compat test")
        )
        req = adapter.build_action_request(tool=tool, args=args)
        r = engine.attempt_action(ident, req)
        assert r.decision == "allow"
        engine.execute(ident, req, r)
        engine.checkpoint()
        engine.end_session(ident)
        pkg = engine.export(identity=ident)
        report = verify_package(pkg)
        results.append((adapter.name, report.verdict))

    print()
    print("=" * 60)
    print("CROSS-ADAPTER COMPATIBILITY — same engine, same verifier")
    print("=" * 60)
    for name, verdict in results:
        print(f"  {name:<10}  ->  {verdict}")
    print("=" * 60)
    assert all(v == "AUTHENTIC" for _, v in results)
