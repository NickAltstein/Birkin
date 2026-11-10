"""Threat-model-driven security tests for Birkin policy enforcement and HITL lifecycle."""
from __future__ import annotations

import os
from pathlib import Path
import pytest

from receiptd import (
    Engine,
    NullAgentAdapter,
    SigningKey,
    load_default_policy,
    PolicySpec,
    ActionRequest,
    AuthorizationReceipt,
)


def _setup_engine(policy_spec: PolicySpec | None = None) -> tuple[Engine, any, any]:
    sk = SigningKey.generate()
    p = policy_spec or load_default_policy()
    adapter = NullAgentAdapter()
    engine = Engine(birkin_signing_key=sk, policy=p, adapter=adapter)
    identity = adapter.make_identity(agent_id="security-agent", policy_ref=p.ref)
    engine.start_session(identity)
    return engine, identity, adapter


def test_path_traversal_blocked():
    """Path traversal sequences (e.g., ../../etc/passwd) must be normalized and not match sandbox prefixes."""
    engine, identity, adapter = _setup_engine()

    # Attempting to escape /tmp/birkin/ using relative directory traversal
    traversal_path = "/tmp/birkin/../../etc/shadow"
    req = adapter.build_action_request(tool="fs.write", args={"path": traversal_path, "data": "evil"})
    receipt = engine.attempt_action(identity, req)

    # Must be denied (by system deny rule), NEVER allowed
    assert receipt.decision == "deny", (
        f"PATH TRAVERSAL VULNERABILITY: path {traversal_path} was granted {receipt.decision} under rule {receipt.rule}"
    )
    assert receipt.rule in ("fs.write.system.deny", "default.deny")


def test_sandbox_write_allowed():
    """Legitimate writes inside the sandbox are allowed."""
    engine, identity, adapter = _setup_engine()

    clean_path = "/tmp/birkin/sandbox_output.txt"
    req = adapter.build_action_request(tool="fs.write", args={"path": clean_path, "data": "clean"})
    receipt = engine.attempt_action(identity, req)

    assert receipt.decision == "allow"
    assert receipt.rule == "fs.write.sandbox.allow"


def test_host_spoofing_in_query_param_blocked():
    """Urls containing trusted hosts in query params must not bypass host matching."""
    policy_dict = {
        "name": "network_policy",
        "version": "1.0.0",
        "rules": [
            {
                "id": "http.trusted.allow",
                "match": {"tool": "http.get", "host_in": ["internal.api.corp"]},
                "decision": "allow",
                "risk_score": 20,
            },
            {
                "id": "http.default.deny",
                "match": {"tool": "http.get"},
                "decision": "deny",
                "risk_score": 90,
            },
        ],
    }
    policy = PolicySpec.from_dict(policy_dict)
    engine, identity, adapter = _setup_engine(policy)

    # Attacker host with trusted host in query parameter
    malicious_url = "https://attacker.com/steal?target=internal.api.corp"
    req = adapter.build_action_request(tool="http.get", args={"url": malicious_url})
    receipt = engine.attempt_action(identity, req)

    assert receipt.decision == "deny"
    assert receipt.rule == "http.default.deny"


def test_hitl_approval_lifecycle_granted():
    """Test human-in-the-loop: require_approval -> approval granted -> execution allowed."""
    engine, identity, adapter = _setup_engine()

    # An action that requires approval under default policy (e.g. fs.write outside sandbox in /home/)
    req = adapter.build_action_request(tool="fs.write", args={"path": "/home/user/export.csv", "data": "row1"})
    receipt = engine.attempt_action(identity, req)
    assert receipt.decision == "require_approval"

    # Execution is refused without approval
    res, ev = engine.execute(identity, req, receipt)
    assert res is None
    assert ev.payload["alert"] == "execution.refused"

    # Human grants approval
    approved_receipt = engine.approve(
        identity,
        receipt,
        approved_by="secops@corp.internal",
        reason="Verified business need for one-time export",
    )
    assert approved_receipt.decision == "allow"
    assert approved_receipt.verify(engine.birkin_signing_key.public_b64)

    # Execution now succeeds
    res_approved, ev_approved = engine.execute(identity, req, approved_receipt)
    assert res_approved is not None
    assert ev_approved.type == "tool.executed"


def test_hitl_approval_lifecycle_rejected():
    """Test human-in-the-loop: require_approval -> approval rejected -> execution denied."""
    engine, identity, adapter = _setup_engine()

    req = adapter.build_action_request(tool="fs.write", args={"path": "/home/user/config.json", "data": "{}"})
    receipt = engine.attempt_action(identity, req)
    assert receipt.decision == "require_approval"

    # Explicit rejection
    rejected_receipt = engine.reject(
        identity,
        receipt,
        rejected_by="secops@corp.internal",
        reason="Unauthorized configuration modification attempt",
    )
    assert rejected_receipt.decision == "deny"
    assert rejected_receipt.verify(engine.birkin_signing_key.public_b64)

    # Execution is refused
    res_rejected, ev_rejected = engine.execute(identity, req, rejected_receipt)
    assert res_rejected is None
    assert ev_rejected.payload["alert"] == "execution.refused"


def test_sibling_prefix_collision_blocked():
    """Paths with shared string prefixes (e.g. /tmp/birkin-unsafe) must NOT match /tmp/birkin/ sandbox."""
    engine, identity, adapter = _setup_engine()

    # Sibling path that begins with /tmp/birkin as a substring but is a different directory
    sibling_path = "/tmp/birkin-unsafe/leak.txt"
    req = adapter.build_action_request(tool="fs.write", args={"path": sibling_path, "data": "leak"})
    receipt = engine.attempt_action(identity, req)

    # Must NOT be allowed by the /tmp/birkin/ sandbox allow rule
    assert receipt.decision != "allow", (
        f"CRITICAL VULNERABILITY: sibling directory {sibling_path} was granted allow under {receipt.rule}"
    )
    # Under default policy, writes outside sandbox require human approval
    assert receipt.decision == "require_approval"
    assert receipt.rule == "fs.write.elsewhere.require_approval"


def test_symlink_traversal_escape_blocked(tmp_path: Path):
    """Symlinks inside the sandbox resolving outside must not bypass containment checks."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "shadow").write_text("root:secret")

    # Create symlink pointing outside sandbox
    leak_symlink = sandbox / "link_outside"
    leak_symlink.symlink_to(outside)

    policy_dict = {
        "name": "strict_sandbox_policy",
        "version": "1.0.0",
        "rules": [
            {
                "id": "fs.sandbox.allow",
                "match": {"tool": "fs.write", "path_prefix": [str(sandbox)]},
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
    engine, identity, adapter = _setup_engine(policy)

    # Attempting to write through the symlink to an outside destination
    target_path = str(leak_symlink / "shadow")
    req = adapter.build_action_request(tool="fs.write", args={"path": target_path, "data": "overwrite"})
    receipt = engine.attempt_action(identity, req)

    assert receipt.decision == "deny", (
        f"SYMLINK ESCAPE VULNERABILITY: write through symlink to {target_path} was granted {receipt.decision}"
    )
    assert receipt.rule == "fs.default.deny"


def test_relative_and_unanchored_paths_fail_closed():
    """Unanchored relative paths must not match absolute sandbox prefixes."""
    engine, identity, adapter = _setup_engine()

    for rel_path in ("relative/output.txt", "birkin/leak.txt", "file.log", "../../etc/passwd"):
        req = adapter.build_action_request(tool="fs.write", args={"path": rel_path, "data": "test"})
        receipt = engine.attempt_action(identity, req)
        assert receipt.decision != "allow", f"Relative path {rel_path} was unexpectedly allowed"


def test_malformed_paths_fail_closed():
    """Null bytes, empty strings, and malformed paths must fail-closed."""
    engine, identity, adapter = _setup_engine()

    for bad_path in ("/tmp/birkin/file\x00evil.txt", "", "   ", None):
        args = {"path": bad_path, "data": "evil"} if bad_path is not None else {"data": "evil"}
        req = adapter.build_action_request(tool="fs.write", args=args)
        receipt = engine.attempt_action(identity, req)
        assert receipt.decision != "allow", f"Malformed path {bad_path!r} was unexpectedly allowed"


def test_symlink_cycle_fails_closed(tmp_path: Path):
    """Symlink cycles must be safely handled and fail closed without crashing."""
    link_a = tmp_path / "link_a"
    link_b = tmp_path / "link_b"
    link_a.symlink_to(link_b)
    link_b.symlink_to(link_a)

    policy_dict = {
        "name": "cycle_policy",
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
    engine, identity, adapter = _setup_engine(policy)

    req = adapter.build_action_request(tool="fs.write", args={"path": str(link_a / "file.txt")})
    receipt = engine.attempt_action(identity, req)
    assert receipt.decision == "deny"


def test_hitl_reject_and_approve_identity_binding():
    """Approve and reject must enforce identity binding against original receipt."""
    engine, identity, adapter = _setup_engine()
    other_identity = adapter.make_identity(agent_id="attacker-agent", policy_ref=engine.policy_ref)
    engine.start_session(other_identity)

    req = adapter.build_action_request(tool="fs.write", args={"path": "/home/user/doc.txt", "data": "data"})
    receipt = engine.attempt_action(identity, req)
    assert receipt.decision == "require_approval"

    # Reject with mismatched identity must raise ValueError
    with pytest.raises(ValueError, match="identity mismatch"):
        engine.reject(other_identity, receipt, rejected_by="secops", reason="Unauthorized")

    # Approve with mismatched identity must raise ValueError
    with pytest.raises(ValueError, match="identity mismatch"):
        engine.approve(other_identity, receipt, approved_by="secops", reason="Unauthorized")


def test_hitl_reject_and_approve_signature_verification():
    """Approve and reject must verify receipt cryptographic signature before state transition."""
    engine, identity, adapter = _setup_engine()

    req = adapter.build_action_request(tool="fs.write", args={"path": "/home/user/doc.txt", "data": "data"})
    receipt = engine.attempt_action(identity, req)

    # Corrupt the receipt signature
    receipt.signature = "AAAA" + receipt.signature[4:]

    with pytest.raises(ValueError, match="invalid or unverified cryptographic signature"):
        engine.reject(identity, receipt, rejected_by="secops", reason="Reject forged")

    with pytest.raises(ValueError, match="invalid or unverified cryptographic signature"):
        engine.approve(identity, receipt, approved_by="secops", reason="Approve forged")


def test_hitl_prevent_duplicate_state_transitions():
    """Receipts can only transition approval state once; duplicates must be prevented."""
    engine, identity, adapter = _setup_engine()

    # 1. Test reject -> cannot reject or approve again
    req1 = adapter.build_action_request(tool="fs.write", args={"path": "/home/user/file1.txt", "data": "d1"})
    receipt1 = engine.attempt_action(identity, req1)
    engine.reject(identity, receipt1, rejected_by="admin", reason="First rejection")

    with pytest.raises(ValueError, match="already resolved"):
        engine.reject(identity, receipt1, rejected_by="admin", reason="Duplicate rejection")

    with pytest.raises(ValueError, match="already resolved"):
        engine.approve(identity, receipt1, approved_by="admin", reason="Approve after rejection")

    # 2. Test approve -> cannot approve or reject again
    req2 = adapter.build_action_request(tool="fs.write", args={"path": "/home/user/file2.txt", "data": "d2"})
    receipt2 = engine.attempt_action(identity, req2)
    engine.approve(identity, receipt2, approved_by="admin", reason="First approval")

    with pytest.raises(ValueError, match="already resolved"):
        engine.approve(identity, receipt2, approved_by="admin", reason="Duplicate approval")

    with pytest.raises(ValueError, match="already resolved"):
        engine.reject(identity, receipt2, rejected_by="admin", reason="Reject after approval")


def test_execute_enforces_identity_and_args_integrity():
    """Execution must refuse receipts if identity or arguments are tampered."""
    engine, identity, adapter = _setup_engine()
    other_identity = adapter.make_identity(agent_id="other-agent", policy_ref=engine.policy_ref)
    engine.start_session(other_identity)

    # Legitimate sandbox write
    req = adapter.build_action_request(tool="fs.write", args={"path": "/tmp/birkin/out.txt", "data": "safe"})
    receipt = engine.attempt_action(identity, req)
    assert receipt.decision == "allow"

    # Execution by another identity must be refused
    res, ev = engine.execute(other_identity, req, receipt)
    assert res is None
    assert ev.payload["reason"] == "identity_mismatch"

    # Execution with swapped/tampered arguments must be refused
    tampered_req = adapter.build_action_request(tool="fs.write", args={"path": "/etc/shadow", "data": "evil"})
    res2, ev2 = engine.execute(identity, tampered_req, receipt)
    assert res2 is None
    assert ev2.payload["reason"] == "args_hash_mismatch"
