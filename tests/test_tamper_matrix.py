"""
╔════════════════════════════════════════════════════════════════════════════╗
║                          SACRED TEST FILE                                   ║
║                                                                            ║
║  This file is part of Birkin's closed credibility surface.                  ║
║                                                                            ║
║  Every test in here asserts that a specific, realistic tampering attack    ║
║  on an exported RunPackage causes ``birkin verify`` to return               ║
║  ``TAMPERED`` (or ``INVALID`` for structural breakage).                     ║
║                                                                            ║
║  Rule (release blocker):                                                   ║
║    No PR may merge if any test in this file is removed, weakened,           ║
║    skipped, or modified to accept ``AUTHENTIC`` for a mutation that          ║
║    previously produced ``TAMPERED``.                                        ║
║                                                                            ║
║  If a future feature requires a new mutation to verify as AUTHENTIC,        ║
║  that is a design change, not a test fix. Open a design discussion         ║
║  first. The credibility of the entire project rests on this closed          ║
║  surface.                                                                  ║
║                                                                            ║
║  See CONTRIBUTING.md → "Sacred tests" for the full rule.                    ║
╚════════════════════════════════════════════════════════════════════════════╝

Tamper surface completeness matrix.

Proves that *each* of the six realistic tampering attacks on a Birkin run
package causes ``birkin verify`` to return ``TAMPERED`` — not ``AUTHENTIC``.

For every attack we:

1. Take a clean, AUTHENTIC package produced by the end-to-end demo.
2. Apply *one* surgical mutation to it.
3. Re-verify.
4. Assert the verdict is ``TAMPERED`` and record *which* of the nine
   verifier checks caught it.

If any of these attacks still verifies as AUTHENTIC, the credibility claim
of the vertical slice is incomplete and this test file goes red.
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

from receiptd import Engine, HermesAdapter, SigningKey, load_default_policy, verify_package
from receiptd.verify import _coerce_package


# --------------------------------------------------------------------------- #
# Fixture: produce one clean AUTHENTIC package to mutate.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def clean_pkg_dict() -> dict:
    sk = SigningKey.generate()
    policy = load_default_policy()
    adapter = HermesAdapter()
    engine = Engine(birkin_signing_key=sk, policy=policy, adapter=adapter)
    identity = adapter.make_identity(agent_id="tamper-matrix-agent", policy_ref=policy.ref)
    engine.start_session(identity)
    engine.declare_intent(identity, adapter.declare_intent(identity, "matrix test intent"))
    for path in ("/tmp/birkin/a.txt", "/tmp/birkin/b.txt"):
        req = adapter.build_action_request(
            tool="fs.write", args={"path": path, "data": "x"}
        )
        r = engine.attempt_action(identity, req)
        engine.execute(identity, req, r)
    engine.checkpoint()
    engine.end_session(identity)
    pkg = engine.export(identity=identity)
    # Sanity: clean package verifies AUTHENTIC before we mutate.
    clean_report = verify_package(pkg)
    assert clean_report.verdict == "AUTHENTIC", "clean package must verify AUTHENTIC before mutation"
    return json.loads(pkg.model_dump_json())


def _verify(d: dict):
    return verify_package(_coerce_package(d))


def _expect_tampered(d: dict, label: str) -> None:
    report = _verify(d)
    assert report.verdict == "TAMPERED", (
        f"TAMPER SURFACE LEAK: {label} still verifies as {report.verdict}.\n"
        f"Checks: {[c.model_dump() for c in report.checks]}"
    )


def _failing_checks(report) -> list[str]:
    return [c.name for c in report.checks if not c.ok]


# --------------------------------------------------------------------------- #
# The six attacks
# --------------------------------------------------------------------------- #
def test_attack_a_receipt_signature_flip(clean_pkg_dict):
    """(1) Flip one byte of a receipt's signature."""
    d = copy.deepcopy(clean_pkg_dict)
    sig = d["receipts"][0]["signature"]
    # Flip the first base64 char (avoid '=' padding chars to keep base64 valid)
    idx = next(i for i, c in enumerate(sig) if c not in "=")
    flipped = chr(ord(sig[idx]) ^ 1) if sig[idx] != "A" else "B"
    d["receipts"][0]["signature"] = sig[:idx] + flipped + sig[idx + 1:]
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    assert "Signatures valid" in _failing_checks(report)


def test_attack_b_identity_rewrite(clean_pkg_dict):
    """(2) Rewrite the agent identity's public_key (and signature) so the
    passport claims to be a different agent."""
    d = copy.deepcopy(clean_pkg_dict)
    new_sk = SigningKey.generate()
    # Self-sign a new identity that claims to be the original agent
    ident = d["identity"]
    ident["public_key"] = new_sk.public_b64
    # Re-sign only the identity (with the new key), but leave every event's
    # 'actor' and every receipt's 'agent_id' pointing at the old agent_id.
    from receiptd.models import AgentIdentity
    new_ident = AgentIdentity(**ident)
    new_ident.sign(new_sk)
    d["identity"] = json.loads(new_ident.model_dump_json(by_alias=True))
    report = _verify(d)
    # Identity's own signature is valid (we re-signed it), but the
    # Birkin-control-plane-signed events/receipts still name the original
    # agent_id, and the new "Identity bound to run" check cross-references
    # session.start.payload.public_key (signed by Birkin) against the
    # rewritten identity — so the rewrite is caught.
    assert report.verdict == "TAMPERED"
    fails = _failing_checks(report)
    assert any(
        name in fails for name in (
            "Identity verified",
            "Signatures valid",
            "Authorization receipts valid",
            "Identity bound to run",
        )
    ), f"identity rewrite must be caught; failing checks were {fails}"


def test_attack_c_policy_version_swap(clean_pkg_dict):
    """(3) Swap policy.spec for a different (more permissive) policy while
    keeping the claimed sha256 unchanged."""
    d = copy.deepcopy(clean_pkg_dict)
    spec = d["policy"]["spec"]
    # Insert a wildly permissive rule and bump the version string in spec
    spec["rules"] = [{"id": "evil.allow.all", "match": {}, "decision": "allow",
                       "risk_score": 1, "reason": "evil"}]
    spec["version"] = "999.evil"
    spec["name"] = "evil"
    # Do NOT update policy.sha256 — the attacker wants the swap to be silent.
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    assert "Policy version verified" in _failing_checks(report)


def test_attack_d_checkpoint_root_rewrite(clean_pkg_dict):
    """(4) Replace the Merkle root with a forged value (without re-signing)."""
    d = copy.deepcopy(clean_pkg_dict)
    # Flip the first hex char of the root
    root = d["final_checkpoint"]["root"]
    flipped = ("a" if root[0] != "a" else "b") + root[1:]
    d["final_checkpoint"]["root"] = flipped
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    assert "Checkpoint matches" in _failing_checks(report)


def test_attack_e_missing_event(clean_pkg_dict):
    """(5) Delete one event from the middle of the chain."""
    d = copy.deepcopy(clean_pkg_dict)
    # Remove event #7 (tool.executed) — leaves a gap in sequence numbers
    # AND breaks prev_hash linkage on the next event.
    d["events"] = [e for e in d["events"] if e["sequence"] != 7]
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    fails = _failing_checks(report)
    assert any(
        name in fails for name in ("No missing events", "Event chain valid")
    ), f"missing event must be caught; failing checks were {fails}"


def test_attack_f_reordered_event(clean_pkg_dict):
    """(6) Swap the order of two adjacent events without rewriting hashes."""
    d = copy.deepcopy(clean_pkg_dict)
    # Swap events at positions 6 and 7 (receipt.issued <-> tool.executed)
    # This breaks prev_hash linkage on the swapped event and on its successor.
    evs = d["events"]
    evs[5], evs[6] = evs[6], evs[5]
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    fails = _failing_checks(report)
    assert any(
        name in fails for name in ("Event chain valid", "No missing events")
    ), f"reordered event must be caught; failing checks were {fails}"


# --------------------------------------------------------------------------- #
# Summary table (printable; run with -s to see)
# --------------------------------------------------------------------------- #
def test_print_tamper_matrix(clean_pkg_dict, capsys):
    """Print the canonical tamper matrix table for human review."""
    cases = [
        ("A. receipt signature flip",   test_attack_a_receipt_signature_flip),
        ("B. identity rewrite",         test_attack_b_identity_rewrite),
        ("C. policy version swap",     test_attack_c_policy_version_swap),
        ("D. checkpoint root rewrite",  test_attack_d_checkpoint_root_rewrite),
        ("E. missing event",            test_attack_e_missing_event),
        ("F. reordered event",          test_attack_f_reordered_event),
    ]
    print()
    print("=" * 78)
    print("BIRKIN TAMPER SURFACE MATRIX — every mutation MUST verify as TAMPERED")
    print("=" * 78)
    print(f"{'attack':<32}  {'verdict':<10}  {'caught by'}")
    print("-" * 78)
    for label, fn in cases:
        d = copy.deepcopy(clean_pkg_dict)
        # Run the mutation in-place; each *_test mutates `clean_pkg_dict`
        # via the fixture copy argument. We re-invoke by calling with d.
        # Simpler: just call fn(d) directly. We need to bind clean_pkg_dict
        # to d. The cleanest path is to redefine the mutation inline.
        pass
    # Print the actual matrix by re-running each attack directly:
    rows = []
    # A
    d = copy.deepcopy(clean_pkg_dict)
    sig = d["receipts"][0]["signature"]
    idx = next(i for i, c in enumerate(sig) if c not in "=")
    flipped = chr(ord(sig[idx]) ^ 1) if sig[idx] != "A" else "B"
    d["receipts"][0]["signature"] = sig[:idx] + flipped + sig[idx + 1:]
    r = _verify(d); rows.append(("A. receipt signature flip", r, "Signatures valid"))
    # B
    d = copy.deepcopy(clean_pkg_dict)
    new_sk = SigningKey.generate()
    ident = d["identity"]
    ident["public_key"] = new_sk.public_b64
    from receiptd.models import AgentIdentity
    new_ident = AgentIdentity(**ident); new_ident.sign(new_sk)
    d["identity"] = json.loads(new_ident.model_dump_json(by_alias=True))
    r = _verify(d); rows.append(("B. identity rewrite", r, "Identity/Signature/Receipt"))
    # C
    d = copy.deepcopy(clean_pkg_dict)
    spec = d["policy"]["spec"]
    spec["rules"] = [{"id": "evil.allow.all", "match": {}, "decision": "allow",
                       "risk_score": 1, "reason": "evil"}]
    spec["version"] = "999.evil"; spec["name"] = "evil"
    r = _verify(d); rows.append(("C. policy version swap", r, "Policy version verified"))
    # D
    d = copy.deepcopy(clean_pkg_dict)
    root = d["final_checkpoint"]["root"]
    d["final_checkpoint"]["root"] = ("a" if root[0] != "a" else "b") + root[1:]
    r = _verify(d); rows.append(("D. checkpoint root rewrite", r, "Checkpoint matches"))
    # E
    d = copy.deepcopy(clean_pkg_dict)
    d["events"] = [e for e in d["events"] if e["sequence"] != 7]
    r = _verify(d); rows.append(("E. missing event", r, "No missing events / Event chain"))
    # F
    d = copy.deepcopy(clean_pkg_dict)
    evs = d["events"]; evs[5], evs[6] = evs[6], evs[5]
    r = _verify(d); rows.append(("F. reordered event", r, "Event chain valid"))

    all_tampered = True
    for label, report, expected_check in rows:
        verdict = report.verdict
        fails = _failing_checks(report)
        mark = "✓" if verdict == "TAMPERED" else "✗ LEAK"
        if verdict != "TAMPERED":
            all_tampered = False
        print(f"{mark} {label:<30}  {verdict:<10}  {expected_check} ({', '.join(fails) or '-'})")
    print("-" * 78)
    print(f"{'ALL TAMPERED' if all_tampered else 'LEAK DETECTED'}")
    print("=" * 78)
    assert all_tampered, "tamper matrix is incomplete — at least one attack verifies as AUTHENTIC"
