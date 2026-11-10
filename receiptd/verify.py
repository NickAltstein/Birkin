"""
birkin.verify
=============

Offline verification of a Birkin :class:`RunPackage`.

This module is the credibility feature. It takes a single JSON file
produced by ``Engine.export`` and, with no Birkin server, no policy file,
no agent runtime — nothing but the package itself — produces a verdict:

* ``AUTHENTIC``    — every check passed;
* ``TAMPERED``     — at least one integrity check failed;
* ``INVALID``      — the package is structurally broken.

The verifier runs exactly seven checks, in order:

1. Event chain valid           — each event's prev_hash matches prior event_hash
2. Signatures valid            — every event + receipt + checkpoint signature verifies
3. Policy version verified    — policy.sha256 == recomputed hash over policy.spec
4. Identity verified           — the agent passport's self-signature verifies
5. No missing events           — sequence numbers are dense 1..N
6. Checkpoint matches          — recomputed Merkle root == final_checkpoint.root
7. Authorization receipts valid — every side-effecting event references a real receipt

The output is identical every time the same package is verified. It is
designed to be pasteable into a security review, an incident report, or a
changelog entry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .crypto import (
    canonical_json,
    merkle_root,
    sha256_hex,
    verify_signature,
)
from .models import (
    AgentIdentity,
    AuthorizationReceipt,
    AuditEvent,
    CheckResult,
    MerkleCheckpoint,
    PACKAGE_MANIFEST,
    RunPackage,
    VerificationReport,
)


# Schemas this verifier knows how to handle. If a package's manifest
# references a schema we don't recognize, we refuse to verify rather
# than silently misinterpreting the bytes.
SUPPORTED_MANIFEST = {
    "evidence_format": PACKAGE_MANIFEST["evidence_format"],
    "identity_scheme": PACKAGE_MANIFEST["identity_scheme"],
    "receipt_scheme":  PACKAGE_MANIFEST["receipt_scheme"],
    "audit_event_scheme": PACKAGE_MANIFEST["audit_event_scheme"],
    "checkpoint_scheme": PACKAGE_MANIFEST["checkpoint_scheme"],
    "policy_decision_scheme": PACKAGE_MANIFEST["policy_decision_scheme"],
}


# Side-effecting event types that MUST reference a receipt.
SIDE_EFFECTING_TYPES = {
    "tool.attempt",
    "tool.allow",
    "tool.deny",
    "tool.require_approval",
    "tool.executed",
    "receipt.issued",
}


# --------------------------------------------------------------------------- #
# Pretty rendering
# --------------------------------------------------------------------------- #
def render_report(report: VerificationReport) -> str:
    """Render a :class:`VerificationReport` as the canonical text block."""
    lines: list[str] = []
    lines.append("BIRKIN VERIFICATION")
    for c in report.checks:
        mark = "✓" if c.ok else "✗"
        lines.append(f"{mark} {c.name}" + (f"  ({c.detail})" if c.detail and not c.ok else ""))
    lines.append(f"VERDICT: {report.verdict}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Core verifier
# --------------------------------------------------------------------------- #
def verify_package(pkg: RunPackage) -> VerificationReport:
    birkin_pub = pkg.birkin_public_key
    checks: list[CheckResult] = []

    # --- 0. Manifest + schema versions ---------------------------------
    # Run *first*. If the package's manifest references schemas this
    # verifier does not know, every other check is meaningless — we'd be
    # re-deriving hashes from a different field set than the signer used.
    manifest = getattr(pkg, "manifest", None) or {}
    missing = [k for k in SUPPORTED_MANIFEST if k not in manifest]
    mismatched = [
        k for k, v in SUPPORTED_MANIFEST.items()
        if k in manifest and manifest.get(k) != v
    ]
    man_ok = (not missing) and (not mismatched)
    man_detail = ""
    if missing:
        man_detail = f"manifest missing keys: {missing}"
    elif mismatched:
        man_detail = (
            f"schema version mismatch on {mismatched}; "
            f"this verifier supports {SUPPORTED_MANIFEST}"
        )
    checks.append(CheckResult(name="Manifest + schema versions", ok=man_ok, detail=man_detail))

    # --- 1. Event chain valid -----------------------------------------
    chain_ok = True
    chain_detail = ""
    prev = "0" * 64
    for i, ev in enumerate(pkg.events):
        if ev.prev_hash != prev:
            chain_ok = False
            chain_detail = f"event #{ev.sequence} prev_hash mismatch"
            break
        if not ev.verify_hash():
            chain_ok = False
            chain_detail = f"event #{ev.sequence} event_hash mismatch (tampered payload?)"
            break
        prev = ev.event_hash or ""
    checks.append(CheckResult(name="Event chain valid", ok=chain_ok, detail=chain_detail))

    # --- 2. Signatures valid ------------------------------------------
    sig_ok = True
    sig_detail = ""
    for ev in pkg.events:
        if not ev.verify_signature(birkin_pub):
            sig_ok = False
            sig_detail = f"event #{ev.sequence} signature invalid"
            break
    if sig_ok:
        for r in pkg.receipts:
            if not r.verify(birkin_pub):
                sig_ok = False
                sig_detail = f"receipt {r.receipt_id} signature invalid"
                break
    if sig_ok:
        for cp in pkg.checkpoints:
            if not cp.verify(birkin_pub):
                sig_ok = False
                sig_detail = f"checkpoint {cp.checkpoint_id} signature invalid"
                break
    checks.append(CheckResult(name="Signatures valid", ok=sig_ok, detail=sig_detail))

    # --- 3. Policy version verified -----------------------------------
    recomputed = sha256_hex(canonical_json(pkg.policy["spec"]))
    policy_ok = recomputed == pkg.policy["sha256"]
    checks.append(
        CheckResult(
            name="Policy version verified",
            ok=policy_ok,
            detail="" if policy_ok else "policy sha256 mismatch",
        )
    )

    # --- 4. Identity verified -----------------------------------------
    ident_ok = pkg.identity.verify()
    checks.append(
        CheckResult(
            name="Identity verified",
            ok=ident_ok,
            detail="" if ident_ok else "agent passport signature invalid",
        )
    )

    # --- 5. No missing events ----------------------------------------
    seq_ok = True
    seq_detail = ""
    for i, ev in enumerate(pkg.events, start=1):
        if ev.sequence != i:
            seq_ok = False
            seq_detail = f"expected sequence {i}, got {ev.sequence}"
            break
    checks.append(CheckResult(name="No missing events", ok=seq_ok, detail=seq_detail))

    # --- 6. Checkpoint matches ---------------------------------------
    # The checkpoint covers a *range* of events (sequence_range). The
    # verifier recomputes the Merkle root over exactly that range and
    # compares to checkpoint.root. Events appended after the checkpoint
    # (e.g. the 'checkpoint' audit event itself, 'session.end') are
    # covered by a subsequent checkpoint or by an export-level final hash.
    cp = pkg.final_checkpoint
    if cp is None:
        cp_ok = False
        cp_detail = "no final checkpoint present"
    else:
        start, end = cp.sequence_range
        in_range = [ev for ev in pkg.events if start <= ev.sequence <= end]
        if len(in_range) != cp.leaf_count:
            cp_ok = False
            cp_detail = (
                f"checkpoint claims {cp.leaf_count} leaves but range "
                f"{cp.sequence_range} contains {len(in_range)} events"
            )
        else:
            leaf_hashes = [ev.event_hash for ev in in_range if ev.event_hash]
            recomputed_root = merkle_root(leaf_hashes)
            cp_ok = recomputed_root == cp.root
            cp_detail = "" if cp_ok else "checkpoint root mismatch"
            if cp_ok:
                cp_ok = cp.verify(birkin_pub)
                cp_detail = "" if cp_ok else "checkpoint signature invalid"
    checks.append(CheckResult(name="Checkpoint matches", ok=cp_ok, detail=cp_detail))

    # --- 7. Authorization receipts valid ------------------------------
    receipt_index = {r.receipt_id: r for r in pkg.receipts}
    rec_ok = True
    rec_detail = ""
    for ev in pkg.events:
        if ev.type in SIDE_EFFECTING_TYPES:
            if not ev.receipt_id:
                rec_ok = False
                rec_detail = f"event #{ev.sequence} ({ev.type}) has no receipt_id"
                break
            r = receipt_index.get(ev.receipt_id)
            if r is None:
                rec_ok = False
                rec_detail = f"event #{ev.sequence} references missing receipt {ev.receipt_id}"
                break
            if not r.verify(birkin_pub):
                rec_ok = False
                rec_detail = f"receipt {r.receipt_id} signature invalid"
                break
    checks.append(CheckResult(name="Authorization receipts valid", ok=rec_ok, detail=rec_detail))

    # --- 8. Identity bound to run -------------------------------------
    # The agent identity embedded in the package must be cryptographically
    # consistent with the audit trail and the receipts. Specifically:
    #
    #   (a) the public_key recorded in the session.start event (which was
    #       signed by the Birkin control plane and cannot be tampered with
    #       without invalidating its signature) must equal
    #       pkg.identity.public_key;
    #
    #   (b) every receipt's agent_public_key must equal
    #       pkg.identity.public_key (so a swapped identity cannot silently
    #       re-bind the receipts to a different agent);
    #
    #   (c) every receipt's agent_id must equal pkg.identity.agent_id;
    #
    #   (d) every receipt's prior_event_hash must reference an event that
    #       actually exists in the package (so a receipt cannot be lifted
    #       out and inserted into a different run);
    #
    #   (e) every receipt's session_id must equal pkg.identity.session_id.
    #
    # This is the cross-object binding check. Without it, an attacker
    # could rewrite identity.json to claim a different agent, and the
    # self-signed passport would still verify (Attack B in the tamper
    # matrix). The new binding makes that attack fail.
    bind_ok = True
    bind_detail = ""
    session_start = next(
        (ev for ev in pkg.events if ev.type == "session.start"), None
    )
    if session_start is not None:
        ss_pub = session_start.payload.get("public_key")
        if ss_pub != pkg.identity.public_key:
            bind_ok = False
            bind_detail = (
                "session.start payload public_key does not match "
                "pkg.identity.public_key (identity swapped?)"
            )
    if bind_ok:
        event_hashes = {ev.event_hash for ev in pkg.events if ev.event_hash}
        for r in pkg.receipts:
            if r.agent_public_key != pkg.identity.public_key:
                bind_ok = False
                bind_detail = (
                    f"receipt {r.receipt_id} agent_public_key does not match "
                    f"pkg.identity.public_key (receipt re-bound to a different agent?)"
                )
                break
            if r.agent_id != pkg.identity.agent_id:
                bind_ok = False
                bind_detail = (
                    f"receipt {r.receipt_id} agent_id does not match "
                    f"pkg.identity.agent_id"
                )
                break
            if r.session_id != pkg.identity.session_id:
                bind_ok = False
                bind_detail = (
                    f"receipt {r.receipt_id} session_id does not match "
                    f"pkg.identity.session_id (cross-run receipt replay?)"
                )
                break
            if r.prior_event_hash not in event_hashes and r.prior_event_hash != "0" * 64:
                bind_ok = False
                bind_detail = (
                    f"receipt {r.receipt_id} prior_event_hash does not exist "
                    f"in the audit chain (receipt lifted from a different run?)"
                )
                break
    checks.append(CheckResult(name="Identity bound to run", ok=bind_ok, detail=bind_detail))

    # --- verdict ------------------------------------------------------
    all_ok = all(c.ok for c in checks)
    verdict = "AUTHENTIC" if all_ok else "TAMPERED"
    if not pkg.events:
        verdict = "INVALID"

    return VerificationReport(
        run_id=pkg.run_id,
        checks=checks,
        verdict=verdict,
    )


# --------------------------------------------------------------------------- #
# Loading helpers
# --------------------------------------------------------------------------- #
def load_run_package(path: str | Path) -> RunPackage:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return _coerce_package(data)


def _coerce_package(data: dict[str, Any]) -> RunPackage:
    # The manifest is the *first* thing we look at. If it's missing or
    # references unknown schemas, we refuse to coerce the rest of the
    # package — because Pydantic would happily fill in defaults that
    # don't reflect what was actually signed.
    if "manifest" not in data or not isinstance(data["manifest"], dict):
        # Return a minimal sentinel package that verify_package() will
        # mark as INVALID via the manifest check.
        return RunPackage(
            run_id=data.get("run_id", "unknown"),
            birkin_public_key=data.get("birkin_public_key", ""),
            identity=AgentIdentity(
                agent_id="invalid",
                public_key="invalid",
                runtime="invalid",
                policy="invalid",
                session_id="invalid",
                expires_at="1970-01-01T00:00:00.000000Z",
            ),
            policy={"name": "invalid", "version": "0", "sha256": "", "spec": {}},
            manifest={"_missing": "true"},
        )
    # Recursively coerce nested dicts into our model types.
    if "identity" in data and isinstance(data["identity"], dict):
        data["identity"] = AgentIdentity(**data["identity"])
    if "events" in data:
        data["events"] = [AuditEvent(**e) for e in data["events"]]
    if "receipts" in data:
        data["receipts"] = [AuthorizationReceipt(**r) for r in data["receipts"]]
    if "checkpoints" in data:
        data["checkpoints"] = [MerkleCheckpoint(**c) for c in data["checkpoints"]]
    if data.get("final_checkpoint") and isinstance(data["final_checkpoint"], dict):
        data["final_checkpoint"] = MerkleCheckpoint(**data["final_checkpoint"])
    return RunPackage(**data)


def verify_file(path: str | Path) -> VerificationReport:
    return verify_package(load_run_package(path))


__all__ = [
    "verify_package",
    "verify_file",
    "load_run_package",
    "render_report",
]
