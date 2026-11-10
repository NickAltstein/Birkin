"""
birkin.engine
=============

The Birkin control plane.

The engine is the only object an integrator needs to talk to. It owns:

* the Birkin control-plane signing key (verifies events, receipts, checkpoints);
* a loaded :class:`PolicySpec`;
* an :class:`AuditLedger`;
* the active :class:`AgentAdapter`.

End-to-end flow for a single action::

    engine.start_session(...)
    engine.declare_intent(...)
    receipt = engine.attempt_action(identity, request)
    # receipt.decision in {"allow","deny","require_approval"}
    if receipt.decision == "allow":
        result = engine.execute(identity, request, receipt)
    # ... or for require_approval:
    #   approved = engine.approve(receipt)
    #   if approved: engine.execute(...)
    package = engine.export(...)
    birkin verify package  -> AUTHENTIC

Every step above — except the human approval gate — is signed and recorded.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .adapter import AgentAdapter, ActionRequest, Intent
from .audit import AuditLedger
from .crypto import SigningKey, canonical_json, sha256_hex
from .models import (
    AgentIdentity,
    AuthorizationReceipt,
    AuditEvent,
    MerkleCheckpoint,
    PolicyDecision,
    RunPackage,
)
from .policy import PolicySpec


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
@dataclass
class Engine:
    """The Birkin control plane for one process."""

    birkin_signing_key: SigningKey
    policy: PolicySpec
    adapter: AgentAdapter
    ledger: AuditLedger = field(init=False)
    _receipts: list[AuthorizationReceipt] = field(default_factory=list, init=False)
    _intent: Optional[Intent] = None
    _checkpoints: list[MerkleCheckpoint] = field(default_factory=list, init=False)
    _run_id: str = field(default_factory=lambda: str(uuid.uuid4()), init=False)
    _resolved_receipt_ids: set[str] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        self.ledger = AuditLedger(self.birkin_signing_key)

    # --- accessors ------------------------------------------------------
    @property
    def birkin_public_b64(self) -> str:
        return self.birkin_signing_key.public_b64

    @property
    def policy_ref(self) -> str:
        return self.policy.ref

    @property
    def policy_sha256(self) -> str:
        return self.policy.sha256

    @property
    def run_id(self) -> str:
        return self._run_id

    # --- lifecycle ------------------------------------------------------
    def start_session(self, identity: AgentIdentity) -> AuditEvent:
        return self.ledger.append(
            type="session.start",
            actor=identity.agent_id,
            session_id=identity.session_id,
            payload={
                "runtime": identity.runtime,
                "policy": identity.policy,
                "public_key": identity.public_key,
                "issued_at": identity.issued_at,
                "expires_at": identity.expires_at,
            },
        )

    def declare_intent(
        self, identity: AgentIdentity, intent: Intent
    ) -> AuditEvent:
        self._intent = intent
        return self.ledger.append(
            type="intent.declared",
            actor=identity.agent_id,
            session_id=identity.session_id,
            payload={
                "text": intent.text,
                "declared_at": intent.declared_at,
                "extras": intent.extras,
            },
        )

    # --- policy + receipt ----------------------------------------------
    def evaluate(
        self, identity: AgentIdentity, request: ActionRequest
    ) -> PolicyDecision:
        return self.policy.evaluate(
            tool=request.tool,
            args=request.args,
            runtime=identity.runtime,
            identity_public_key=identity.public_key,
        )

    def _args_hash(self, request: ActionRequest) -> str:
        return sha256_hex(canonical_json(request.args))

    def _intent_hash(self) -> Optional[str]:
        """SHA-256 over the declared intent's text + extras.

        Bound into every receipt issued after the intent was declared, so
        a receipt cannot be lifted out and replayed against a different
        claimed intent.
        """
        if not self._intent:
            return None
        return sha256_hex(
            canonical_json(
                {"text": self._intent.text, "extras": self._intent.extras}
            )
        )

    def attempt_action(
        self,
        identity: AgentIdentity,
        request: ActionRequest,
        *,
        justification: str = "",
    ) -> AuthorizationReceipt:
        """Run the policy engine and emit a signed :class:`AuthorizationReceipt`.

        Always returns a receipt — even on deny / require_approval. The
        receipt is the artifact; the engine records an audit event for
        each receipt, and never executes the side-effect itself.

        The receipt is cryptographically bound to:

        * the agent identity (``agent_id`` + ``agent_public_key``);
        * the session (``session_id``);
        * the declared intent (``intent_hash``, if any);
        * the action (``action`` + ``tool``);
        * the arguments (``args_hash``);
        * the policy decision (``decision`` + ``policy`` + ``rule``);
        * the audit chain position (``prior_event_hash``).
        """
        decision = self.evaluate(identity, request)
        args_hash = self._args_hash(request)

        receipt = AuthorizationReceipt(
            agent_id=identity.agent_id,
            agent_public_key=identity.public_key,
            session_id=identity.session_id,
            intent_hash=self._intent_hash(),
            action="tool.invoke",
            tool=request.tool,
            args_hash=args_hash,
            decision=decision.decision,
            policy=decision.policy,
            rule=decision.rule,
            risk_score=decision.risk_score,
            reason=decision.reason,
            prior_event_hash=self.ledger.last_hash,
        )
        receipt.sign(self.birkin_signing_key)
        self._receipts.append(receipt)

        # Audit: policy decision + attempt + (allow/deny/require_approval)
        self.ledger.append(
            type="policy.decision",
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={
                "decision": decision.decision,
                "rule": decision.rule,
                "risk_score": decision.risk_score,
                "reason": decision.reason,
            },
        )
        self.ledger.append(
            type="tool.attempt",
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={
                "tool": request.tool,
                "args_hash": args_hash,
                "justification": justification or request.justification,
            },
        )
        event_type = {
            "allow": "tool.allow",
            "deny": "tool.deny",
            "require_approval": "tool.require_approval",
        }[decision.decision]
        self.ledger.append(
            type=event_type,
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={"rule": decision.rule, "risk_score": decision.risk_score},
        )
        self.ledger.append(
            type="receipt.issued",
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={
                "decision": receipt.decision,
                "tool": receipt.tool,
                "args_hash": receipt.args_hash,
            },
        )
        return receipt

    # --- approval gate (for require_approval) ---------------------------
    def approve(
        self,
        identity: AgentIdentity,
        receipt: AuthorizationReceipt,
        *,
        approved_by: str,
        reason: str,
    ) -> AuthorizationReceipt:
        """Convert a ``require_approval`` receipt into an ``allow`` receipt.

        The approval itself is recorded as a signed audit event. The new
        receipt replaces the prior one in the run package; the prior
        decision is preserved in the audit trail.
        """
        if receipt.decision != "require_approval":
            raise ValueError(
                f"cannot approve receipt with decision={receipt.decision}"
            )
        if receipt.receipt_id in self._resolved_receipt_ids:
            raise ValueError(
                f"cannot approve receipt {receipt.receipt_id}: already resolved"
            )
        if receipt.agent_id != identity.agent_id or receipt.session_id != identity.session_id:
            raise ValueError(
                f"identity mismatch: receipt {receipt.receipt_id} belongs to agent {receipt.agent_id} "
                f"(session {receipt.session_id}), not {identity.agent_id} (session {identity.session_id})"
            )
        if not receipt.verify(self.birkin_signing_key.public_b64):
            raise ValueError(
                f"cannot approve receipt {receipt.receipt_id}: invalid or unverified cryptographic signature"
            )

        self._resolved_receipt_ids.add(receipt.receipt_id)
        self.ledger.append(
            type="alert",
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={
                "event": "approval.granted",
                "approved_by": approved_by,
                "reason": reason,
            },
        )
        # Issue a new receipt with decision=allow, inheriting everything else.
        new_receipt = AuthorizationReceipt(
            agent_id=receipt.agent_id,
            agent_public_key=receipt.agent_public_key,
            session_id=receipt.session_id,
            intent_hash=receipt.intent_hash,
            action=receipt.action,
            tool=receipt.tool,
            args_hash=receipt.args_hash,
            decision="allow",
            policy=receipt.policy,
            rule=receipt.rule,
            risk_score=max(receipt.risk_score - 10, 0),
            reason=f"approved by {approved_by}: {reason}",
            prior_event_hash=self.ledger.last_hash,
        )
        new_receipt.sign(self.birkin_signing_key)
        self._receipts.append(new_receipt)
        return new_receipt

    def reject(
        self,
        identity: AgentIdentity,
        receipt: AuthorizationReceipt,
        *,
        rejected_by: str,
        reason: str,
    ) -> AuthorizationReceipt:
        """Convert a ``require_approval`` receipt into an explicit ``deny`` receipt.

        The rejection is recorded as an audit alert event, and a new signed
        AuthorizationReceipt with decision='deny' is issued.
        """
        if receipt.decision != "require_approval":
            raise ValueError(
                f"cannot reject receipt with decision={receipt.decision}"
            )
        if receipt.receipt_id in self._resolved_receipt_ids:
            raise ValueError(
                f"cannot reject receipt {receipt.receipt_id}: already resolved"
            )
        if receipt.agent_id != identity.agent_id or receipt.session_id != identity.session_id:
            raise ValueError(
                f"identity mismatch: receipt {receipt.receipt_id} belongs to agent {receipt.agent_id} "
                f"(session {receipt.session_id}), not {identity.agent_id} (session {identity.session_id})"
            )
        if not receipt.verify(self.birkin_signing_key.public_b64):
            raise ValueError(
                f"cannot reject receipt {receipt.receipt_id}: invalid or unverified cryptographic signature"
            )

        self._resolved_receipt_ids.add(receipt.receipt_id)
        self.ledger.append(
            type="alert",
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={
                "event": "approval.denied",
                "rejected_by": rejected_by,
                "reason": reason,
            },
        )
        new_receipt = AuthorizationReceipt(
            agent_id=receipt.agent_id,
            agent_public_key=receipt.agent_public_key,
            session_id=receipt.session_id,
            intent_hash=receipt.intent_hash,
            action=receipt.action,
            tool=receipt.tool,
            args_hash=receipt.args_hash,
            decision="deny",
            policy=receipt.policy,
            rule=receipt.rule,
            risk_score=receipt.risk_score,
            reason=f"denied by {rejected_by}: {reason}",
            prior_event_hash=self.ledger.last_hash,
        )
        new_receipt.sign(self.birkin_signing_key)
        self._receipts.append(new_receipt)
        return new_receipt

    # --- execution ------------------------------------------------------
    def execute(
        self,
        identity: AgentIdentity,
        request: ActionRequest,
        receipt: AuthorizationReceipt,
    ) -> tuple[Any, AuditEvent]:
        """Execute via the adapter iff the receipt permits it."""
        if receipt.decision != "allow":
            ev = self.ledger.append(
                type="alert",
                actor=identity.agent_id,
                session_id=identity.session_id,
                receipt_id=receipt.receipt_id,
                payload={
                    "alert": "execution.refused",
                    "reason": f"receipt.decision={receipt.decision}",
                },
            )
            return None, ev

        if receipt.agent_id != identity.agent_id or receipt.session_id != identity.session_id:
            ev = self.ledger.append(
                type="alert",
                actor=identity.agent_id,
                session_id=identity.session_id,
                receipt_id=receipt.receipt_id,
                payload={
                    "alert": "execution.refused",
                    "reason": "identity_mismatch",
                },
            )
            return None, ev

        if not receipt.verify(self.birkin_signing_key.public_b64):
            ev = self.ledger.append(
                type="alert",
                actor=identity.agent_id,
                session_id=identity.session_id,
                receipt_id=receipt.receipt_id,
                payload={
                    "alert": "execution.refused",
                    "reason": "invalid_receipt_signature",
                },
            )
            return None, ev

        if self._args_hash(request) != receipt.args_hash:
            ev = self.ledger.append(
                type="alert",
                actor=identity.agent_id,
                session_id=identity.session_id,
                receipt_id=receipt.receipt_id,
                payload={
                    "alert": "execution.refused",
                    "reason": "args_hash_mismatch",
                },
            )
            return None, ev

        result = self.adapter.execute(identity, request, receipt)
        ev = self.ledger.append(
            type="tool.executed",
            actor=identity.agent_id,
            session_id=identity.session_id,
            receipt_id=receipt.receipt_id,
            payload={
                "ok": result.ok,
                "output": str(result.output)[:500] if result.output is not None else None,
                "error": result.error,
                "side_effect_recorded": result.side_effect_recorded,
            },
        )
        return result, ev

    # --- checkpoint + export -------------------------------------------
    def checkpoint(
        self, *, anchors: list[dict] | None = None
    ) -> MerkleCheckpoint:
        cp = self.ledger.checkpoint(anchors=anchors)
        self._checkpoints.append(cp)
        # Audit the checkpoint itself.
        self.ledger.append(
            type="checkpoint",
            actor="birkin",
            session_id=(self.ledger.events[0].session_id if self.ledger.events else ""),
            payload={
                "checkpoint_id": cp.checkpoint_id,
                "root": cp.root,
                "sequence_range": list(cp.sequence_range),
                "leaf_count": cp.leaf_count,
            },
        )
        return cp

    def end_session(self, identity: AgentIdentity) -> AuditEvent:
        return self.ledger.append(
            type="session.end",
            actor=identity.agent_id,
            session_id=identity.session_id,
            payload={"event_count": len(self.ledger)},
        )

    def export(
        self,
        *,
        identity: AgentIdentity,
        notes: Optional[str] = None,
    ) -> RunPackage:
        if not self._checkpoints:
            self.checkpoint()
        final_cp = self._checkpoints[-1]
        return RunPackage(
            run_id=self._run_id,
            birkin_public_key=self.birkin_public_b64,
            identity=identity,
            policy={
                "name": self.policy.name,
                "version": self.policy.version,
                "sha256": self.policy.sha256,
                "spec": self.policy.to_dict(),
            },
            intent={
                "text": self._intent.text if self._intent else None,
                "declared_at": self._intent.declared_at if self._intent else None,
                "extras": self._intent.extras if self._intent else {},
            },
            events=self.ledger.events,
            receipts=list(self._receipts),
            checkpoints=list(self._checkpoints),
            final_checkpoint=final_cp,
            notes=notes,
        )

    # --- serialization helpers -----------------------------------------
    def export_json(self, *, identity: AgentIdentity, indent: int = 2) -> str:
        return self.export(identity=identity).model_dump_json(indent=indent)

    def export_to_file(
        self, path: str, *, identity: AgentIdentity, notes: Optional[str] = None
    ) -> str:
        pkg = self.export(identity=identity, notes=notes)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(pkg.model_dump_json(indent=2))
        return path


__all__ = ["Engine"]
