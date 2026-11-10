"""
birkin.models
=============

Concrete data models for the Birkin evidence layer.

Every object in here is a Pydantic v2 ``BaseModel`` so that:

* schemas are explicit and versioned (``schema`` field on every model);
* JSON round-trips are deterministic via ``model_dump_json``;
* the verifier can re-derive hashes from the *exact* bytes the signer used.

The models are deliberately small and orthogonal. There is no god-object.
Authorization lives in :class:`AuthorizationReceipt`. Event log lives in
:class:`AuditEvent`. Policy output lives in :class:`PolicyDecision`. The
agent lives in :class:`AgentIdentity`. The checkpoint lives in
:class:`MerkleCheckpoint`. The export artifact lives in :class:`RunPackage`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from .crypto import (
    SigningKey,
    canonical_json_subset,
    sha256_hex,
    verify_signature,
)


SCHEMA_VERSION = "birkin.run.package@1"

Decision = Literal["allow", "deny", "require_approval"]


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uuid() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# Agent Identity (Passport)
# --------------------------------------------------------------------------- #
class AgentIdentity(BaseModel):
    """A cryptographic passport carried by a single agent execution.

    An agent must present this passport before any side-effecting action is
    attempted. The passport is *self-signed* by the agent's own Ed25519 key
    over a canonical subset of its fields, which means:

    * anyone holding the passport can verify the agent actually possessed
      the matching private key;
    * the bound ``policy`` reference cannot be swapped out after the fact;
    * the ``runtime`` string is part of the signed material, so an Hermes
      passport cannot be replayed as if it came from another runtime.
    """

    schema_version: str = Field(default="birkin.identity@1")
    agent_id: str
    public_key: str                      # base64 Ed25519 public key
    runtime: str                         # e.g. "hermes-0.1"
    policy: str                          # e.g. "default@1.0.0"
    session_id: str
    issued_at: str = Field(default_factory=_utcnow)
    expires_at: str
    signature: Optional[str] = None      # set by .sign()

    SIGN_FIELDS: ClassVar[Tuple[str, ...]] = (
        "schema_version",
        "agent_id",
        "public_key",
        "runtime",
        "policy",
        "session_id",
        "issued_at",
        "expires_at",
    )

    def sign(self, sk: SigningKey) -> "AgentIdentity":
        if self.public_key and self.public_key != sk.public_b64:
            raise ValueError(
                "AgentIdentity.public_key does not match the signing key"
            )
        if not self.public_key:
            self.public_key = sk.public_b64
        msg = canonical_json_subset(self.model_dump(), self.SIGN_FIELDS)
        self.signature = sk.sign(msg)
        return self

    def verify(self) -> bool:
        if not self.signature:
            return False
        msg = canonical_json_subset(self.model_dump(), self.SIGN_FIELDS)
        return verify_signature(self.public_key, self.signature, msg)


# --------------------------------------------------------------------------- #
# Policy Decision
# --------------------------------------------------------------------------- #
class PolicyDecision(BaseModel):
    """The structured output of the :class:`PolicyEngine`.

    Every tool invocation that Birkin governs yields exactly one of these.
    Downstream code MUST branch on ``decision``; the ``risk_score`` and
    ``reason`` are recorded in the audit ledger as evidence of *why*.
    """

    schema_version: str = Field(default="birkin.policy.decision@1")
    decision: Decision
    policy: str                          # "name@version"
    rule: str                            # rule id
    risk_score: int = Field(ge=0, le=100)
    reason: str


# --------------------------------------------------------------------------- #
# Authorization Receipt
# --------------------------------------------------------------------------- #
class AuthorizationReceipt(BaseModel):
    """A signed record that Birkin authorized (or denied) an action.

    The receipt is the new primitive. Every side-effecting action — or
    refusal of one — produces exactly one receipt, signed by the Birkin
    control plane's signing key. A receipt is *portable*: it can be
    presented to a downstream system, to a human reviewer, or to an
    offline verifier, and it stands on its own as cryptographic evidence.

    Cryptographic binding (every field below is part of the signed
    material — flipping any one invalidates the signature):

    * ``agent_id`` + ``agent_public_key``  — *which* agent (by both the
      stable identifier AND the specific keypair that the agent proved
      possession of when its passport was minted);
    * ``session_id``                       — *which* execution of that agent;
    * ``intent_hash``                      — *what* the agent publicly said
      it was going to do, before any action (bound at policy-eval time);
    * ``action`` + ``tool``                — *which* capability was attempted;
    * ``args_hash``                        — *what* arguments were passed
      (SHA-256 over canonical JSON of the args dict);
    * ``decision`` + ``policy`` + ``rule`` — *what* the policy engine
      decided, under *which* policy version, by *which* rule;
    * ``risk_score`` + ``reason``          — the structured risk output;
    * ``prior_event_hash``                 — *where* in the audit chain this
      receipt was issued (binds the receipt to its position, preventing
      lift-and-replay into a different run).
    """

    schema_version: str = Field(default="birkin.receipt@1")
    receipt_id: str = Field(default_factory=_uuid)
    agent_id: str
    agent_public_key: str                # base64 Ed25519 — binds to identity
    session_id: str
    intent_hash: Optional[str] = None    # sha256 of declared intent text (if any)
    action: str                          # e.g. "tool.invoke"
    tool: str                            # e.g. "shell.exec"
    args_hash: str                       # sha256 hex of canonical args
    decision: Decision
    policy: str                          # "name@version"
    rule: str                            # rule id that fired
    risk_score: int = Field(ge=0, le=100)
    reason: str
    prior_event_hash: str                # ledger.last_hash at issue time
    issued_at: str = Field(default_factory=_utcnow)
    signature: Optional[str] = None      # set by .sign(), signed by Birkin SK

    SIGN_FIELDS: ClassVar[Tuple[str, ...]] = (
        "schema_version",
        "receipt_id",
        "agent_id",
        "agent_public_key",
        "session_id",
        "intent_hash",
        "action",
        "tool",
        "args_hash",
        "decision",
        "policy",
        "rule",
        "risk_score",
        "reason",
        "prior_event_hash",
        "issued_at",
    )

    def sign(self, sk: SigningKey) -> "AuthorizationReceipt":
        msg = canonical_json_subset(self.model_dump(), self.SIGN_FIELDS)
        self.signature = sk.sign(msg)
        return self

    def verify(self, birkin_public_b64: str) -> bool:
        if not self.signature:
            return False
        msg = canonical_json_subset(self.model_dump(), self.SIGN_FIELDS)
        return verify_signature(birkin_public_b64, self.signature, msg)


# --------------------------------------------------------------------------- #
# Audit Event
# --------------------------------------------------------------------------- #
AuditEventType = Literal[
    "session.start",
    "intent.declared",
    "policy.decision",
    "tool.attempt",
    "tool.allow",
    "tool.deny",
    "tool.require_approval",
    "tool.executed",
    "receipt.issued",
    "checkpoint",
    "session.end",
    "alert",
]


class AuditEvent(BaseModel):
    """A single, signed, hash-chained record in the Birkin audit ledger.

    Every event carries:

    * ``sequence`` — 1-indexed, dense, no gaps allowed by the verifier;
    * ``prev_hash`` — sha256 of the previous event's ``event_hash``;
    * ``event_hash`` — sha256 over canonical subset of *this* event's fields
      (excluding ``signature`` and ``event_hash`` itself);
    * ``signature`` — Ed25519 signature by the Birkin control plane over
      ``event_hash``.

    The chain is built so that modifying any historical event invalidates
    every subsequent ``prev_hash`` and the Merkle checkpoint root.
    """

    schema_version: str = Field(default="birkin.audit@1")
    event_id: str = Field(default_factory=_uuid)
    sequence: int
    timestamp: str = Field(default_factory=_utcnow)
    type: AuditEventType
    actor: str                          # agent_id
    session_id: str
    receipt_id: Optional[str] = None
    prev_hash: str = "0" * 64           # genesis = 64 zeros
    payload: dict[str, Any] = Field(default_factory=dict)
    event_hash: Optional[str] = None    # set by .seal()
    signature: Optional[str] = None     # set by .seal()

    HASH_FIELDS: ClassVar[Tuple[str, ...]] = (
        "schema_version",
        "event_id",
        "sequence",
        "timestamp",
        "type",
        "actor",
        "session_id",
        "receipt_id",
        "prev_hash",
        "payload",
    )

    SIGN_FIELDS: ClassVar[Tuple[str, ...]] = ("event_hash",)

    def compute_hash(self) -> str:
        msg = canonical_json_subset(self.model_dump(), self.HASH_FIELDS)
        return sha256_hex(msg)

    def seal(self, sk: SigningKey) -> "AuditEvent":
        self.event_hash = self.compute_hash()
        self.signature = sk.sign(self.event_hash.encode("ascii"))
        return self

    def verify_signature(self, birkin_public_b64: str) -> bool:
        if not self.signature or not self.event_hash:
            return False
        return verify_signature(
            birkin_public_b64, self.signature, self.event_hash.encode("ascii")
        )

    def verify_hash(self) -> bool:
        if not self.event_hash:
            return False
        return self.event_hash == self.compute_hash()


# --------------------------------------------------------------------------- #
# Merkle Checkpoint
# --------------------------------------------------------------------------- #
class MerkleCheckpoint(BaseModel):
    """A signed Merkle root over a contiguous range of audit events.

    Anchors are deliberately minimal for this slice (``kind=local``). The
    seam is here so that future cycles can add anchoring to a public
    transparency log, a TCP/timestamping authority, or an on-chain anchor
    without breaking the verifier.
    """

    schema_version: str = Field(default="birkin.checkpoint@1")
    checkpoint_id: str = Field(default_factory=_uuid)
    sequence_range: tuple[int, int]
    leaf_count: int
    root: str                            # hex
    anchors: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(default_factory=_utcnow)
    signature: Optional[str] = None      # signed by Birkin SK over root

    SIGN_FIELDS: ClassVar[Tuple[str, ...]] = (
        "schema_version",
        "checkpoint_id",
        "sequence_range",
        "leaf_count",
        "root",
        "anchors",
        "timestamp",
    )

    def sign(self, sk: SigningKey) -> "MerkleCheckpoint":
        msg = canonical_json_subset(self.model_dump(), self.SIGN_FIELDS)
        self.signature = sk.sign(msg)
        return self

    def verify(self, birkin_public_b64: str) -> bool:
        if not self.signature:
            return False
        msg = canonical_json_subset(self.model_dump(), self.SIGN_FIELDS)
        return verify_signature(birkin_public_b64, self.signature, msg)


# --------------------------------------------------------------------------- #
# Run Package (exportable, offline-verifiable)
# --------------------------------------------------------------------------- #
# Manifest of every versioned schema embedded in a RunPackage. The verifier
# reads this first and refuses to verify packages whose schema versions it
# does not understand — so future format changes break loudly, not silently.
PACKAGE_MANIFEST = {
    "evidence_format": SCHEMA_VERSION,                # birkin.run.package@1
    "identity_scheme":  "birkin.identity@1",
    "receipt_scheme":   "birkin.receipt@1",
    "audit_event_scheme": "birkin.audit@1",
    "checkpoint_scheme": "birkin.checkpoint@1",
    "policy_decision_scheme": "birkin.policy.decision@1",
    "verifier_min_version": "0.1.0",                  # birkin CLI must be >= this
}


class RunPackage(BaseModel):
    """The export artifact: a self-contained, offline-verifiable record
    of one agent run under Birkin governance.

    A reviewer with ``birkin verify`` and this file needs nothing else —
    not the Birkin server, not the policy file, not the agent's runtime.
    Everything required to recompute the verdict is embedded here.

    The ``manifest`` field is the *first* thing the verifier reads. It
    declares the schema versions of every embedded object. If a future
    Birkin version emits a different schema, the verifier refuses to
    verify rather than silently misinterpreting the bytes.
    """

    model_config = ConfigDict(populate_by_name=True)

    schema_: str = Field(default=SCHEMA_VERSION, alias="schema")
    manifest: dict[str, str] = Field(default_factory=lambda: dict(PACKAGE_MANIFEST))
    run_id: str
    exported_at: str = Field(default_factory=_utcnow)
    birkin_public_key: str               # base64 Ed25519 — verifies events, receipts, checkpoints
    birkin_version: str = "0.1.0"        # version of the engine that produced this package
    identity: AgentIdentity
    policy: dict[str, Any]              # {"name", "version", "sha256", "spec": {...}}
    intent: Optional[dict[str, Any]] = None
    events: list[AuditEvent] = []
    receipts: list[AuthorizationReceipt] = []
    checkpoints: list[MerkleCheckpoint] = []
    final_checkpoint: Optional[MerkleCheckpoint] = None
    notes: Optional[str] = None


# --------------------------------------------------------------------------- #
# Verifier output (machine + human readable)
# --------------------------------------------------------------------------- #
class CheckResult(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class VerificationReport(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_: str = Field(default="birkin.verify.report@1", alias="schema")
    run_id: str
    checks: list[CheckResult]
    verdict: Literal["AUTHENTIC", "TAMPERED", "INVALID"]


def make_passport(
    *,
    agent_id: str,
    runtime: str,
    policy: str,
    session_id: Optional[str] = None,
    ttl_seconds: int = 3600,
    agent_signing_key: SigningKey,
) -> AgentIdentity:
    """Construct and sign a fresh :class:`AgentIdentity`."""
    now = datetime.now(timezone.utc)
    return AgentIdentity(
        agent_id=agent_id,
        public_key=agent_signing_key.public_b64,
        runtime=runtime,
        policy=policy,
        session_id=session_id or _uuid(),
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        expires_at=(now + timedelta(seconds=ttl_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    ).sign(agent_signing_key)


__all__ = [
    "SCHEMA_VERSION",
    "Decision",
    "AgentIdentity",
    "PolicyDecision",
    "AuthorizationReceipt",
    "AuditEvent",
    "AuditEventType",
    "MerkleCheckpoint",
    "RunPackage",
    "CheckResult",
    "VerificationReport",
    "make_passport",
]
