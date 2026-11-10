"""
birkin.audit
=============

Append-only audit ledger with hash chaining and Merkle checkpoints.

The ledger is the spine of Birkin's evidence story. Every side-effecting
event is appended as an :class:`AuditEvent`. The verifier can later prove:

* no event was inserted or removed (dense 1..N sequence);
* no event was mutated (``event_hash`` recompute + signature);
* the chain is unbroken (``prev_hash`` linkage);
* the historical state is frozen at checkpoint time (signed Merkle root).

The implementation is intentionally small. It is *not* a database. The
in-memory representation is the source of truth within a run; once a
:class:`RunPackage` is exported, the verifier reads only the package.
"""

from __future__ import annotations

from typing import Any

from .crypto import SigningKey, merkle_root
from .models import AuditEvent, AuditEventType, MerkleCheckpoint


GENESIS_HASH = "0" * 64


class AuditLedger:
    """An append-only, hash-chained ledger of :class:`AuditEvent` records."""

    def __init__(self, birkin_signing_key: SigningKey) -> None:
        self._sk = birkin_signing_key
        self._events: list[AuditEvent] = []

    # --- append ----------------------------------------------------------
    def append(
        self,
        *,
        type: AuditEventType,
        actor: str,
        session_id: str,
        receipt_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditEvent:
        seq = len(self._events) + 1
        prev_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        ev = AuditEvent(
            sequence=seq,
            type=type,
            actor=actor,
            session_id=session_id,
            receipt_id=receipt_id,
            prev_hash=prev_hash,
            payload=payload or {},
        )
        ev.seal(self._sk)
        self._events.append(ev)
        return ev

    # --- inspection ------------------------------------------------------
    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    @property
    def last_hash(self) -> str:
        return self._events[-1].event_hash if self._events else GENESIS_HASH

    def __len__(self) -> int:
        return len(self._events)

    # --- checkpoint ------------------------------------------------------
    def checkpoint(
        self,
        *,
        anchors: list[dict[str, Any]] | None = None,
    ) -> MerkleCheckpoint:
        if not self._events:
            raise ValueError("cannot checkpoint an empty ledger")
        leaf_hashes = [ev.event_hash for ev in self._events]  # type: ignore[arg-type]
        cp = MerkleCheckpoint(
            sequence_range=(1, len(self._events)),
            leaf_count=len(self._events),
            root=merkle_root(leaf_hashes),
            anchors=anchors or [{"kind": "local"}],
        )
        cp.sign(self._sk)
        return cp


__all__ = ["AuditLedger", "GENESIS_HASH"]
