"""
birkin.adapter
==============

The ``AgentAdapter`` interface.

Birkin is runtime-agnostic. An adapter is the seam through which a
particular agent runtime (Hermes, an MCP server, a custom bot, …) is
brought under Birkin governance. The adapter is responsible for:

* constructing an :class:`AgentIdentity` (passport) for the run;
* declaring the agent's intent before any side-effect;
* producing an :class:`ActionRequest` that the Birkin engine can hand to
  the policy engine;
* executing the action *only* after a signed receipt with
  ``decision == "allow"`` has been issued.

Hermes is shipped as the first adapter. Adding a new runtime is a matter of
implementing this protocol; the rest of Birkin does not change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .crypto import SigningKey
from .models import AgentIdentity, make_passport


@dataclass
class Intent:
    text: str
    declared_at: str
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionRequest:
    """A request from an agent to attempt a side-effecting action."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    justification: str = ""


@dataclass
class ActionResult:
    ok: bool
    output: Any = None
    error: str = ""
    side_effect_recorded: bool = False


@runtime_checkable
class AgentAdapter(Protocol):
    """Stable interface that every runtime adapter must implement."""

    name: str
    version: str

    # --- lifecycle ------------------------------------------------------
    def make_identity(
        self,
        *,
        agent_id: str,
        policy_ref: str,
        session_id: str | None = None,
        ttl_seconds: int = 3600,
    ) -> AgentIdentity:
        """Mint a fresh signed passport for this run."""
        ...

    def declare_intent(
        self, identity: AgentIdentity, text: str, extras: dict | None = None
    ) -> Intent:
        """Record the agent's declared intent *before* any action."""
        ...

    def build_action_request(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        justification: str = "",
    ) -> ActionRequest:
        """Construct an :class:`ActionRequest` to be evaluated by Birkin."""
        ...

    def execute(
        self,
        identity: AgentIdentity,
        request: ActionRequest,
        receipt,  # AuthorizationReceipt — avoiding import for runtime_checkable
    ) -> ActionResult:
        """Execute the action iff the receipt permits it."""
        ...


# --------------------------------------------------------------------------- #
# A tiny base class providing identity minting shared by all adapters.
# --------------------------------------------------------------------------- #
class BaseAdapter:
    """Common scaffolding for concrete adapters."""

    name: str = "base"
    version: str = "0.0.0"

    def __init__(self, agent_signing_key: SigningKey | None = None) -> None:
        self._agent_sk = agent_signing_key or SigningKey.generate()

    @property
    def agent_public_b64(self) -> str:
        return self._agent_sk.public_b64

    def make_identity(
        self,
        *,
        agent_id: str,
        policy_ref: str,
        session_id: str | None = None,
        ttl_seconds: int = 3600,
    ) -> AgentIdentity:
        return make_passport(
            agent_id=agent_id,
            runtime=f"{self.name}-{self.version}",
            policy=policy_ref,
            session_id=session_id,
            ttl_seconds=ttl_seconds,
            agent_signing_key=self._agent_sk,
        )

    def declare_intent(
        self, identity: AgentIdentity, text: str, extras: dict | None = None
    ) -> Intent:
        from datetime import datetime, timezone

        return Intent(
            text=text,
            declared_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            extras=extras or {},
        )

    def build_action_request(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        justification: str = "",
    ) -> ActionRequest:
        return ActionRequest(tool=tool, args=args or {}, justification=justification)

    # Concrete adapters override this.
    def execute(self, identity, request, receipt) -> ActionResult:  # pragma: no cover
        raise NotImplementedError


__all__ = [
    "AgentAdapter",
    "BaseAdapter",
    "Intent",
    "ActionRequest",
    "ActionResult",
]
