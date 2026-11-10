"""
birkin.adapters.null_agent
==========================

NullAgent — a deliberately minimal second :class:`AgentAdapter`.

It exists for exactly one reason: to prove the architecture. If a second,
trivially-simple adapter that knows *nothing* about Hermes can sit under
the same Birkin control plane, produce the same kind of signed receipts,
emit the same kind of signed audit events, and verify AUTHENTIC with the
same offline verifier — then ``AgentAdapter`` is a real seam, not a
one-customer interface dressed up as a protocol.

What NullAgent does
-------------------
* ``make_identity``  — inherited from :class:`BaseAdapter`.
* ``declare_intent`` — inherited.
* ``build_action_request`` — inherited.
* ``execute``         — has exactly one tool, ``null.ping``, which always
  succeeds and has no side effect. The policy engine still has to
  authorize it; the receipt is still signed; the audit event is still
  recorded; the checkpoint still covers it; the verifier still says
  AUTHENTIC.

What this proves
-----------------
The Birkin evidence plane does not depend on Hermes. Hermes is the first
adapter; NullAgent is the second; the next can be an MCP stub, a custom
runtime, or a managed agent service — the contract is the same.
"""

from __future__ import annotations

from typing import Any

from ..adapter import ActionResult, BaseAdapter
from ..models import AuthorizationReceipt


def _null_ping(args: dict[str, Any]) -> tuple[bool, Any]:
    # Always succeeds. No side effect. The point is the *receipt*, not the tool.
    return True, {"echo": args}


class NullAgentAdapter(BaseAdapter):
    """A deliberately trivial second adapter."""

    name: str = "null"
    version: str = "0.1.0"

    def __init__(self, agent_signing_key=None) -> None:
        super().__init__(agent_signing_key=agent_signing_key)
        self._tools = {"null.ping": _null_ping}

    def known_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def execute(self, identity, request, receipt: AuthorizationReceipt) -> ActionResult:
        if receipt.decision != "allow":
            return ActionResult(
                ok=False,
                error=f"refused by receipt {receipt.receipt_id}: decision={receipt.decision}",
                side_effect_recorded=False,
            )
        handler = self._tools.get(request.tool)
        if handler is None:
            return ActionResult(
                ok=False,
                error=f"unknown tool: {request.tool}",
                side_effect_recorded=False,
            )
        ok, out = handler(request.args)
        return ActionResult(
            ok=ok,
            output=out,
            error="" if ok else str(out),
            side_effect_recorded=False,  # null.ping has no side effect by design
        )


__all__ = ["NullAgentAdapter"]
