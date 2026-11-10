"""
birkin.adapters.infini_gateway
==============================

Decoupled action gateway for portable workflow runtimes (such as INFINI).

Contract:
1. Workflow proposes an action: tool name + arguments.
2. Gateway queries Birkin policy engine and issues a signed AuthorizationReceipt.
3. If allowed, returns structured authorization granting permission to execute.
4. If denied or require_approval, returns fail-closed refusal.
5. Emits offline-verifiable Birkin evidence package upon workflow completion.
"""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field

from ..engine import Engine
from ..adapter import ActionRequest, BaseAdapter, ActionResult
from ..models import AgentIdentity, AuthorizationReceipt, RunPackage
from ..crypto import SigningKey
from ..policy import PolicySpec, load_default_policy


class GatewayDecision(BaseModel):
    """Structured decision returned to an orchestrator."""
    allowed: bool
    decision: str
    receipt_id: str
    tool: str
    rule: str
    risk_score: int
    reason: str
    receipt: AuthorizationReceipt


class InfiniActionGateway:
    """Independent gateway exposing Birkin authorization to external workflow engines."""

    def __init__(
        self,
        policy: Optional[PolicySpec] = None,
        signing_key: Optional[SigningKey] = None,
        adapter: Optional[BaseAdapter] = None,
    ) -> None:
        self.signing_key = signing_key or SigningKey.generate()
        self.policy = policy or load_default_policy()
        from .null_agent import NullAgentAdapter
        self.adapter = adapter or NullAgentAdapter()
        self.engine = Engine(
            birkin_signing_key=self.signing_key,
            policy=self.policy,
            adapter=self.adapter,
        )
        self.identity: Optional[AgentIdentity] = None

    def initialize_workflow(self, workflow_name: str, agent_id: str = "infini-agent") -> AgentIdentity:
        """Start a governance session for a named workflow."""
        ident = self.adapter.make_identity(
            agent_id=agent_id,
            policy_ref=self.policy.ref,
        )
        self.identity = ident
        self.engine.start_session(ident)
        intent = self.adapter.declare_intent(ident, f"Execute workflow: {workflow_name}")
        self.engine.declare_intent(ident, intent)
        return ident

    def evaluate_step(
        self,
        tool: str,
        args: dict[str, Any],
        justification: str = "",
    ) -> GatewayDecision:
        """Evaluate a proposed workflow step prior to execution."""
        if not self.identity:
            self.initialize_workflow("default-workflow")

        request = self.adapter.build_action_request(
            tool=tool,
            args=args,
            justification=justification,
        )
        receipt = self.engine.attempt_action(self.identity, request, justification=justification)

        return GatewayDecision(
            allowed=(receipt.decision == "allow"),
            decision=receipt.decision,
            receipt_id=receipt.receipt_id,
            tool=receipt.tool,
            rule=receipt.rule,
            risk_score=receipt.risk_score,
            reason=receipt.reason,
            receipt=receipt,
        )

    def complete_workflow(self) -> RunPackage:
        """Checkpoint, end session, and export offline-verifiable run package."""
        if not self.identity:
            raise RuntimeError("No active workflow session to complete")
        self.engine.checkpoint()
        self.engine.end_session(self.identity)
        return self.engine.export(identity=self.identity)
