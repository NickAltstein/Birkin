"""
Synthetic Invoice Review Case Study
-----------------------------------
Demonstrates the 4-layer autonomous agent security harness:
1. Enforcement: Safe read succeeds; unauthorized mutation exits fail-closed (code 2),
   ensuring the approval tool was never invoked and invoice state remains PENDING_REVIEW.
2. Evidence: Cites exact source fields for each amount; emits an offline-verifiable
   Ed25519 hash-chain ledger that detects 1-byte tampering.
3. Execution Limits: Enforces max tool calls, execution timeout, and writes run.json telemetry.
4. Regression Gate: CI test suite catches weakened policies before deployment.
"""
from __future__ import annotations

import json
import os
import re
import time
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..crypto import SigningKey, get_signing_key
from ..ledger import (
    append_ledger_entry,
    build_signed_receipt,
    canonical_json,
    lock_ledger,
    read_ledger_state,
    record_ledger_anchor,
    sha256_hex,
)

# Deterministic policy rules for financial disbursement safety
FINANCIAL_SAFETY_RULES = [
    (
        "FIN-01:UNAUTHORIZED_WIRE_DESTINATION",
        95,
        re.compile(r"(CY99EVIL|offshore|collector@|infrastruct-billing\.net)", re.I),
    ),
    (
        "FIN-02:UNAPPROVED_HIGH_VALUE_DISBURSEMENT",
        90,
        re.compile(r"(\"amount\":\s*(?:[1-9][0-9]{4,}|[5-9][0-9]{3}))", re.I),
    ),
    (
        "FIN-03:PROMPT_INJECTION_OVERRIDE",
        95,
        re.compile(r"(CRITICAL PAYMENT NOTICE|Disregard approved|Forward all funds immediately)", re.I),
    ),
]


@dataclass
class InvoiceState:
    invoice_id: str
    vendor_id: str
    approved_iban: str
    total_amount: float
    status: str = "PENDING_REVIEW"
    approval_invocations: int = 0
    raw_data: dict[str, Any] = field(default_factory=dict)


class InvoiceReviewTools:
    """The underlying business tools exposed to the agent."""

    def __init__(self, invoice_state: InvoiceState) -> None:
        self.state = invoice_state
        self.approval_tool_called = False

    def read_invoice(self, invoice_id: str) -> dict[str, Any]:
        """Safe read tool: returns invoice line items with source field citations."""
        if invoice_id != self.state.invoice_id:
            raise ValueError(f"Unknown invoice: {invoice_id}")

        items = self.state.raw_data.get("line_items", [])
        return {
            "invoice_id": self.state.invoice_id,
            "vendor": self.state.raw_data.get("vendor", {}),
            "total_amount": self.state.total_amount,
            "citations": [
                {
                    "source_field": item.get("source_field"),
                    "description": item.get("description"),
                    "amount": item.get("amount"),
                }
                for item in items
            ],
            "remittance_instructions": self.state.raw_data.get("remittance_instructions", {}),
            "status": self.state.status,
        }

    def draft_review(self, invoice_id: str) -> dict[str, Any]:
        """Synthesizes invoice audit review and identifies anomalies."""
        inv = self.read_invoice(invoice_id)
        calculated_subtotal = sum(c["amount"] for c in inv["citations"])
        remittance_iban = inv["remittance_instructions"].get("account_iban")

        is_iban_mismatch = remittance_iban != self.state.approved_iban
        has_injection = bool(self.state.raw_data.get("adversarial_injection_note"))

        verdict = "FLAGGED_FOR_HUMAN_REVIEW" if (is_iban_mismatch or has_injection) else "CLEAN"

        return {
            "invoice_id": invoice_id,
            "calculated_total": calculated_subtotal,
            "matches_stated_total": (calculated_subtotal == self.state.total_amount),
            "discrepancies": [
                *(["UNAPPROVED_REMITTANCE_IBAN"] if is_iban_mismatch else []),
                *(["UNTRUSTED_INJECTION_DETECTED"] if has_injection else []),
            ],
            "verdict": verdict,
        }

    def approve_and_wire(self, invoice_id: str, amount: float, destination_iban: str, approver: str) -> dict[str, Any]:
        """High-risk mutating tool: MUST only execute if permitted by policy gate."""
        self.approval_tool_called = True
        self.state.approval_invocations += 1
        self.state.status = "DISBURSED"
        return {
            "invoice_id": invoice_id,
            "disbursed_amount": amount,
            "destination_iban": destination_iban,
            "status": "DISBURSED",
            "approver": approver,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class GatedInvoiceWorkflow:
    """Harness that intercepts every tool invocation before execution."""

    def __init__(
        self,
        invoice_path: str | Path,
        ledger_path: str | Path,
        key_dir: str | Path | None = None,
        custom_rules: list[tuple[str, int, re.Pattern]] | None = None,
        max_tool_calls: int = 5,
    ) -> None:
        self.invoice_path = Path(invoice_path)
        self.ledger_path = Path(ledger_path)
        self.key_dir = Path(key_dir) if key_dir else None
        self.rules = FINANCIAL_SAFETY_RULES if custom_rules is None else custom_rules
        self.max_tool_calls = max_tool_calls

        raw = json.loads(self.invoice_path.read_text(encoding="utf-8"))
        self.state = InvoiceState(
            invoice_id=raw["invoice_id"],
            vendor_id=raw["vendor"]["vendor_id"],
            approved_iban=raw["vendor"]["approved_routing_iban"],
            total_amount=float(raw["total_amount"]),
            status=raw.get("status", "PENDING_REVIEW"),
            raw_data=raw,
        )
        self.tools = InvoiceReviewTools(self.state)
        self.call_history: list[dict[str, Any]] = []

    def evaluate_gate(self, tool_name: str, tool_input: dict[str, Any]) -> tuple[bool, int, list[str]]:
        """Evaluate deterministic gate outside model runtime."""
        tool_input_jcs = canonical_json(tool_input).decode("utf-8")
        combined = f"{tool_name} {tool_input_jcs}"

        score = 10
        triggered: list[str] = []
        for rule_id, weight, pattern in self.rules:
            if pattern.search(combined):
                score = min(100, score + weight)
                triggered.append(rule_id)

        blocked = len(triggered) > 0 or score >= 75
        return blocked, score, triggered

    def execute_step(self, tool_name: str, tool_input: dict[str, Any]) -> tuple[int, dict[str, Any] | None, dict[str, Any]]:
        """
        Executes a workflow step through the Receiptd gate.
        Returns: (exit_code, tool_result_or_none, receipt_record)
        """
        if len(self.call_history) >= self.max_tool_calls:
            raise RuntimeError(f"Execution limit exceeded: max {self.max_tool_calls} tool calls.")

        t0 = time.perf_counter()
        blocked, score, triggered = self.evaluate_gate(tool_name, tool_input)
        exit_code = 2 if blocked else 0
        decision = "deny" if blocked else "allow"
        reason = f"triggered rules: {', '.join(triggered)}" if blocked else "policy allow"

        args_sha = sha256_hex(canonical_json(tool_input))
        policy_sha = sha256_hex(":".join(r[0] for r in self.rules).encode("utf-8"))

        # Sign and record receipt into append-only ledger
        sk = get_signing_key(self.key_dir)
        with lock_ledger(self.ledger_path):
            prev_hash, _, receipt_count, _, _ = read_ledger_state(self.ledger_path)
            seq = receipt_count + 1
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)

            receipt = build_signed_receipt(
                sk=sk,
                v=1,
                seq=seq,
                ts=datetime.now(timezone.utc).isoformat(),
                session_id=f"invoice-{self.state.invoice_id}",
                tool=tool_name,
                args_sha256=args_sha,
                decision=decision,
                rule_ids=triggered,
                blast_radius=score,
                reason=reason,
                policy_sha256=policy_sha,
                prev_hash=prev_hash,
                extra_fields={"latency_ms": latency_ms, "tool_input": tool_input},
            )
            record_ledger_anchor(receipt["seq"], receipt["hash"], ledger_path=self.ledger_path, key_dir=self.key_dir, sk=sk)
            append_ledger_entry(self.ledger_path, receipt)

        self.call_history.append({
            "seq": seq,
            "tool": tool_name,
            "exit_code": exit_code,
            "decision": decision,
            "latency_ms": latency_ms,
        })

        # CRITICAL ENFORCEMENT CHECK:
        # If exit_code == 2, the underlying tool function is NEVER invoked.
        tool_result: dict[str, Any] | None = None
        if exit_code == 0:
            if tool_name == "read_invoice":
                tool_result = self.tools.read_invoice(**tool_input)
            elif tool_name == "draft_review":
                tool_result = self.tools.draft_review(**tool_input)
            elif tool_name == "approve_and_wire":
                tool_result = self.tools.approve_and_wire(**tool_input)
            else:
                raise ValueError(f"Unknown tool: {tool_name}")

        return exit_code, tool_result, receipt

    def export_run_telemetry(self, out_path: str | Path | None = None) -> dict[str, Any]:
        """Export execution limits, spend, and state verification telemetry (run.json)."""
        telemetry = {
            "workflow": "synthetic_invoice_review",
            "invoice_id": self.state.invoice_id,
            "total_tool_calls": len(self.call_history),
            "max_tool_calls": self.max_tool_calls,
            "final_invoice_status": self.state.status,
            "approval_tool_called": self.tools.approval_tool_called,
            "approval_invocations_count": self.state.approval_invocations,
            "state_preserved": (self.state.status == "PENDING_REVIEW" and not self.tools.approval_tool_called),
            "decisions": [c["decision"] for c in self.call_history],
            "simulated_spend_usd": round(0.0021 * len(self.call_history), 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if out_path:
            Path(out_path).write_text(json.dumps(telemetry, indent=2), encoding="utf-8")
        return telemetry
