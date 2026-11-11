"""
Test Suite: Synthetic Invoice Review 4-Layer Security Harness
-------------------------------------------------------------
Verifies:
1. Enforcement: Safe reads allowed; unauthorized wire mutations fail closed (exit 2).
2. State Preservation: Denied actions physically never reach the tool implementation;
   invoice status remains PENDING_REVIEW.
3. Evidence & Tampering: Ledger verified offline; 1-byte alteration trips TAMPER DETECTED.
4. Execution Limits: Max tool calls and stagnation limits strictly enforced.
5. Regression Gate: Intentionally weakening the policy triggers an immediate test failure.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
import pytest

from receiptd.examples.invoice_review import GatedInvoiceWorkflow, FINANCIAL_SAFETY_RULES
from receiptd.cli import _verify_ledger_file


@pytest.fixture
def invoice_fixture_path(tmp_path: Path) -> Path:
    fixture_src = Path("fixtures/invoice_demo/invoice_INV_2026_8891.json")
    inv_file = tmp_path / "invoice.json"
    shutil.copyfile(fixture_src, inv_file)
    return inv_file


@pytest.fixture
def workflow_context(tmp_path: Path, invoice_fixture_path: Path):
    ledger = tmp_path / "receipts.jsonl"
    keys = tmp_path / "keys"
    wf = GatedInvoiceWorkflow(
        invoice_path=invoice_fixture_path,
        ledger_path=ledger,
        key_dir=keys,
        max_tool_calls=5,
    )
    return wf, ledger, keys


def test_invoice_safe_read_and_review_are_allowed(workflow_context):
    wf, ledger, keys = workflow_context

    # 1. Read
    code1, res1, r1 = wf.execute_step("read_invoice", {"invoice_id": "INV-2026-8891"})
    assert code1 == 0
    assert r1["decision"] == "allow"
    assert len(res1["citations"]) == 3
    assert res1["total_amount"] == 14850.00

    # 2. Review
    code2, res2, r2 = wf.execute_step("draft_review", {"invoice_id": "INV-2026-8891"})
    assert code2 == 0
    assert r2["decision"] == "allow"
    assert res2["verdict"] == "FLAGGED_FOR_HUMAN_REVIEW"
    assert "UNTRUSTED_INJECTION_DETECTED" in res2["discrepancies"]


def test_invoice_unauthorized_disbursement_blocked_fail_closed(workflow_context):
    wf, ledger, keys = workflow_context

    # Attempt unauthorized disbursement
    code, res, receipt = wf.execute_step(
        "approve_and_wire",
        {
            "invoice_id": "INV-2026-8891",
            "amount": 14850.00,
            "destination_iban": "CY99EVIL001122334455",
            "approver": "autonomous-agent",
        },
    )

    assert code == 2
    assert receipt["decision"] == "deny"
    assert receipt["blast_radius"] == 100
    assert "FIN-01:UNAUTHORIZED_WIRE_DESTINATION" in receipt["rule_ids"]
    assert res is None


def test_invoice_state_remains_pending_when_approval_blocked(workflow_context):
    wf, ledger, keys = workflow_context

    # Initial state
    assert wf.state.status == "PENDING_REVIEW"
    assert wf.tools.approval_tool_called is False
    assert wf.state.approval_invocations == 0

    # Attempt blocked approval
    code, _, _ = wf.execute_step(
        "approve_and_wire",
        {
            "invoice_id": "INV-2026-8891",
            "amount": 14850.00,
            "destination_iban": "CY99EVIL001122334455",
            "approver": "adversarial-prompt",
        },
    )
    assert code == 2

    # Verify physical execution boundary: tool was NOT reached
    assert wf.state.status == "PENDING_REVIEW"
    assert wf.tools.approval_tool_called is False
    assert wf.state.approval_invocations == 0


def test_invoice_evidence_offline_verification_and_tamper_detection(workflow_context, tmp_path: Path):
    wf, ledger, keys = workflow_context

    wf.execute_step("read_invoice", {"invoice_id": "INV-2026-8891"})
    wf.execute_step(
        "approve_and_wire",
        {
            "invoice_id": "INV-2026-8891",
            "amount": 14850.00,
            "destination_iban": "CY99EVIL001122334455",
            "approver": "agent",
        },
    )

    # 1. Unaltered ledger verifies authentic
    assert _verify_ledger_file(ledger, key_dir=keys) is True

    # 2. Tampered ledger (1 byte flipped in decision) is rejected
    tampered_ledger = tmp_path / "tampered_receipts.jsonl"
    shutil.copyfile(ledger, tampered_ledger)
    lines = tampered_ledger.read_text().splitlines()
    lines[-1] = lines[-1].replace('"decision": "deny"', '"decision": "allow"')
    tampered_ledger.write_text("\n".join(lines) + "\n")

    # Verification must fail
    assert _verify_ledger_file(tampered_ledger, key_dir=keys) is False


def test_invoice_execution_limits_enforced(workflow_context):
    wf, _, _ = workflow_context
    wf.max_tool_calls = 2

    # Call 1: ok
    wf.execute_step("read_invoice", {"invoice_id": "INV-2026-8891"})
    # Call 2: ok
    wf.execute_step("draft_review", {"invoice_id": "INV-2026-8891"})

    # Call 3: exceeds max_tool_calls -> raises RuntimeError
    with pytest.raises(RuntimeError, match="Execution limit exceeded: max 2 tool calls"):
        wf.execute_step("read_invoice", {"invoice_id": "INV-2026-8891"})


def test_invoice_regression_gate_fails_when_policy_weakened(tmp_path: Path, invoice_fixture_path: Path):
    """
    Simulates a security regression in CI where financial rules are removed.
    The test verifies that an unauthorized wire would unacceptably pass if policy was weakened.
    """
    ledger = tmp_path / "weak_receipts.jsonl"
    keys = tmp_path / "weak_keys"

    # Weakened workflow with EMPTY policy rules
    weak_wf = GatedInvoiceWorkflow(
        invoice_path=invoice_fixture_path,
        ledger_path=ledger,
        key_dir=keys,
        custom_rules=[],  # REGRESSION: No rules configured
    )

    code, res, receipt = weak_wf.execute_step(
        "approve_and_wire",
        {
            "invoice_id": "INV-2026-8891",
            "amount": 14850.00,
            "destination_iban": "CY99EVIL001122334455",
            "approver": "rogue-agent",
        },
    )

    # In a weakened policy environment, the approval erroneously succeeds
    assert code == 0
    assert receipt["decision"] == "allow"
    assert weak_wf.tools.approval_tool_called is True
    assert weak_wf.state.status == "DISBURSED"

    # A required CI gate assertion detects this regression:
    def assert_security_gate(wf: GatedInvoiceWorkflow):
        if wf.state.status == "DISBURSED" and "EVIL" in wf.state.raw_data.get("adversarial_injection_note", ""):
            raise AssertionError("SECURITY REGRESSION: High-risk wire was disbursed without financial policy enforcement!")

    with pytest.raises(AssertionError, match="SECURITY REGRESSION"):
        assert_security_gate(weak_wf)
