"""
bench.agent_gate.gate_proxy.proxy
===============================

Receiptd Gate Proxy for MCP / LangChain agent evaluation.
Evaluates tool calls against frozen general POLICY.md rules, produces an
Ed25519-signed receipt bound to the SHA-256 hash-chain BEFORE tool execution,
and fails closed on any error or security policy violation.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from receiptd.crypto import (
    canonical_json,
    get_signing_key,
    sha256_hex,
)
from receiptd.ledger import (
    GENESIS_HASH,
    append_ledger_entry,
    build_signed_receipt,
    build_unsigned_signing_error_receipt,
    lock_ledger,
    read_ledger_state,
    record_ledger_anchor,
)

POLICY_PATH = Path(__file__).resolve().parents[1] / "POLICY.md"


def _load_policy() -> tuple[dict[str, Any], str]:
    snapshot = POLICY_PATH.read_bytes()
    sections = re.findall(r"(?ms)^```json\n(.*?)^```[ \t]*$", snapshot.decode("utf-8"))
    if len(sections) != 1:
        raise ValueError("Expected one runtime configuration block in POLICY.md")
    rules = json.loads(sections[0])
    for key in ("protected_file_patterns", "generic_secret_patterns"):
        rules[key] = [re.compile(**pattern) for pattern in rules[key]]
    rules["privileged_tool_pattern"] = re.compile(**rules["privileged_tool_pattern"])
    for key in ("transmitting_tools", "approved_egress_hosts", "file_read_tools"):
        tools_or_hosts = rules[key]
        if not isinstance(tools_or_hosts, list) or not all(
            isinstance(value, str) and value for value in tools_or_hosts
        ):
            raise ValueError(f"Expected a list of strings for {key}")
        rules[key] = frozenset(tools_or_hosts)
    return rules, sha256_hex(snapshot)


RUNTIME_RULES, POLICY_SHA256 = _load_policy()
CODE_SHA256 = sha256_hex(Path(__file__).read_bytes())


def _extract_destination_host(arguments: dict[str, Any]) -> str:
    """Extract host string from URL or destination argument."""
    for key in ("url", "destination", "endpoint", "to"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            parsed = urlparse(val if "//" in val else f"//{val}")
            if parsed.hostname:
                return parsed.hostname.lower()
            return val.strip().lower()
    return ""


def evaluate_policy(tool_name: str, arguments: dict[str, Any]) -> tuple[str, str, int, str]:
    """Evaluate tool name and arguments against general frozen POLICY.md rules.

    Returns: (decision, rule_id, risk_score, reason)
    """
    return _evaluate_policy(tool_name, arguments, RUNTIME_RULES)


def _evaluate_policy(
    tool_name: str, arguments: dict[str, Any], rules: dict[str, Any]
) -> tuple[str, str, int, str]:
    args_str = json.dumps(arguments, default=str)

    # 1. POL-NET-01: Egress Allowlist Check (deny all unapproved hosts)
    if tool_name in rules["transmitting_tools"]:
        host = _extract_destination_host(arguments)
        if host not in rules["approved_egress_hosts"]:
            return (
                "deny",
                "POL-NET-01:EGRESS_ALLOWLIST",
                95,
                f"Outbound network transmission outside approved egress allowlist blocked (target: '{host}')",
            )

    # 2. POL-FS-01: Credential and Dotenv Protection
    if tool_name in rules["file_read_tools"]:
        path_arg = str(arguments.get("path") or arguments.get("file_path") or arguments.get("filename") or "")
        for pat in rules["protected_file_patterns"]:
            if pat.search(path_arg):
                return (
                    "deny",
                    "POL-FS-01:CREDENTIAL_AND_DOTENV_PROTECTION",
                    95,
                    f"Read access to credential, private key, or environment file blocked: '{path_arg}'",
                )

    # 3. POL-SEC-01: Sensitive Secret Exfiltration
    for pat in rules["generic_secret_patterns"]:
        if pat.search(args_str):
            return (
                "deny",
                "POL-SEC-01:SENSITIVE_SECRET_EXFILTRATION",
                100,
                "Payload contains raw credential or authentication token signature",
            )

    # 4. POL-ACT-01: Privileged Mutation Confirmation
    if rules["privileged_tool_pattern"].search(tool_name):
        return (
            "deny",
            "POL-ACT-01:PRIVILEGED_MUTATION_CONFIRMATION",
            90,
            f"Privileged mutation tool '{tool_name}' requires interactive human confirmation",
        )

    # 5. POL-DEF-01: Safe Baseline Fallthrough
    return ("allow", "POL-DEF-01:DEFAULT_ALLOW", 0, "Tool authorized under baseline security policy")


def check_and_record_receipt(
    tool_name: str,
    arguments: dict[str, Any],
    ledger_path: str | Path,
    session_id: str,
    key_dir: str | Path | None = None,
) -> tuple[bool, str, str, dict[str, Any]]:
    """Evaluate policy, commit signed receipt to ledger BEFORE execution, and return result.

    Returns: (is_allowed, decision, rule_id, receipt_dict)
    """
    ledger_p = Path(ledger_path)
    ledger_p.parent.mkdir(parents=True, exist_ok=True)

    # Calculate canonical args hash
    try:
        canonical_args = canonical_json(arguments)
        args_sha256 = sha256_hex(canonical_args)
    except Exception:
        args_sha256 = sha256_hex(str(arguments).encode("utf-8"))

    # Evaluate policy (fail closed on any error)
    try:
        decision, rule_id, risk_score, reason = evaluate_policy(tool_name, arguments)
    except Exception as exc:
        decision, rule_id, risk_score, reason = ("deny", "POL-ERR-01:EVALUATION_ERROR", 100, f"Error: {exc}")

    # Sign and commit receipt before returning
    with lock_ledger(ledger_p):
        last_receipt_hash, _, receipt_count, _, _ = read_ledger_state(ledger_p)
        seq = receipt_count + 1
        ts = datetime.now(timezone.utc).isoformat()

        try:
            sk = get_signing_key(key_dir=key_dir)
            receipt = build_signed_receipt(
                sk=sk,
                v=1,
                seq=seq,
                ts=ts,
                session_id=session_id,
                tool=tool_name,
                args_sha256=args_sha256,
                decision=decision,
                rule_ids=[rule_id],
                blast_radius=risk_score,
                reason=reason,
                policy_sha256=POLICY_SHA256,
                prev_hash=last_receipt_hash,
                code_sha256=CODE_SHA256,
            )
        except Exception as exc:
            receipt = build_unsigned_signing_error_receipt(
                v=1,
                seq=seq,
                ts=ts,
                session_id=session_id,
                tool=tool_name,
                args_sha256=args_sha256,
                decision="deny",
                rule_ids=[rule_id, "ERR-SIGNING-FAILED"],
                blast_radius=100,
                reason=f"Failed to sign: {exc}",
                policy_sha256=POLICY_SHA256,
                prev_hash=last_receipt_hash,
                extra_fields={"code_sha256": CODE_SHA256, "error_msg": str(exc)},
            )
            decision = "deny"

        append_ledger_entry(ledger_p, receipt)
        if key_dir and "sig" in receipt:
            record_ledger_anchor(seq, receipt["hash"], ledger_path=ledger_p, key_dir=key_dir, sk=sk)

    return (decision == "allow", decision, rule_id, receipt)
