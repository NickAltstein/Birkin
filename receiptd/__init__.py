"""
birkin
======

Birkin — the open Agent Authorization & Evidence Layer.

Runtime-agnostic control plane for autonomous agents:
signed authorization receipts, a verifiable audit ledger with Merkle
checkpoints, and offline verification of exported run packages.
"""

from .crypto import SigningKey, verify_signature, canonical_json, sha256_hex, merkle_root
from .models import (
    AgentIdentity,
    AuthorizationReceipt,
    AuditEvent,
    MerkleCheckpoint,
    PolicyDecision,
    RunPackage,
    PACKAGE_MANIFEST,
    VerificationReport,
    CheckResult,
    make_passport,
)
from .policy import PolicySpec, load_default_policy, DEFAULT_POLICY_PATH
from .adapter import AgentAdapter, BaseAdapter, Intent, ActionRequest, ActionResult
from .adapters.hermes import HermesAdapter
from .adapters.null_agent import NullAgentAdapter
from .adapters.grok_bot import GrokBotAdapter
from .audit import AuditLedger, GENESIS_HASH
from .engine import Engine
from .verify import (
    verify_package,
    verify_file,
    load_run_package,
    render_report,
)

__version__ = "0.2.0"

__all__ = [
    "SigningKey",
    "verify_signature",
    "canonical_json",
    "sha256_hex",
    "merkle_root",
    "AgentIdentity",
    "AuthorizationReceipt",
    "AuditEvent",
    "MerkleCheckpoint",
    "PolicyDecision",
    "RunPackage",
    "PACKAGE_MANIFEST",
    "VerificationReport",
    "CheckResult",
    "make_passport",
    "PolicySpec",
    "load_default_policy",
    "DEFAULT_POLICY_PATH",
    "AgentAdapter",
    "BaseAdapter",
    "Intent",
    "ActionRequest",
    "ActionResult",
    "HermesAdapter",
    "NullAgentAdapter",
    "GrokBotAdapter",
    "AuditLedger",
    "GENESIS_HASH",
    "Engine",
    "verify_package",
    "verify_file",
    "load_run_package",
    "render_report",
    "__version__",
]
