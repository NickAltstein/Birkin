"""
╔════════════════════════════════════════════════════════════════════════════╗
║                          SACRED TEST FILE                                   ║
║                                                                            ║
║  This file is part of Birkin's closed credibility surface.                  ║
║                                                                            ║
║  Every test in here asserts that a specific field on an                    ║
║  AuthorizationReceipt is cryptographically bound into the receipt's          ║
║  signature — i.e. mutating that field *and only that field*                ║
║  invalidates the signature.                                                 ║
║                                                                            ║
║  Rule (release blocker):                                                   ║
║    No PR may merge if any test in this file is removed, weakened,            ║
║    skipped, or modified to accept a still-valid signature after a          ║
║    bound field has been mutated.                                            ║
║                                                                            ║
║  If a future feature requires a new field to be added to the receipt        ║
║  without being part of the signed material, that is a design change,        ║
║  not a test fix. Open a design discussion first. The credibility of         ║
║  the entire project rests on every receipt being tightly bound to          ║
║  the context it claims to authorize.                                       ║
║                                                                            ║
║  See CONTRIBUTING.md → "Sacred tests" for the full rule.                    ║
╚════════════════════════════════════════════════════════════════════════════╝

Receipt binding strength tests.

These tests prove that an :class:`AuthorizationReceipt` cryptographically
binds each of the pieces of context the credibility claim depends on:

* agent identity    — agent_id AND agent_public_key
* session           — session_id
* declared intent   — intent_hash
* action            — action + tool
* arguments         — args_hash
* policy decision    — decision + policy + rule
* prior context     — prior_event_hash (binds receipt to its position
                     in the audit chain, preventing lift-and-replay)

For every binding, the test:

  1. Mints an AUTHENTIC receipt.
  2. Surgically mutates *only* the bound field.
  3. Asserts the receipt's signature no longer verifies.

If any of these pass after mutation, the binding is weak and the
credibility claim is incomplete.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from receiptd import AuthorizationReceipt, SigningKey, sha256_hex


def _mint_receipt(**overrides) -> AuthorizationReceipt:
    sk = SigningKey.generate()
    defaults = dict(
        agent_id="agent-1",
        agent_public_key=sk.public_b64,
        session_id="sess-1",
        intent_hash=sha256_hex(b"declared intent"),
        action="tool.invoke",
        tool="fs.write",
        args_hash=sha256_hex(b'{"path":"/tmp/x"}'),
        decision="allow",
        policy="default@1.0.0",
        rule="fs.write.sandbox.allow",
        risk_score=20,
        reason="sandbox write",
        prior_event_hash="0" * 64,
    )
    defaults.update(overrides)
    r = AuthorizationReceipt(**defaults)
    r.sign(sk)
    return r, sk


@pytest.mark.parametrize(
    "field, new_value, label",
    [
        ("agent_id",            "agent-2",                              "agent identity (agent_id)"),
        ("agent_public_key",    None,                                   "agent identity (public_key)"),
        ("session_id",         "sess-2",                              "session"),
        ("intent_hash",        sha256_hex(b"different intent"),       "declared intent"),
        ("tool",               "shell.exec",                          "action (tool)"),
        ("action",             "tool.frob",                           "action (action)"),
        ("args_hash",          sha256_hex(b'{"path":"/etc/passwd"}'), "arguments"),
        ("decision",           "deny",                                "policy decision"),
        ("policy",             "default@2.0.0",                      "policy version"),
        ("rule",               "evil.allow",                          "policy rule"),
        ("risk_score",         5,                                     "risk score"),
        ("prior_event_hash",   "a" * 64,                              "prior context (chain position)"),
    ],
)
def test_receipt_binds(field, new_value, label):
    """Mutating *only* ``field`` must invalidate the receipt signature."""
    r, sk = _mint_receipt()
    assert r.verify(sk.public_b64), "clean receipt must verify before mutation"

    if new_value is None and field == "agent_public_key":
        new_value = SigningKey.generate().public_b64

    mutated = r.model_copy(update={field: new_value})
    assert not mutated.verify(sk.public_b64), (
        f"BINDING WEAKNESS: mutating {field} ({label}) did not invalidate "
        f"the receipt signature. The receipt is NOT cryptographically bound "
        f"to {label}."
    )


def test_receipt_binding_strength_summary(capsys):
    """Print a one-page table of every binding for human review."""
    cases = [
        ("agent identity (agent_id)",   "agent_id",         "agent-2"),
        ("agent identity (public_key)", "agent_public_key", "SWAPPED"),
        ("session",                     "session_id",       "sess-2"),
        ("declared intent",              "intent_hash",      sha256_hex(b"x")),
        ("action (tool)",                "tool",             "shell.exec"),
        ("action (action)",              "action",           "tool.frob"),
        ("arguments",                    "args_hash",        sha256_hex(b"y")),
        ("policy decision",              "decision",         "deny"),
        ("policy version",               "policy",           "default@2.0.0"),
        ("policy rule",                  "rule",             "evil.allow"),
        ("risk score",                   "risk_score",       5),
        ("prior context (chain pos)",    "prior_event_hash", "a" * 64),
    ]
    print()
    print("=" * 78)
    print("BIRKIN RECEIPT BINDING STRENGTH — mutating each field MUST break sig")
    print("=" * 78)
    print(f"{'binding':<32}  {'field':<22}  {'sig still valid?'}")
    print("-" * 78)
    all_strong = True
    for label, field, new_val in cases:
        r, sk = _mint_receipt()
        if new_val == "SWAPPED":
            new_val = SigningKey.generate().public_b64
        mutated = r.model_copy(update={field: new_val})
        still_valid = mutated.verify(sk.public_b64)
        mark = "✗ WEAK" if still_valid else "✓ strong"
        if still_valid:
            all_strong = False
        print(f"{mark} {label:<30}  {field:<22}  {still_valid}")
    print("-" * 78)
    print(f"{'ALL BINDINGS STRONG' if all_strong else 'WEAK BINDING DETECTED'}")
    print("=" * 78)
    assert all_strong
