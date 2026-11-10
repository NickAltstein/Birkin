"""
Manifest + schema-version gate tests.

These prove that:

* A clean package's manifest is recognized and AUTHENTIC.
* If an attacker (or a future Birkin version) emits a package whose
  manifest references a schema this verifier does not recognize, the
  verdict is TAMPERED (not silently AUTHENTIC) and the failure is
  attributed to the new "Manifest + schema versions" check.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from receiptd import Engine, HermesAdapter, SigningKey, load_default_policy, verify_package
from receiptd.verify import _coerce_package


@pytest.fixture
def clean_pkg_dict() -> dict:
    sk = SigningKey.generate()
    policy = load_default_policy()
    adapter = HermesAdapter()
    engine = Engine(birkin_signing_key=sk, policy=policy, adapter=adapter)
    identity = adapter.make_identity(agent_id="manifest-agent", policy_ref=policy.ref)
    engine.start_session(identity)
    engine.declare_intent(identity, adapter.declare_intent(identity, "manifest test"))
    req = adapter.build_action_request(
        tool="fs.write", args={"path": "/tmp/birkin/x", "data": "y"}
    )
    r = engine.attempt_action(identity, req)
    engine.execute(identity, req, r)
    engine.checkpoint()
    engine.end_session(identity)
    pkg = engine.export(identity=identity)
    assert verify_package(pkg).verdict == "AUTHENTIC"
    return json.loads(pkg.model_dump_json())


def _verify(d: dict):
    return verify_package(_coerce_package(d))


def test_clean_manifest_is_recognized(clean_pkg_dict):
    """Sanity: a freshly exported package's manifest is recognized."""
    report = _verify(clean_pkg_dict)
    assert report.verdict == "AUTHENTIC"
    man_check = next(c for c in report.checks if c.name == "Manifest + schema versions")
    assert man_check.ok


def test_unknown_receipt_scheme_is_rejected(clean_pkg_dict):
    """If the manifest references an unknown receipt scheme, the verdict
    is TAMPERED and the failure is attributed to the manifest check."""
    d = copy.deepcopy(clean_pkg_dict)
    d["manifest"]["receipt_scheme"] = "birkin.receipt@99-evil"
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    man_check = next(c for c in report.checks if c.name == "Manifest + schema versions")
    assert not man_check.ok
    assert "receipt_scheme" in man_check.detail


def test_missing_manifest_key_is_rejected(clean_pkg_dict):
    """If the manifest is missing a required key, the verdict is TAMPERED."""
    d = copy.deepcopy(clean_pkg_dict)
    del d["manifest"]["checkpoint_scheme"]
    report = _verify(d)
    assert report.verdict == "TAMPERED"
    man_check = next(c for c in report.checks if c.name == "Manifest + schema versions")
    assert not man_check.ok
    assert "checkpoint_scheme" in man_check.detail


def test_missing_manifest_entirely_is_rejected(clean_pkg_dict):
    """If the manifest is missing entirely, the verdict is INVALID (a
    structurally broken package). The manifest check itself is also red."""
    d = copy.deepcopy(clean_pkg_dict)
    d.pop("manifest", None)
    report = _verify(d)
    assert report.verdict in ("TAMPERED", "INVALID")
    man_check = next(c for c in report.checks if c.name == "Manifest + schema versions")
    assert not man_check.ok
