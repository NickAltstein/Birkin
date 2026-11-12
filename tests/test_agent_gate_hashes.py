import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from receiptd.crypto import canonical_json_subset, get_public_key_pem, verify_ed25519
from receiptd.ledger import SIGNABLE_RECEIPT_FIELDS

GATE = Path(__file__).resolve().parents[1] / "bench" / "agent_gate"


def load_gate(tmp_path, policy_bytes):
    source = tmp_path / "gate_proxy" / "proxy.py"
    source.parent.mkdir(exist_ok=True)
    source.write_bytes((GATE / "gate_proxy" / "proxy.py").read_bytes())
    if policy_bytes is not None:
        (tmp_path / "POLICY.md").write_bytes(policy_bytes)
    spec = importlib.util.spec_from_file_location("test_gate_proxy", source)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


@pytest.fixture
def policy_bytes():
    return (GATE / "POLICY.md").read_bytes()


def receipt(gate, tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    _, _, _, result = gate.check_and_record_receipt(
        "fetch_weather", {}, ledger, "test", key_dir=tmp_path / "keys"
    )
    assert json.loads(ledger.read_text()) == result
    return result


def test_receipt_policy_hash_matches_file(tmp_path, policy_bytes):
    gate = load_gate(tmp_path, policy_bytes)
    assert receipt(gate, tmp_path)["policy_sha256"] == hashlib.sha256(policy_bytes).hexdigest()


def test_one_byte_policy_edit_changes_hash(tmp_path, policy_bytes):
    original = load_gate(tmp_path, policy_bytes)
    edited_bytes = policy_bytes.replace(b"Status: FROZEN", b"Status: FROzEN", 1)
    assert sum(a != b for a, b in zip(policy_bytes, edited_bytes)) == 1
    edited = load_gate(tmp_path, edited_bytes)
    assert receipt(edited, tmp_path)["policy_sha256"] == hashlib.sha256(edited_bytes).hexdigest()
    assert original.POLICY_SHA256 != edited.POLICY_SHA256


def test_missing_policy_fails_startup_without_receipt(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_gate(tmp_path, None)
    assert not (tmp_path / "ledger.jsonl").exists()


def test_receipt_code_hash_matches_proxy_and_is_signed(tmp_path, policy_bytes):
    gate = load_gate(tmp_path, policy_bytes)
    result = receipt(gate, tmp_path)
    assert result["code_sha256"] == hashlib.sha256(Path(gate.__file__).read_bytes()).hexdigest()
    public_key = get_public_key_pem(tmp_path / "keys")
    assert verify_ed25519(public_key, result["sig"], canonical_json_subset(result, SIGNABLE_RECEIPT_FIELDS))
