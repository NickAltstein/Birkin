"""policy_sha256 is the SHA-256 of the policy bytes the hook enforced."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from receiptd.hooks.claude_code_gate import (
    default_policy_path,
    evaluate_payload,
    load_policy_from_argv,
    parse_policy,
)

ROOT = Path(__file__).resolve().parents[1]
LEGACY_LABEL = b"DEFAULT_RULES:POL-01,POL-02,POL-03"
SAFE = {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}
DANGEROUS = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(work: Path, payload: dict, policy: Path | None = None, extra_args: list[str] | None = None):
    work.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "HOME": str(work),
        "RECEIPTD_KEY_DIR": str(work / "keys"),
    }
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)
    ledger = work / "receipts.jsonl"
    cmd = [sys.executable, "-m", "receiptd.hooks.claude_code_gate", "--ledger", str(ledger)]
    if policy is not None:
        cmd.extend(["--policy", str(policy)])
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(
        cmd,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=work,
        env=env,
    )
    receipts = []
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("type") != "checkpoint":
                receipts.append(entry)
    return result, receipts


def _policy(**overrides) -> dict:
    document = {
        "format": "receiptd.pretooluse.v1",
        "base_score": 10,
        "deny_at": 75,
        "rules": [],
    }
    document.update(overrides)
    return document


def test_default_policy_sha256_is_file_bytes(tmp_path: Path):
    policy_bytes = default_policy_path().read_bytes()
    result, receipts = _run(tmp_path, SAFE)
    assert result.returncode == 0, result.stderr
    assert len(receipts) == 1
    assert receipts[0]["decision"] == "allow"
    assert receipts[0]["policy_sha256"] == _sha256(policy_bytes)
    assert receipts[0]["policy_sha256"] != _sha256(LEGACY_LABEL)


def test_explicit_policy_sha256_is_that_files_bytes(tmp_path: Path):
    raw = default_policy_path().read_bytes()
    edited = raw.replace(b'"weight": 95', b'"weight": 96', 1)
    assert edited != raw
    assert sum(left != right for left, right in zip(raw, edited)) == 1
    custom = tmp_path / "edited.policy.json"
    custom.write_bytes(edited)
    parse_policy(edited)

    result, receipts = _run(tmp_path / "run", SAFE, custom)
    assert result.returncode == 0, result.stderr
    assert receipts[0]["policy_sha256"] == _sha256(edited)
    assert receipts[0]["policy_sha256"] != _sha256(raw)


def test_policy_path_is_read_once(tmp_path: Path, monkeypatch):
    target = tmp_path / "once.policy.json"
    target.write_bytes(default_policy_path().read_bytes())
    reads = {"count": 0}
    original = Path.read_bytes

    def counting(self: Path) -> bytes:
        if self == target:
            reads["count"] += 1
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", counting)
    policy, digest, error = load_policy_from_argv(["gate", "--policy", str(target)])
    assert reads["count"] == 1
    assert error is None
    assert policy is not None
    assert digest == _sha256(original(target))


def test_custom_rule_changes_allow_and_deny(tmp_path: Path):
    allow_all = tmp_path / "allow.policy.json"
    allow_all.write_text(json.dumps(_policy()), encoding="utf-8")
    denied_by_default, default_receipts = _run(tmp_path / "default-deny", DANGEROUS)
    assert denied_by_default.returncode == 2
    assert default_receipts[0]["decision"] == "deny"
    assert "POL-02:DESTRUCTIVE_DDL_OR_FS" in default_receipts[0]["rule_ids"]

    allowed, allow_receipts = _run(tmp_path / "custom-allow", DANGEROUS, allow_all)
    assert allowed.returncode == 0, allowed.stderr
    assert allow_receipts[0]["decision"] == "allow"
    assert allow_receipts[0]["rule_ids"] == []
    assert allow_receipts[0]["policy_sha256"] == _sha256(allow_all.read_bytes())

    deny_echo = tmp_path / "echo.policy.json"
    deny_echo.write_text(
        json.dumps(
            _policy(
                rules=[
                    {
                        "id": "POL-ECHO",
                        "weight": 50,
                        "ignore_case": False,
                        "pattern": "echo hello",
                    }
                ]
            )
        ),
        encoding="utf-8",
    )
    allowed_by_default, _ = _run(tmp_path / "default-allow", SAFE)
    assert allowed_by_default.returncode == 0
    denied, deny_receipts = _run(tmp_path / "custom-deny", SAFE, deny_echo)
    assert denied.returncode == 2
    assert deny_receipts[0]["decision"] == "deny"
    assert deny_receipts[0]["rule_ids"] == ["POL-ECHO"]
    assert deny_receipts[0]["policy_sha256"] == _sha256(deny_echo.read_bytes())

    blocked, _, triggered = evaluate_payload(SAFE, parse_policy(deny_echo.read_bytes()))
    assert blocked is True
    assert triggered == ["POL-ECHO"]
    assert evaluate_payload(SAFE)[0] is False


def test_missing_invalid_and_unreadable_policy_fail_closed(tmp_path: Path):
    default_digest = _sha256(default_policy_path().read_bytes())
    legacy = _sha256(LEGACY_LABEL)

    missing = tmp_path / "missing.policy.json"
    result, receipts = _run(tmp_path / "missing-run", SAFE, missing)
    assert result.returncode == 2
    assert "FAIL-CLOSED" in result.stderr
    assert receipts[0]["decision"] == "deny"
    assert receipts[0]["rule_ids"] == ["POLICY_MISSING"]
    assert receipts[0]["policy_sha256"] == ""
    assert receipts[0]["policy_sha256"] not in {default_digest, legacy}

    omitted = tmp_path / "omitted-run"
    omitted.mkdir()
    env = {**os.environ, "HOME": str(omitted), "RECEIPTD_KEY_DIR": str(omitted / "keys")}
    env.pop("RECEIPTD_SIGNING_KEY", None)
    env.pop("BIRKIN_SIGNING_KEY", None)
    no_value = subprocess.run(
        [
            sys.executable,
            "-m",
            "receiptd.hooks.claude_code_gate",
            "--ledger",
            str(omitted / "receipts.jsonl"),
            "--policy",
        ],
        input=json.dumps(SAFE),
        capture_output=True,
        text=True,
        cwd=omitted,
        env=env,
    )
    assert no_value.returncode == 2
    no_value_receipt = json.loads((omitted / "receipts.jsonl").read_text().splitlines()[0])
    assert no_value_receipt["rule_ids"] == ["POLICY_MISSING"]
    assert no_value_receipt["policy_sha256"] == ""

    invalid = tmp_path / "invalid.policy.json"
    invalid.write_bytes(b"{")
    result, receipts = _run(tmp_path / "invalid-run", SAFE, invalid)
    assert result.returncode == 2
    assert receipts[0]["decision"] == "deny"
    assert receipts[0]["rule_ids"] == ["POLICY_INVALID"]
    assert receipts[0]["policy_sha256"] == _sha256(b"{")
    assert receipts[0]["policy_sha256"] != default_digest

    directory = tmp_path / "not-a-file"
    directory.mkdir()
    result, receipts = _run(tmp_path / "dir-run", SAFE, directory)
    assert result.returncode == 2
    assert receipts[0]["decision"] == "deny"
    assert receipts[0]["rule_ids"] == ["POLICY_UNREADABLE"]
    assert receipts[0]["policy_sha256"] == ""

    engine_policy = ROOT / "policies" / "default.policy.json"
    engine_bytes = engine_policy.read_bytes()
    result, receipts = _run(tmp_path / "engine-run", SAFE, engine_policy)
    assert result.returncode == 2
    assert receipts[0]["decision"] == "deny"
    assert receipts[0]["rule_ids"] == ["POLICY_INVALID"]
    assert receipts[0]["policy_sha256"] == _sha256(engine_bytes)
    assert receipts[0]["policy_sha256"] != default_digest
