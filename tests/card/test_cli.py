"""CLI tests for receiptd card and verify-card."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from receiptd.cli import app, main

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_cli_requires_command():
    result = runner.invoke(app, [])
    assert result.exit_code != 0


def test_cli_card_help():
    result = runner.invoke(
        app,
        ["card", "--help"],
        env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"},
    )
    assert result.exit_code == 0
    clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert "--session" in clean or "-s" in clean
    assert "--out" in clean
    assert "--redact-paths" in clean


def test_cli_verify_card_help():
    result = runner.invoke(app, ["verify-card", "--help"])
    assert result.exit_code == 0
    clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert "--pubkey-id" in clean
    assert "--pubkey-file" in clean


@pytest.fixture
def run_card(tmp_path, monkeypatch):
    def _run(fixture_name, *extra):
        monkeypatch.chdir(tmp_path)
        fixture = FIXTURES / "sessions" / fixture_name
        result = runner.invoke(app, ["card", "--session", str(fixture), *extra])
        return result.exit_code, tmp_path
    return _run


def test_card_cli_produces_all_three_outputs(run_card):
    rc, out_dir = run_card("claude_basic.jsonl")
    assert rc == 0
    assert (out_dir / "card.png").is_file()
    assert (out_dir / "card.svg").is_file()
    assert (out_dir / "card.json").is_file()


def test_card_cli_json_structure(run_card):
    rc, out_dir = run_card("claude_basic.jsonl")
    payload = json.loads((out_dir / "card.json").read_text())
    assert payload["verdict"]["level"] == "RED"
    assert payload["rules_version"] == "1"
    assert isinstance(payload["evidence"], list) and payload["evidence"]
    assert payload["digest"]
    assert payload["signature"]
    for item in payload["evidence"]:
        assert set(item) == {"category", "index", "tool", "target", "timestamp", "rule"}


def test_card_cli_codex_fixture(run_card):
    rc, out_dir = run_card("codex_basic.jsonl")
    assert rc == 0
    payload = json.loads((out_dir / "card.json").read_text())
    assert payload["verdict"]["level"] in ("RED", "YELLOW")


def test_card_cli_out_option_changes_paths(run_card):
    rc, out_dir = run_card("claude_basic.jsonl", "--out", "mine.png")
    assert rc == 0
    assert (out_dir / "mine.png").is_file()
    assert (out_dir / "mine.svg").is_file()
    assert (out_dir / "mine.json").is_file()


def test_card_cli_missing_session_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["card", "--session", str(tmp_path / "nope.jsonl")])
    assert result.exit_code == 2


def test_card_cli_no_logs_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RECEIPTD_CLAUDE_DIR", str(tmp_path / "empty"))
    monkeypatch.setenv("RECEIPTD_CODEX_DIR", str(tmp_path / "empty2"))
    result = runner.invoke(app, ["card"])
    assert result.exit_code == 2


def test_card_cli_redact_paths_hashes_targets(run_card):
    _rc, plain_dir = run_card("claude_basic.jsonl")
    plain = json.loads((plain_dir / "card.json").read_text())
    _rc, red_dir = run_card("claude_basic.jsonl", "--redact-paths")
    redacted = json.loads((red_dir / "card.json").read_text())

    path_targets = {".env", "password", "payload.bin"}
    redacted_targets = {e["target"] for e in redacted["evidence"]}
    assert not (path_targets & redacted_targets)
    assert "api.example.com" in redacted_targets
    hashed = redacted_targets - {"api.example.com", "collector.example.net", "github"}
    assert hashed
    assert all(len(t) == 8 and all(c in "0123456789abcdef" for c in t) for t in hashed)
    assert redacted["redacted"] is True
    assert plain["redacted"] is False


def test_verify_card_valid(run_card, tmp_path):
    run_card("claude_basic.jsonl")
    result = runner.invoke(app, ["verify-card", str(tmp_path / "card.json")])
    assert result.exit_code == 0
    assert "VALID" in result.stdout


def test_verify_card_tampered(run_card, tmp_path):
    run_card("claude_basic.jsonl")
    payload = json.loads((tmp_path / "card.json").read_text())
    payload["evidence"][0]["target"] = "zzz-tampered"
    (tmp_path / "card.json").write_text(json.dumps(payload))
    result = runner.invoke(app, ["verify-card", str(tmp_path / "card.json")])
    assert result.exit_code == 1
    assert "TAMPERED" in result.stdout


def test_verify_card_single_byte_flip(run_card, tmp_path):
    run_card("claude_basic.jsonl")
    raw = (tmp_path / "card.json").read_text()
    flipped = raw.replace('"rules_version": "1"', '"rules_version": "2"')
    assert flipped != raw
    (tmp_path / "card.json").write_text(flipped)
    result = runner.invoke(app, ["verify-card", str(tmp_path / "card.json")])
    assert result.exit_code == 1
    assert "TAMPERED" in result.stdout


def test_verify_card_missing_file():
    result = runner.invoke(app, ["verify-card", "/nonexistent/card.json"])
    assert result.exit_code == 1
    assert "TAMPERED" in result.stdout or "error" in result.stdout.lower()


def test_verify_card_with_pubkey_id_match(run_card, tmp_path):
    run_card("claude_basic.jsonl")
    card_path = tmp_path / "card.json"
    card_doc = json.loads(card_path.read_text())
    from receiptd.crypto import get_pubkey_id

    key_id = get_pubkey_id(card_doc["public_key"])

    result = runner.invoke(app, ["verify-card", str(card_path), "--pubkey-id", key_id])
    assert result.exit_code == 0
    assert "VALID" in result.stdout


def test_verify_card_with_pubkey_file_match(run_card, tmp_path):
    run_card("claude_basic.jsonl")
    card_path = tmp_path / "card.json"
    card_doc = json.loads(card_path.read_text())
    pub_file = tmp_path / "expected_signer.pem"
    pub_file.write_text(card_doc["public_key"])

    result = runner.invoke(app, ["verify-card", str(card_path), "--pubkey-file", str(pub_file)])
    assert result.exit_code == 0
    assert "VALID" in result.stdout


def test_verify_card_resigned_with_fresh_key_in_temp_dir(run_card, tmp_path, monkeypatch):
    run_card("claude_basic.jsonl")
    card_path = tmp_path / "card.json"
    card_doc = json.loads(card_path.read_text())
    from receiptd.crypto import get_pubkey_id

    original_id = get_pubkey_id(card_doc["public_key"])

    # Re-sign the card with a fresh key in a temp RECEIPTD_KEY_DIR
    fresh_keys_dir = tmp_path / "fresh_keys"
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(fresh_keys_dir))

    from receiptd.card.signing import sign_card_payload

    payload = {k: v for k, v in card_doc.items() if k not in ("signature", "digest", "public_key")}
    resigned_doc = sign_card_payload(payload)
    fresh_id = get_pubkey_id(resigned_doc["public_key"])
    assert fresh_id != original_id
    card_path.write_text(json.dumps(resigned_doc))

    # Without --pubkey-id, behavior is unchanged and passes
    result_unpinned = runner.invoke(app, ["verify-card", str(card_path)])
    assert result_unpinned.exit_code == 0
    assert "VALID" in result_unpinned.stdout

    # With --pubkey-id pinned to original key, fails with exit 1 and UNTRUSTED SIGNER
    result_pinned = runner.invoke(app, ["verify-card", str(card_path), "--pubkey-id", original_id])
    assert result_pinned.exit_code == 1
    assert f"UNTRUSTED SIGNER (key {fresh_id} != expected {original_id})" in result_pinned.stdout

