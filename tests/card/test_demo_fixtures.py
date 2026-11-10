"""End-to-end tests for the trifecta_demo fixtures.

Anyone must be able to run:
    receiptd card --session fixtures/trifecta_demo/red.jsonl
and get a correct card without real user logs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from receiptd.cli import main
from receiptd.card.pipeline import analyze_paths

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEMO = REPO_ROOT / "fixtures" / "trifecta_demo"


@pytest.fixture(autouse=True)
def _isolated_key_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("RECEIPTD_KEY_DIR", str(tmp_path / "keys"))


@pytest.mark.parametrize(
    "name,level,ordered,counts",
    [
        ("red.jsonl", "RED", False, {"PRIVATE": 2, "UNTRUSTED": 4, "EGRESS": 3}),
        ("yellow.jsonl", "YELLOW", False, {"PRIVATE": 1, "UNTRUSTED": 0, "EGRESS": 1}),
        ("green.jsonl", "GREEN", False, {"PRIVATE": 0, "UNTRUSTED": 0, "EGRESS": 0}),
    ],
)
def test_demo_verdicts(name, level, ordered, counts):
    report = analyze_paths([DEMO / name])
    assert report.level == level, (report.counts, [ (h.category, h.rule, h.target) for h in report.hits])
    assert report.ordered is ordered
    assert report.counts == counts


def test_demo_red_is_ordered_kill_chain():
    report = analyze_paths([DEMO / "red.jsonl"])
    private_idx = [h.index for h in report.hits if h.category == "PRIVATE"]
    untrusted_idx = [h.index for h in report.hits if h.category == "UNTRUSTED"]
    egress_idx = [h.index for h in report.hits if h.category == "EGRESS"]
    # Private reads and untrusted inputs all precede the final exfiltration
    # call (the POST at index 6); the WebFetch at 2 is both untrusted input
    # and (by policy) egress, so the strict ordered flag is False here.
    assert max(private_idx) < max(egress_idx)
    assert max(untrusted_idx) <= max(egress_idx)
    assert min(egress_idx) == 2  # first egress is the WebFetch itself


def test_demo_green_has_zero_hits():
    report = analyze_paths([DEMO / "green.jsonl"])
    assert report.hits == []
    assert report.sessions[0].source_format == "codex"
    assert report.sessions[0].tool_calls == 4


def test_card_network_isolation_on_all_fixtures(tmp_path, monkeypatch):
    """Guarantees zero network calls on all three fixtures (red, yellow, green) and no content leaks."""
    import socket

    def _block_socket(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during card execution")

    monkeypatch.setattr(socket, "socket", _block_socket)
    monkeypatch.setattr(socket, "create_connection", _block_socket)

    for fixture_name in ["red.jsonl", "yellow.jsonl", "green.jsonl"]:
        fixture_path = DEMO / fixture_name
        out_png = tmp_path / f"{fixture_name}.png"
        rc = main(["card", "--session", str(fixture_path), "--out", str(out_png)])
        assert rc == 0
        json_file = out_png.with_suffix(".json")
        assert json_file.is_file()
        data = json.loads(json_file.read_text())
        # The card never outputs file contents or prompt text
        for ev in data.get("evidence", []):
            assert "prompt" not in ev
            assert "content" not in ev
            assert "file_contents" not in ev
            assert set(ev.keys()) == {"category", "index", "tool", "target", "timestamp", "rule"}


# ---------------------------------------------------------------------------
# full CLI runs (in-process)
# ---------------------------------------------------------------------------


def _run_cli(fixture, tmp_path, monkeypatch, *extra):
    monkeypatch.chdir(tmp_path)
    rc = main(["card", "--session", str(DEMO / fixture), *extra])
    assert rc == 0
    return tmp_path


def test_demo_red_cli_outputs_and_verify(tmp_path, monkeypatch):
    _run_cli("red.jsonl", tmp_path, monkeypatch)
    payload = json.loads((tmp_path / "card.json").read_text())
    assert payload["verdict"]["level"] == "RED"
    assert (tmp_path / "card.png").is_file()
    assert (tmp_path / "card.svg").is_file()
    assert main(["verify-card", "card.json"]) == 0


def test_demo_yellow_cli(tmp_path, monkeypatch):
    _run_cli("yellow.jsonl", tmp_path, monkeypatch)
    payload = json.loads((tmp_path / "card.json").read_text())
    assert payload["verdict"]["level"] == "YELLOW"


def test_demo_green_cli(tmp_path, monkeypatch):
    _run_cli("green.jsonl", tmp_path, monkeypatch)
    payload = json.loads((tmp_path / "card.json").read_text())
    assert payload["verdict"]["level"] == "GREEN"
    assert payload["evidence"] == []


def test_demo_cli_from_repo_root(tmp_path, monkeypatch):
    """The README quickstart: run from the repository root."""
    monkeypatch.chdir(REPO_ROOT)
    try:
        rc = main(["card", "--session", "fixtures/trifecta_demo/red.jsonl", "--out", str(tmp_path / "c.png")])
        assert rc == 0
        assert (tmp_path / "c.png").is_file()
        assert (tmp_path / "c.json").is_file()
    finally:
        # never leave stray outputs in the repo
        for stray in ("card.png", "card.svg", "card.json"):
            (REPO_ROOT / stray).unlink(missing_ok=True)


def test_demo_subprocess_invocation(tmp_path):
    """The exact user-facing command works as a standalone process."""
    result = subprocess.run(
        [sys.executable, "-m", "receiptd", "card", "--session", str(DEMO / "red.jsonl"),
         "--out", str(tmp_path / "s.png")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "s.png").is_file()
    assert (tmp_path / "s.svg").is_file()
    assert (tmp_path / "s.json").is_file()
    assert "LETHAL TRIFECTA" in result.stdout
    # privacy: no full private paths in the terminal output
    assert "/users/nick/.ssh" not in result.stdout
    assert "/users/nick/birkin/.env" not in result.stdout


# ---------------------------------------------------------------------------
# privacy invariants on demo outputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["red.jsonl", "yellow.jsonl", "green.jsonl"])
def test_demo_outputs_never_leak_paths_or_prompts(fixture, tmp_path, monkeypatch):
    _run_cli(fixture, tmp_path, monkeypatch)
    blob = (tmp_path / "card.json").read_text() + (tmp_path / "card.svg").read_text()
    for secret_path in ("/users/nick/.ssh", "/users/nick/.aws", "/users/nick/birkin/.env",
                        "Downloads/agent-config", "bundle.tgz"):
        assert secret_path not in blob
    for marker in ("REDACTED", "PROMPT", "INSTRUCTIONS", "REASONING"):
        assert marker not in blob
