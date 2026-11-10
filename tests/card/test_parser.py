"""Tests for the Claude Code / Codex session log parsers."""

from __future__ import annotations

import json
import os
import time

from receiptd.card.parser import (
    detect_format,
    discover_session_files,
    flatten_shell_command,
    parse_session_file,
    select_sessions,
)


# ---------------------------------------------------------------------------
# format detection
# ---------------------------------------------------------------------------


def test_detect_format_claude(claude_fixture):
    records = [json.loads(line) for line in claude_fixture.read_text().splitlines() if line]
    assert detect_format(records) == "claude"


def test_detect_format_codex(codex_fixture):
    records = [json.loads(line) for line in codex_fixture.read_text().splitlines() if line]
    assert detect_format(records) == "codex"


def test_detect_format_empty_records_falls_back_to_claude():
    assert detect_format([]) == "claude"


# ---------------------------------------------------------------------------
# Claude Code parsing
# ---------------------------------------------------------------------------


def test_claude_session_metadata(claude_fixture):
    session = parse_session_file(claude_fixture)
    assert session.source_format == "claude"
    assert session.file_name == "claude_basic.jsonl"
    assert session.session_id == "aa11aa11-1111-4111-8111-111111111111"
    assert session.started == "2026-11-09T10:00:00.000Z"
    assert session.ended == "2026-11-09T10:00:40.000Z"


def test_claude_extracts_tool_calls_with_sequential_indexes(claude_fixture):
    session = parse_session_file(claude_fixture)
    tools = [c.tool for c in session.calls]
    assert tools == [
        "Read",
        "WebFetch",
        "Bash",
        "Bash",
        "mcp__github__create_issue",
        "Read",
        "Grep",
        "Write",
    ]
    assert [c.index for c in session.calls] == list(range(len(session.calls)))


def test_claude_field_extraction(claude_fixture):
    session = parse_session_file(claude_fixture)
    read_env, webfetch, bash_curl, bash_cat, mcp, read_dl, grep, _write = session.calls
    assert read_env.file_path == "/users/nick/birkin/.env"
    assert webfetch.url == "https://api.example.com/status"
    assert webfetch.query == "[REDACTED FETCH PROMPT]"
    assert bash_curl.command == "curl -s https://api.example.com/data.json | jq .status"
    assert bash_cat.command.startswith("cat ~/.ssh/id_rsa")
    assert mcp.server == "github"
    assert read_dl.file_path == "/users/nick/Downloads/payload.bin"
    assert grep.pattern == "password"
    assert read_env.timestamp == "2026-11-09T10:00:05.000Z"


def test_claude_never_exposes_prompt_or_result_text(claude_fixture):
    """User prompts and tool results are never extracted. The WebFetch prompt
    lands in the internal `query` field (classification input only); renderer
    tests assert it never reaches any output."""
    session = parse_session_file(claude_fixture)
    blob = json.dumps([c.__dict__ for c in session.calls])
    assert "REDACTED USER PROMPT" not in blob
    assert "REDACTED RESULT" not in blob


def test_claude_malformed_lines_are_skipped(tmp_path):
    log = tmp_path / "mangled.jsonl"
    good = (
        '{"type":"assistant","timestamp":"2026-11-09T10:00:00.000Z","sessionId":"s1",'
        '"message":{"role":"assistant","content":[{"type":"tool_use","id":"t1",'
        '"name":"Bash","input":{"command":"ls"}}]}}'
    )
    log.write_text("not json at all\n\n" + good + "\n[]\n" + good.replace("ls", "pwd") + "\n")
    session = parse_session_file(log)
    assert [c.command for c in session.calls] == ["ls", "pwd"]


# ---------------------------------------------------------------------------
# Codex parsing
# ---------------------------------------------------------------------------


def test_codex_session_metadata(codex_fixture):
    session = parse_session_file(codex_fixture)
    assert session.source_format == "codex"
    assert session.file_name == "codex_basic.jsonl"
    assert session.session_id == "bb22bb22-2222-4222-8222-222222222222"
    assert session.started == "2026-11-08T09:00:00.000Z"
    assert session.ended == "2026-11-08T09:00:50.000Z"


def test_codex_extracts_function_calls_in_order(codex_fixture):
    session = parse_session_file(codex_fixture)
    assert [c.tool for c in session.calls] == [
        "shell",
        "shell",
        "shell",
        "read_file",
        "web_search",
        "shell",
        "apply_patch",
    ]
    assert [c.index for c in session.calls] == list(range(7))


def test_codex_shell_command_flattening(codex_fixture):
    session = parse_session_file(codex_fixture)
    ls, curl_pipe, curl_download, _read, _search, git_push, _patch = session.calls
    assert ls.command == "ls -la"
    assert curl_pipe.command == "curl -s https://api.example.com/feeds/latest.json | jq .status"
    assert curl_download.command.startswith("curl -o /users/nick/Downloads/notes.md")
    assert git_push.command == "git push origin main"


def test_codex_other_tool_fields(codex_fixture):
    session = parse_session_file(codex_fixture)
    _ls, _curl, _dl, read_file, web_search, _push, patch = session.calls
    assert read_file.file_path == "/users/nick/Downloads/notes.md"
    assert web_search.query == "[REDACTED QUERY]"
    assert patch.file_path == "src/app.py"


def test_flatten_shell_command_variants():
    assert flatten_shell_command({"command": ["bash", "-lc", "echo hi"]}) == "echo hi"
    assert flatten_shell_command({"command": ["sh", "-c", "echo hi"]}) == "echo hi"
    assert flatten_shell_command({"command": ["curl", "-s", "https://x.io"]}) == "curl -s https://x.io"
    assert flatten_shell_command({"command": "echo hi"}) == "echo hi"
    assert flatten_shell_command({"command": []}) == ""
    assert flatten_shell_command({}) == ""


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def _write_session(directory, name, content, mtime_offset):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    stamp = time.time() - mtime_offset
    os.utime(path, (stamp, stamp))
    return path


SIMPLE_CLAUDE_SESSION = (
    '{"type":"assistant","timestamp":"2026-11-01T10:00:00.000Z","sessionId":"s-%s",'
    '"message":{"role":"assistant","content":[{"type":"tool_use","id":"t1",'
    '"name":"Bash","input":{"command":"ls"}}]}}\n'
)


def test_discovery_finds_both_formats_newest_first(tmp_path):
    claude_dir = tmp_path / "claude" / "projects" / "-proj"
    codex_dir = tmp_path / "codex" / "sessions" / "2026" / "11" / "01"
    oldest = _write_session(claude_dir, "old.jsonl", SIMPLE_CLAUDE_SESSION % "old", 3000)
    newest = _write_session(codex_dir, "rollout-new.jsonl", SIMPLE_CLAUDE_SESSION % "new", 60)
    middle = _write_session(claude_dir, "mid.jsonl", SIMPLE_CLAUDE_SESSION % "mid", 500)

    found = discover_session_files(claude_dir, codex_dir)
    assert [p.name for p, _ in found] == [newest.name, middle.name, oldest.name]


def test_discovery_skips_missing_roots(tmp_path):
    assert discover_session_files(tmp_path / "nope", tmp_path / "also-nope") == []


def test_select_sessions_last_n(tmp_path):
    claude_dir = tmp_path / "claude"
    for i in range(3):
        _write_session(claude_dir, f"s{i}.jsonl", SIMPLE_CLAUDE_SESSION % i, 100 * (10 - i))
    paths = select_sessions(2, claude_dir=claude_dir, codex_dir=tmp_path / "none")
    assert len(paths) == 2
    # newest first: s2 was written with the smallest offset
    assert paths[0].name == "s2.jsonl"


def test_select_sessions_defaults_to_one(tmp_path):
    claude_dir = tmp_path / "claude"
    for i in range(3):
        _write_session(claude_dir, f"s{i}.jsonl", SIMPLE_CLAUDE_SESSION % i, 100 * (10 - i))
    assert len(select_sessions(None, claude_dir=claude_dir)) == 1


def test_discovery_env_overrides(tmp_path, monkeypatch):
    claude_root = tmp_path / "fakehome" / ".claude" / "projects"
    _write_session(claude_root, "only.jsonl", SIMPLE_CLAUDE_SESSION % "env", 10)
    monkeypatch.setenv("RECEIPTD_CLAUDE_DIR", str(claude_root))
    monkeypatch.setenv("RECEIPTD_CODEX_DIR", str(tmp_path / "fakehome" / ".codex"))
    from receiptd.card import parser

    assert parser.default_claude_dir() == claude_root
    found = parser.discover_session_files()
    assert [p.name for p, _ in found] == ["only.jsonl"]
