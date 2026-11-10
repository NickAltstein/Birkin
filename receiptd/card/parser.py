"""Parsers for Claude Code and Codex session logs (.jsonl).

Supported schemas (both observed in the wild; this machine has neither, so the
parsers are exercised through fixtures in tests/fixtures/sessions/):

Claude Code - ~/.claude/projects/<sanitized-cwd>/<session-uuid>.jsonl
    One JSON object per line:
      {"type": "user"|"assistant"|"summary"|"system",
       "uuid": ..., "parentUuid": ..., "sessionId": ..., "cwd": ...,
       "version": ..., "gitBranch": ..., "isSidechain": false,
       "timestamp": "2026-11-09T10:00:00.000Z",
       "message": {"role": "assistant",
                   "content": [{"type": "tool_use", "id": "toolu_...",
                                "name": "Bash",
                                "input": {"command": "...", ...}}]}}
    Tool names seen: Bash, Read, Write, Edit, Glob, Grep, WebFetch,
    WebSearch, Task, TodoWrite, NotebookEdit, mcp__<server>__<tool>.

Codex CLI - ~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl
    One JSON object per line with an envelope:
      {"timestamp": "...", "type": "session_meta"|"response_item"|"event_msg"
                        |"turn_context"|"compacted",
       "payload": {...}}
    Tool calls are response_item payloads of type "function_call":
      {"type": "function_call", "name": "shell", "call_id": "call_...",
       "arguments": "{\"command\": [\"bash\", \"-lc\", \"curl ... \"]}"}
    Tool names seen: shell, apply_patch, view_image, web_search, read_file,
    plus MCP / custom function names.

Neither parser ever returns prompt text, tool results or file contents: only
the structured fields needed for classification.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from receiptd.card.models import ToolCall

CODEX_LINE_TYPES = {
    "session_meta",
    "response_item",
    "event_msg",
    "turn_context",
    "compacted",
}

CLAUDE_LINE_TYPES = {"user", "assistant", "summary", "system"}

SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh"}

PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", re.MULTILINE)


@dataclass(frozen=True)
class ParsedSession:
    source_format: str  # "claude" | "codex"
    file_name: str
    session_id: Optional[str]
    started: Optional[str]
    ended: Optional[str]
    calls: list  # list[ToolCall]


# ---------------------------------------------------------------------------
# loading helpers
# ---------------------------------------------------------------------------


def _load_records(path):
    """Parse a .jsonl file into a list of dicts; malformed lines are skipped."""
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def detect_format(records):
    """Detect the log flavor from the first records that identify themselves."""
    for record in records[:100]:
        line_type = record.get("type") or record.get("record_type")
        if line_type in CODEX_LINE_TYPES:
            return "codex"
        if line_type in CLAUDE_LINE_TYPES and "message" in record:
            return "claude"
    return "claude"  # conservative fallback


def parse_session_file(path):
    """Parse one session log; format is auto-detected per file."""
    path = Path(path)
    records = _load_records(path)
    fmt = detect_format(records)
    if fmt == "codex":
        return _parse_codex(records, path)
    return _parse_claude(records, path)


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


def _parse_claude(records, path):
    calls = []
    session_id = None
    timestamps = []
    for record in records:
        ts = record.get("timestamp")
        if isinstance(ts, str) and ts:
            timestamps.append(ts)
        if session_id is None and record.get("sessionId"):
            session_id = str(record["sessionId"])
        if record.get("type") != "assistant":
            continue
        message = record.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            calls.append(
                _claude_tool_call(block.get("name"), block.get("input"), ts, len(calls))
            )
    return ParsedSession(
        source_format="claude",
        file_name=path.name,
        session_id=session_id,
        started=min(timestamps) if timestamps else None,
        ended=max(timestamps) if timestamps else None,
        calls=calls,
    )


def _claude_tool_call(name, raw_input, ts, index):
    name = str(name or "unknown")
    fields = {"index": index, "tool": name, "timestamp": ts, "source_format": "claude"}
    inp = raw_input if isinstance(raw_input, dict) else {}
    if name == "Bash":
        fields["command"] = _as_str(inp.get("command"))
        fields["description"] = _as_str(inp.get("description"))
    elif name in ("Read", "Write", "Edit", "NotebookEdit"):
        fields["file_path"] = _as_str(inp.get("file_path") or inp.get("notebook_path"))
    elif name in ("Glob", "Grep"):
        fields["file_path"] = _as_str(inp.get("path"))
        fields["pattern"] = _as_str(inp.get("pattern"))
    elif name == "WebFetch":
        fields["url"] = _as_str(inp.get("url"))
        fields["query"] = _as_str(inp.get("prompt"))
    elif name == "WebSearch":
        fields["query"] = _as_str(inp.get("query"))
    elif name.startswith("mcp__"):
        parts = name.split("__")
        fields["server"] = parts[1] if len(parts) >= 3 else None
        fields["description"] = _as_str(inp.get("description"))
    else:
        # Unknown / future tool: pick up the common structured fields only.
        fields["file_path"] = _as_str(inp.get("file_path") or inp.get("path"))
        fields["command"] = _as_str(inp.get("command"))
        fields["url"] = _as_str(inp.get("url"))
        fields["query"] = _as_str(inp.get("query"))
        fields["description"] = _as_str(inp.get("description"))
    return ToolCall(**fields)


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------


def _parse_codex(records, path):
    calls = []
    session_id = None
    timestamps = []
    for record in records:
        ts = record.get("timestamp")
        if isinstance(ts, str) and ts:
            timestamps.append(ts)
        line_type = record.get("type") or record.get("record_type")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        if line_type == "session_meta" and not session_id:
            session_id = payload.get("id") or session_id
        if line_type != "response_item" or payload.get("type") != "function_call":
            continue
        calls.append(
            _codex_tool_call(payload.get("name"), payload.get("arguments"), ts, len(calls))
        )
    return ParsedSession(
        source_format="codex",
        file_name=path.name,
        session_id=session_id,
        started=min(timestamps) if timestamps else None,
        ended=max(timestamps) if timestamps else None,
        calls=calls,
    )


def _codex_tool_call(name, raw_arguments, ts, index):
    name = str(name or "unknown")
    args = raw_arguments
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    if not isinstance(args, dict):
        args = {}
    fields = {"index": index, "tool": name, "timestamp": ts, "source_format": "codex"}
    if name in ("shell", "bash", "local_shell", "unified_exec", "exec_command"):
        fields["command"] = flatten_shell_command(args)
        fields["description"] = _as_str(args.get("description"))
    elif name == "apply_patch":
        patch = _as_str(args.get("input") or args.get("patch"))
        fields["file_path"] = "\n".join(PATCH_FILE_RE.findall(patch))
    elif name in ("web_search", "websearch"):
        fields["query"] = _as_str(args.get("query"))
    elif name in ("view_image", "read_file", "open_file"):
        fields["file_path"] = _as_str(
            args.get("path") or args.get("file_path") or args.get("abs_path")
        )
    else:
        command = args.get("command")
        fields["file_path"] = _as_str(args.get("file_path") or args.get("path"))
        fields["command"] = command if isinstance(command, str) else None
        fields["url"] = _as_str(args.get("url"))
        fields["query"] = _as_str(args.get("query"))
        fields["description"] = _as_str(args.get("description"))
    return ToolCall(**fields)


def flatten_shell_command(args):
    """Codex shell arguments arrive as e.g. ["bash", "-lc", "<command>"]."""
    cmd = args.get("command")
    if cmd is None:
        cmd = args.get("cmd")
    if isinstance(cmd, str):
        return cmd
    if isinstance(cmd, list):
        tokens = [str(t) for t in cmd]
        if tokens and os.path.basename(tokens[0]) in SHELL_INTERPRETERS:
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                tokens = tokens[1:]
        return " ".join(tokens)
    return ""


def _as_str(value):
    return value if isinstance(value, str) and value else None


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def default_claude_dir():
    override = os.environ.get("RECEIPTD_CLAUDE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".claude" / "projects"


def default_codex_dir():
    override = os.environ.get("RECEIPTD_CODEX_DIR")
    if override:
        return Path(override)
    return Path.home() / ".codex" / "sessions"


def discover_session_files(claude_dir=None, codex_dir=None):
    """All session logs found under both roots, newest first.

    Returns a list of (path, mtime) tuples. Missing roots are skipped silently.
    """
    found = []
    roots = (
        Path(claude_dir) if claude_dir is not None else default_claude_dir(),
        Path(codex_dir) if codex_dir is not None else default_codex_dir(),
    )
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*.jsonl"):
            if path.is_file():
                found.append((path, path.stat().st_mtime))
    found.sort(key=lambda item: (item[1], str(item[0])), reverse=True)
    return found


def select_sessions(last_n, claude_dir=None, codex_dir=None):
    """The `last_n` most recent session files across both formats."""
    if last_n is None:
        last_n = 1
    last_n = max(0, int(last_n))
    return [path for path, _mtime in discover_session_files(claude_dir, codex_dir)[:last_n]]
