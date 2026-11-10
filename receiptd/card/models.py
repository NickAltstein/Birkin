"""Core data model for the Trifecta Card.

Privacy rule baked into the model: a ToolCall may hold raw structured input
(command text, file path, URL, query) for classification purposes, but nothing
outside the classifier is ever allowed to render those fields. Evidence rows
(Hit) carry only: tool name, target (a *filename*, a *host*, or a program
token), timestamp, call index and the rule id that fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

CATEGORIES = ("PRIVATE", "UNTRUSTED", "EGRESS")

URL_HOST_RE = re.compile(r"https?://([^/\s:?#\"']+)")
USER_HOST_RE = re.compile(r"[\w.-]+@([A-Za-z0-9.-]+)(?=[\s:/\\)]|$)")


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation extracted from a session log."""

    index: int  # 0-based position within the session's call sequence
    tool: str  # e.g. "Bash", "Read", "shell", "mcp__github__create_issue"
    timestamp: Optional[str] = None
    file_path: Optional[str] = None
    command: Optional[str] = None
    url: Optional[str] = None
    query: Optional[str] = None  # search / fetch prompt - never rendered
    pattern: Optional[str] = None  # grep / glob pattern - never rendered
    description: Optional[str] = None
    server: Optional[str] = None  # MCP server name for mcp__<server>__<tool>
    source_format: str = "claude"  # "claude" | "codex"

    def hosts(self) -> list:
        """Hosts referenced by this call (from URL or user@host arguments)."""
        hosts = []
        for text in (self.url, self.command):
            if not text:
                continue
            for match in URL_HOST_RE.finditer(text):
                host = match.group(1)
                if host not in hosts:
                    hosts.append(host)
        if not hosts and self.command:
            match = USER_HOST_RE.search(" " + self.command + " ")
            if match:
                hosts.append(match.group(1))
        return hosts


@dataclass(frozen=True)
class Hit:
    """One classified rule hit. `target` is a filename, host or program token."""

    category: str  # one of CATEGORIES
    index: int
    tool: str
    target: str
    timestamp: Optional[str]
    rule: str
    is_path: bool = False  # target is a path component (hashable under --redact-paths)


@dataclass(frozen=True)
class SessionInfo:
    """Non-sensitive metadata about one analyzed session file."""

    source_format: str  # "claude" | "codex"
    file_name: str  # basename only, never the full path
    session_id: Optional[str]
    started: Optional[str]
    ended: Optional[str]
    tool_calls: int


@dataclass
class Report:
    """Aggregated result for one `receiptd card` run."""

    sessions: list = field(default_factory=list)  # list[SessionInfo]
    hits: list = field(default_factory=list)  # list[Hit]
    counts: dict = field(default_factory=lambda: {c: 0 for c in CATEGORIES})
    level: str = "GREEN"  # RED | YELLOW | GREEN
    ordered: bool = False
    rules_version: str = "0"
    redacted: bool = False

    def top_evidence(self, limit: int = 5) -> list:
        """Deterministic 'top' evidence: PRIVATE first, then UNTRUSTED, then
        EGRESS, each by call index; truncated to `limit`."""
        priority = {c: i for i, c in enumerate(CATEGORIES)}
        ordered_hits = sorted(self.hits, key=lambda h: (priority[h.category], h.index))
        return ordered_hits[:limit]
