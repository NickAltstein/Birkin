"""Pipeline: session logs -> classified Report (pure, no rendering)."""

from __future__ import annotations

from pathlib import Path

from receiptd.card.classifier import classify_session, load_rules
from receiptd.card.parser import parse_session_file, select_sessions
from receiptd.card.redact import redact_hits
from receiptd.card.verdict import build_report


def analyze_paths(paths, redacted=False, rules=None):
    """Analyze explicit .jsonl session files into one Report."""
    if rules is None:
        rules = load_rules()
    sessions = []
    hits = []
    for raw in paths:
        path = Path(raw)
        parsed = parse_session_file(path)
        sessions.append(parsed)
        hits.extend(classify_session(parsed.calls, rules))
    if redacted:
        hits = redact_hits(hits)
    return build_report(sessions, hits, redacted=redacted, rules=rules)


def analyze_last(last_n, redacted=False, rules=None, claude_dir=None, codex_dir=None):
    """Analyze the N most recent sessions found on this machine."""
    paths = select_sessions(last_n, claude_dir=claude_dir, codex_dir=codex_dir)
    if not paths:
        raise FileNotFoundError(
            "no session logs found (looked in ~/.claude/projects and ~/.codex/sessions); "
            "pass --session <path> to analyze a specific .jsonl file"
        )
    return analyze_paths(paths, redacted=redacted, rules=rules)
