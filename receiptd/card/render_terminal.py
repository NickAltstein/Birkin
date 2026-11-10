"""Colored terminal renderer for the Trifecta Card."""

from __future__ import annotations

import os
import sys

from receiptd.card.models import CATEGORIES, Report

# ANSI colors (disabled automatically when not a TTY or NO_COLOR is set).
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"

LEVEL_COLOR = {"RED": RED, "YELLOW": YELLOW, "GREEN": GREEN}
LEVEL_TITLE = {"RED": "LETHAL TRIFECTA", "YELLOW": "2 OF 3", "GREEN": "CLEAN"}

CATEGORY_LABELS = {
    "PRIVATE": "private data read",
    "UNTRUSTED": "untrusted input",
    "EGRESS": "egress",
}


def _colors_enabled(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def render_terminal(report: Report, stream=None, card_json_name: str = "card.json") -> str:
    """Render the full terminal summary; returns the text (uncolored when
    colors are disabled)."""
    stream = stream or sys.stdout
    color = _colors_enabled(stream)

    def paint(text, *codes):
        if not color:
            return text
        return "".join(codes) + text + RESET

    lines = []
    lines.append("")
    # Huge verdict line.
    verdict_color = LEVEL_COLOR[report.level]
    title = LEVEL_TITLE[report.level]
    lines.append(paint(f"  ██ {title} ██", BOLD, verdict_color))
    lines.append(paint(f"  verdict: {report.level}", BOLD, verdict_color))
    if report.ordered:
        lines.append(paint("  ⚠ ORDERED: private read + untrusted input preceded egress", BOLD, RED))
    lines.append("")

    # Three category rows with check/cross marks and counts.
    for category in CATEGORIES:
        count = report.counts[category]
        mark = paint("✗" if count else "✓", BOLD, RED if count else GREEN)
        label = CATEGORY_LABELS[category]
        lines.append(f"  {mark}  {label.ljust(18)} {count}")
    lines.append("")

    # Top 5 evidence items.
    top = report.top_evidence(5)
    if top:
        lines.append(paint("  top evidence:", BOLD, WHITE))
        for hit in top:
            where = hit.target
            when = (hit.timestamp or "")[:19].replace("T", " ")
            lines.append(
                f"    {paint(hit.category, BOLD, LEVEL_COLOR.get('RED'))} "
                f"{hit.tool}  {paint(where, CYAN)}  #{hit.index}  {when}"
            )
        lines.append("")

    # Session metadata (basename + ids only - never full paths).
    for s in report.sessions:
        started = (s.started or "")[:10]
        lines.append(
            paint(
                f"  session: {s.file_name} ({s.source_format})  {started}  "
                f"{s.tool_calls} tool calls",
                DIM,
            )
        )
    lines.append("")

    # The exact verify command.
    lines.append(paint(f"  verify: receiptd verify-card {card_json_name}", DIM))
    lines.append("")

    text = "\n".join(lines)
    stream.write(text + "\n")
    return text
