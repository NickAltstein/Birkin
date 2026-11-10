"""Verdict and ordering logic for the Trifecta Card.

Verdict:
    RED    - all three categories present (private + untrusted + egress)
    YELLOW - exactly two categories present
    GREEN  - zero or one category present

Ordered flag: a PRIVATE read and an UNTRUSTED input both occur strictly
before an EGRESS call within the same session - the classic kill-chain
sequence (read secrets, ingest attacker data, phone home).
"""

from __future__ import annotations

from receiptd.card.classifier import rules_version
from receiptd.card.models import CATEGORIES, Hit, Report, SessionInfo


def verdict_level(counts):
    """GREEN / YELLOW / RED from per-category hit counts."""
    present = sum(1 for c in CATEGORIES if counts.get(c, 0) > 0)
    if present == 3:
        return "RED"
    if present == 2:
        return "YELLOW"
    return "GREEN"


def is_ordered(hits):
    """True when a PRIVATE and an UNTRUSTED hit both precede an EGRESS hit.

    Comparison is by call index; ties (same call index, e.g. one Bash call that
    both reads .env and curls it out) count as "before" only if strictly
    smaller. Zero EGRESS hits -> False.
    """
    egress_indexes = [h.index for h in hits if h.category == "EGRESS"]
    if not egress_indexes:
        return False
    first_egress = min(egress_indexes)
    has_private_before = any(
        h.category == "PRIVATE" and h.index < first_egress for h in hits
    )
    has_untrusted_before = any(
        h.category == "UNTRUSTED" and h.index < first_egress for h in hits
    )
    return has_private_before and has_untrusted_before


def build_report(sessions, hits, redacted=False, rules=None) -> Report:
    """Assemble the final Report from parsed sessions and classified hits.

    `sessions` is a list of ParsedSession; `hits` the combined Hit list.
    """
    counts = {c: 0 for c in CATEGORIES}
    for hit in hits:
        counts[hit.category] = counts.get(hit.category, 0) + 1
    session_infos = [
        SessionInfo(
            source_format=s.source_format,
            file_name=s.file_name,
            session_id=s.session_id,
            started=s.started,
            ended=s.ended,
            tool_calls=len(s.calls),
        )
        for s in sessions
    ]
    report = Report(
        sessions=session_infos,
        hits=list(hits),
        counts=counts,
        level=verdict_level(counts),
        ordered=is_ordered(hits),
        rules_version=rules_version(rules) if rules else "0",
        redacted=redacted,
    )
    return report
