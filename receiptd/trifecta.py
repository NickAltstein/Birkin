"""Backward-compatibility wrapper for receiptd.card."""
from __future__ import annotations

from receiptd.card.pipeline import analyze_last as scan_agent_logs
from receiptd.card.render_terminal import render_terminal as render_terminal_card
from receiptd.card.render_card import render_card_png as render_png_card

__all__ = ["scan_agent_logs", "render_terminal_card", "render_png_card"]
