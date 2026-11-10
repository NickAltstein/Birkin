"""
birkin.adapters.grok_bot
========================

Grok Bot adapter — implements AgentAdapter for agents running in the
Grok Bot environment (or any similar tool-using agent).

The adapter does not call the real tools itself. It only decides whether
a receipt permits the call. The actual tool execution is performed by the
host (the Grok Bot runtime or your own code) *after* it receives an
allow receipt.

This keeps Birkin as a pure authorization + evidence plane.
"""

from __future__ import annotations

from typing import Any

from ..adapter import BaseAdapter, ActionResult
from ..models import AuthorizationReceipt


class GrokBotAdapter(BaseAdapter):
    """Adapter for Grok Bots / similar tool-using agents."""

    name: str = "grok-bot"
    version: str = "0.1.0"

    # Tools that a typical Grok Bot is expected to expose.
    # The host is responsible for the real implementation.
    KNOWN_TOOLS = [
        "web_search",
        "browse_page",
        "bash",
        "read_file",
        "write_file",
        "edit_file",
        "places_search",
        "weather_forecast",
        "x_keyword_search",
        "generate_image",
    ]

    def known_tools(self) -> list[str]:
        return sorted(self.KNOWN_TOOLS)

    def execute(
        self,
        identity,
        request,
        receipt: AuthorizationReceipt,
    ) -> ActionResult:
        """Refuse to execute unless the receipt says allow.

        The real tool call happens outside this method. This method only
        records that the host is allowed to proceed.
        """
        if receipt.decision != "allow":
            return ActionResult(
                ok=False,
                error=f"refused by receipt {receipt.receipt_id}: decision={receipt.decision}",
                side_effect_recorded=False,
            )

        # We do not execute the tool here. The host does, after seeing the allow.
        return ActionResult(
            ok=True,
            output={"note": "receipt allows execution; host should perform the tool call"},
            side_effect_recorded=False,
        )


__all__ = ["GrokBotAdapter"]
