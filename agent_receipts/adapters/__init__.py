"""Birkin adapter registry."""

from .hermes import HermesAdapter
from .null_agent import NullAgentAdapter
from .grok_bot import GrokBotAdapter

__all__ = ["HermesAdapter", "NullAgentAdapter", "GrokBotAdapter"]
