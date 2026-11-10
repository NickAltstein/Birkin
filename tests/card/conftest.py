"""Shared test configuration for tests/card.

Every test runs with the network forcibly disabled: the Trifecta Card is an
offline-only tool, and these tests prove it never opens a socket.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any attempt to create a socket fails the test."""

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted - receiptd card must be offline")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


@pytest.fixture
def claude_fixture():
    return FIXTURES / "sessions" / "claude_basic.jsonl"


@pytest.fixture
def codex_fixture():
    return FIXTURES / "sessions" / "codex_basic.jsonl"
