"""
birkin.adapters.hermes
======================

Hermes adapter — the first concrete :class:`AgentAdapter`.

Hermes is treated here as a tool registry. The runtime surfaces a small set
of tools to the agent (``shell.exec``, ``fs.write``, ``http.get``,
``http.post``, ``db.query``), and Birkin gates every invocation through the
policy engine + signed receipt flow.

This is deliberately minimal: it shows the seam. A production Hermes
adapter would plug into the real Hermes tool dispatch loop instead of this
in-process registry, but the contract with Birkin does not change.
"""

from __future__ import annotations

from typing import Any, Callable

from ..adapter import BaseAdapter, ActionResult
from ..models import AuthorizationReceipt


# Tool handlers: name -> callable(args) -> (ok, output_or_error)
ToolHandler = Callable[[dict[str, Any]], tuple[bool, Any]]


def _tool_fs_write(args: dict[str, Any]) -> tuple[bool, Any]:
    path = args.get("path", "")
    data = args.get("data", "")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(str(data))
        return True, f"wrote {len(str(data))} bytes to {path}"
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


def _tool_fs_read(args: dict[str, Any]) -> tuple[bool, Any]:
    path = args.get("path", "")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return True, fh.read()
    except Exception as exc:
        return False, str(exc)


def _tool_http_get(args: dict[str, Any]) -> tuple[bool, Any]:
    url = args.get("url", "")
    # Simulated HTTP GET — we do not actually network in this slice, but the
    # call is real and the receipt is real.
    return True, {"status": 200, "url": url, "body": "<simulated 200 OK>"}


def _tool_http_post(args: dict[str, Any]) -> tuple[bool, Any]:
    url = args.get("url", "")
    body = args.get("body", "")
    return True, {"status": 201, "url": url, "echo": str(body)[:200]}


def _tool_db_query(args: dict[str, Any]) -> tuple[bool, Any]:
    sql = args.get("sql", "")
    # Simulated DB. The point is that the receipt is real and the policy
    # decision is real.
    if "DROP" in sql.upper():
        return False, "refused: DROP statements are blocked"
    return True, {"rows": [], "sql": sql}


def _tool_shell_exec(args: dict[str, Any]) -> tuple[bool, Any]:
    cmd = args.get("cmd", "")
    # Hermes registry always *can* run shell, but policy denies it by
    # default. If a policy ever allowed it, we'd actually shell out here.
    import subprocess

    try:
        out = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return out.returncode == 0, out.stdout + out.stderr
    except Exception as exc:
        return False, str(exc)


class HermesAdapter(BaseAdapter):
    """Hermes runtime adapter."""

    name: str = "hermes"
    version: str = "0.1.0"

    def __init__(self, agent_signing_key=None) -> None:
        super().__init__(agent_signing_key=agent_signing_key)
        self._tools: dict[str, ToolHandler] = {
            "fs.write": _tool_fs_write,
            "fs.read": _tool_fs_read,
            "http.get": _tool_http_get,
            "http.post": _tool_http_post,
            "db.query": _tool_db_query,
            "shell.exec": _tool_shell_exec,
        }

    def known_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def execute(self, identity, request, receipt: AuthorizationReceipt) -> ActionResult:
        """Execute the action iff the receipt permits it.

        The receipt is the ground truth. The adapter MUST refuse to execute
        if the receipt's decision is not ``"allow"``. This is the
        invariant that makes the receipt meaningful as a primitive.
        """
        if receipt.decision != "allow":
            return ActionResult(
                ok=False,
                error=f"refused by receipt {receipt.receipt_id}: decision={receipt.decision}",
                side_effect_recorded=False,
            )

        handler = self._tools.get(request.tool)
        if handler is None:
            return ActionResult(
                ok=False,
                error=f"unknown tool: {request.tool}",
                side_effect_recorded=False,
            )

        ok, out = handler(request.args)
        return ActionResult(
            ok=ok,
            output=out if ok else None,
            error="" if ok else str(out),
            side_effect_recorded=ok,
        )


__all__ = ["HermesAdapter"]
