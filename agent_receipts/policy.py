"""
birkin.policy
============

The Birkin Policy Engine.

This is *not* a shell script. It is a structured rule evaluator that, given
a (tool, args) request, returns a :class:`PolicyDecision` containing the
``decision``, the ``policy`` (name@version), the ``rule`` id that fired, a
``risk_score`` in [0, 100], and a human-readable ``reason``.

Policy spec format
------------------
A policy is a JSON document::

    {
      "name": "default",
      "version": "1.0.0",
      "description": "...",
      "rules": [
        {
          "id": "shell.exec.deny",
          "match": {"tool": "shell.exec"},
          "decision": "deny",
          "risk_score": 90,
          "reason": "Shell execution forbidden by default policy"
        },
        ...
      ]
    }

Rule matching
-------------
Rules are evaluated top-down. The first rule whose ``match`` predicate
succeeds wins. ``match`` supports:

* ``tool``     — exact tool name (or list of names)
* ``args``     — dict of {arg_name: literal_value OR {"$in": [...]}}
* ``path_prefix`` — list of path prefixes; matched against ``args["path"]``
* ``host_in``  — list of host substrings; matched against ``args["url"]``
* ``runtime_in`` — list of runtime strings; matched against the identity

If no rule matches, the engine returns a synthetic default-deny decision
with ``risk_score=100`` so the run cannot proceed silently.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .crypto import sha256_hex, canonical_json
from .models import PolicyDecision


class PolicySpec:
    """In-memory representation of a loaded policy file."""

    def __init__(self, spec: dict[str, Any]) -> None:
        if "name" not in spec or "version" not in spec or "rules" not in spec:
            raise ValueError("Policy spec must have name, version, rules")
        self.name: str = spec["name"]
        self.version: str = spec["version"]
        self.description: str = spec.get("description", "")
        self.rules: list[dict[str, Any]] = spec["rules"]
        self._raw = spec

    # --- loading --------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "PolicySpec":
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    @classmethod
    def from_dict(cls, spec: dict[str, Any]) -> "PolicySpec":
        return cls(spec)

    # --- introspection --------------------------------------------------
    @property
    def ref(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def sha256(self) -> str:
        return sha256_hex(canonical_json(self._raw))

    def to_dict(self) -> dict[str, Any]:
        return self._raw

    # --- evaluation -----------------------------------------------------
    def evaluate(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        runtime: str | None = None,
        identity_public_key: str | None = None,
    ) -> PolicyDecision:
        args = args or {}
        for rule in self.rules:
            rule_decision = rule.get("decision", "deny")
            if _match_rule(
                rule.get("match", {}),
                tool=tool,
                args=args,
                runtime=runtime,
                decision=rule_decision,
            ):
                return PolicyDecision(
                    decision=rule_decision,
                    policy=self.ref,
                    rule=rule.get("id", "unnamed"),
                    risk_score=int(rule.get("risk_score", 100)),
                    reason=rule.get("reason", "Matched rule"),
                )
        # No rule matched. Default deny. We do NOT silently allow.
        return PolicyDecision(
            decision="deny",
            policy=self.ref,
            rule="default.no_match",
            risk_score=100,
            reason=f"No rule matched tool={tool!r} under policy {self.ref}",
        )


# --------------------------------------------------------------------------- #
# Matching primitives
# --------------------------------------------------------------------------- #
def _is_path_contained(
    candidate_path: Any,
    prefix_path: Any,
    *,
    decision_mode: str = "allow",
) -> bool:
    """Component-aware, symlink-aware filesystem containment check.

    Security Guarantees:
    - Path-component awareness: Prevents sibling-prefix collisions (e.g. /tmp/birkin-unsafe matching /tmp/birkin)
      by enforcing strict path-part ancestor relationships via Path.is_relative_to().
    - Domain boundary enforcement: Absolute policy prefixes require absolute candidate paths.
      Unanchored relative paths fail-closed against absolute security boundaries.
    - Canonical resolution: Evaluates both lexical boundaries (normalizing '..') and canonical
      filesystem targets via resolve() to neutralize symlink traversal escapes (e.g. /tmp/birkin/link_to_etc).
    - Mode-aware containment semantics:
      * For 'allow' decisions: requires BOTH lexical AND resolved targets to reside within the boundary.
      * For 'deny' (or 'require_approval') decisions: triggers if EITHER lexical OR resolved targets enter the restricted boundary.
    - Fails closed on null bytes, malformed paths, symlink cycles (RuntimeError), or resolution errors.

    Filesystem Race-Condition (TOCTOU) Limitations:
    Policy evaluation inspects path containment at check time. If symlinks or directory mounts
    are swapped concurrently by an untrusted actor between authorization and runtime access,
    a TOCTOU race can occur. Full mitigation requires atomic openat2(..., RESOLVE_BENEATH) or
    operating system namespace sandboxing at the execution runtime layer.
    """
    if not isinstance(candidate_path, str) or not isinstance(prefix_path, str):
        return False
    if not candidate_path.strip() or not prefix_path.strip():
        return False
    if "\x00" in candidate_path or "\x00" in prefix_path:
        return False

    try:
        cand_p = Path(candidate_path)
        pref_p = Path(prefix_path)

        # Domain boundary check: absolute prefix requires absolute candidate
        if pref_p.is_absolute() and not cand_p.is_absolute():
            return False
        if not pref_p.is_absolute() and cand_p.is_absolute():
            return False

        # Lexical component containment (catches sibling prefixes and raw .. escapes)
        norm_cand = Path(os.path.normpath(candidate_path))
        norm_pref = Path(os.path.normpath(prefix_path))
        lexical_match = norm_cand.is_relative_to(norm_pref)

        # Canonical resolved containment (resolves existing symlinks and normalizes paths)
        resolved_cand = cand_p.resolve()
        resolved_pref = pref_p.resolve()
        resolved_match = resolved_cand.is_relative_to(resolved_pref)

        if decision_mode == "allow":
            return lexical_match and resolved_match
        return lexical_match or resolved_match
    except (ValueError, TypeError, OSError, RuntimeError):
        return False


def _match_rule(
    match: dict[str, Any],
    *,
    tool: str,
    args: dict[str, Any],
    runtime: str | None,
    decision: str = "allow",
) -> bool:
    if not match:
        return True  # empty match = always matches (used for default rules)

    tool_match = match.get("tool")
    if tool_match is not None:
        if isinstance(tool_match, str):
            if tool != tool_match:
                return False
        elif isinstance(tool_match, list):
            if tool not in tool_match:
                return False
        else:
            return False

    runtime_match = match.get("runtime_in")
    if runtime_match is not None:
        if runtime is None or not any(r in runtime for r in runtime_match):
            return False

    args_match = match.get("args")
    if args_match is not None:
        for k, v in args_match.items():
            actual = args.get(k)
            if isinstance(v, dict) and "$in" in v:
                if actual not in v["$in"]:
                    return False
            else:
                if actual != v:
                    return False

    path_prefix = match.get("path_prefix")
    if path_prefix is not None:
        raw_path = args.get("path")
        if not isinstance(raw_path, str):
            return False
        if not any(_is_path_contained(raw_path, p, decision_mode=decision) for p in path_prefix):
            return False

    host_in = match.get("host_in")
    if host_in is not None:
        url = args.get("url", "") or ""
        try:
            from urllib.parse import urlparse
            parsed_host = (urlparse(url).hostname or "").lower()
            if not any(h.lower() == parsed_host or parsed_host.endswith("." + h.lower()) for h in host_in):
                return False
        except Exception:
            return False

    # Negative matchers (allow-list / deny-list)
    path_not_prefix = match.get("path_not_prefix")
    if path_not_prefix is not None:
        raw_path = args.get("path", "")
        if not isinstance(raw_path, str):
            return False
        if any(_is_path_contained(raw_path, p, decision_mode="deny") for p in path_not_prefix):
            return False

    return True


# --------------------------------------------------------------------------- #
# Helper: ensure policy dir exists
# --------------------------------------------------------------------------- #
DEFAULT_POLICY_PATH = os.environ.get(
    "BIRKIN_POLICY",
    str(Path(__file__).resolve().parent.parent / "policies" / "default.policy.json"),
)


def load_default_policy() -> PolicySpec:
    return PolicySpec.load(DEFAULT_POLICY_PATH)


__all__ = ["PolicySpec", "PolicyDecision", "DEFAULT_POLICY_PATH", "load_default_policy"]
