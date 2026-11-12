#!/usr/bin/env python3
"""
Receiptd Deterministic PreToolUse Gate for Claude Code.
Reads tool invocation JSON from stdin.
Exit 0 -> Tool allowed + signed Ed25519 receipt appended.
Exit 2 -> Tool HARD BLOCKED (fail-closed) + signed rejection receipt emitted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..crypto import (
    SigningKey,
    canonical_json,
    get_signing_key,
)
from ..ledger import (
    GENESIS_HASH,
    append_ledger_entry,
    build_signed_checkpoint,
    build_signed_receipt,
    build_unsigned_signing_error_receipt,
    lock_ledger,
    read_ledger_state,
    record_ledger_anchor,
)

# Shipped default. The hook reads this file once and both evaluates and hashes those bytes.
POLICY_FORMAT = "receiptd.pretooluse.v1"
_DEFAULT_POLICY_NAME = "default_pretooluse.policy.json"


class PolicyLoadError(Exception):
    """The policy file cannot be enforced. kind is missing, unreadable, or invalid."""

    def __init__(self, kind: str, message: str, raw: bytes | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.raw = raw

    @property
    def rule_id(self) -> str:
        return f"POLICY_{self.kind.upper()}"

    @property
    def reason(self) -> str:
        return f"receiptd: policy {self.kind}"


@dataclass(frozen=True)
class HookRule:
    id: str
    weight: int
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class HookPolicy:
    base_score: int
    deny_at: int
    rules: tuple[HookRule, ...]


def default_policy_path() -> Path:
    """Path of the packaged default policy. The file bytes are the policy."""
    return Path(__file__).resolve().parent / _DEFAULT_POLICY_NAME


def _require_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < 0 or value > 100:
        raise ValueError(f"{name} must be from 0 to 100")
    return value


def parse_policy(data: bytes) -> HookPolicy:
    """Parse a PreToolUse policy from the exact bytes that will be hashed."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("policy is not UTF-8") from exc
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("policy is not JSON") from exc
    if not isinstance(spec, dict):
        raise ValueError("policy must be a JSON object")
    if spec.get("format") != POLICY_FORMAT:
        raise ValueError(f"policy format must be {POLICY_FORMAT}")
    base_score = _require_int(spec.get("base_score"), "base_score")
    deny_at = _require_int(spec.get("deny_at"), "deny_at")
    raw_rules = spec.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("policy rules must be a list")
    rules: list[HookRule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise ValueError(f"rule {index} must be an object")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError(f"rule {index} id must be a non-empty string")
        weight = _require_int(raw.get("weight"), f"rule {index} weight")
        pattern = raw.get("pattern")
        if not isinstance(pattern, str):
            raise ValueError(f"rule {index} pattern must be a string")
        ignore_case = raw.get("ignore_case")
        if not isinstance(ignore_case, bool):
            raise ValueError(f"rule {index} ignore_case must be a boolean")
        flags = re.IGNORECASE if ignore_case else 0
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise ValueError(f"rule {index} pattern is not a valid regex") from exc
        rules.append(HookRule(id=rule_id, weight=weight, pattern=compiled))
    return HookPolicy(base_score=base_score, deny_at=deny_at, rules=tuple(rules))


def load_policy_file(path: Path) -> tuple[bytes, HookPolicy]:
    """Read path once. The returned bytes are the hash preimage and the parsed rules."""
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise PolicyLoadError("missing", f"policy file not found: {path}") from exc
    except OSError as exc:
        raise PolicyLoadError("unreadable", f"policy file unreadable: {path}: {exc}") from exc
    try:
        policy = parse_policy(data)
    except ValueError as exc:
        raise PolicyLoadError("invalid", f"invalid policy: {exc}", raw=data) from exc
    return data, policy


def policy_path_from_argv(argv: list[str]) -> Path:
    """Return --policy PATH, or the packaged default when the flag is absent."""
    for index, arg in enumerate(argv):
        if arg != "--policy":
            continue
        if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith("--"):
            raise PolicyLoadError("missing", "--policy requires a path")
        return Path(argv[index + 1])
    return default_policy_path()


def load_policy_from_argv(argv: list[str]) -> tuple[HookPolicy | None, str, PolicyLoadError | None]:
    """Load the policy for this process from a single read of one path."""
    try:
        path = policy_path_from_argv(argv)
    except PolicyLoadError as exc:
        return None, "", exc
    try:
        data, policy = load_policy_file(path)
    except PolicyLoadError as exc:
        digest = sha256_hex(exc.raw) if exc.raw is not None else ""
        return None, digest, exc
    return policy, sha256_hex(data), None


# Hook deadline. Claude Code lets the tool call through when a PreToolUse hook
# times out, so the gate must decide (and exit 2) before that can happen.
# Keep the deadline below the hook "timeout" written by `receiptd init`.
DEFAULT_DEADLINE_MS = 5000
MIN_DEADLINE_MS = 100
MAX_DEADLINE_MS = 30000
# After the deadline fires, the watchdog gets this long to write a deny
# receipt before the process is killed with exit 2 regardless.
DEADLINE_GRACE_S = 1.0

# Held for every ledger write so the watchdog never cuts a write in half.
_LEDGER_LOCK = threading.Lock()
# What the watchdog needs to write a deny receipt. "finished" is set under
# _LEDGER_LOCK in the same block as the final ledger write.
_CTX: dict = {"finished": False}


def resolve_deadline_ms(environ=None) -> int:
    """Read RECEIPTD_HOOK_DEADLINE_MS, clamped. Bad values use the default."""
    environ = os.environ if environ is None else environ
    raw = environ.get("RECEIPTD_HOOK_DEADLINE_MS")
    if raw is None:
        return DEFAULT_DEADLINE_MS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_DEADLINE_MS
    return max(MIN_DEADLINE_MS, min(MAX_DEADLINE_MS, value))


def _resolve_ledger_path(argv: list[str]) -> str:
    ledger_path = ".receiptd/receipts.jsonl"
    for i, arg in enumerate(argv):
        if arg == "--ledger" and i + 1 < len(argv):
            ledger_path = argv[i + 1]
            break
    if not os.path.exists(ledger_path) and os.path.exists(".birkin/receipts.jsonl"):
        ledger_path = ".birkin/receipts.jsonl"
    return ledger_path


def _write_deadline_receipt(deadline_ms: int) -> None:
    """Append an unsigned deny receipt. Unsigned because key loading may be what hung."""
    ledger_path = _CTX["ledger_path"]
    with lock_ledger(ledger_path):
        prev_hash, _, receipt_count, _, _ = read_ledger_state(ledger_path)
        tool_input = _CTX.get("tool_input", {})
        receipt = build_unsigned_signing_error_receipt(
            v=1,
            seq=receipt_count + 1,
            ts=datetime.now(timezone.utc).isoformat(),
            session_id=_CTX.get("session_id", "default"),
            tool=_CTX.get("tool_name", ""),
            args_sha256=sha256_hex(canonical_json(tool_input)),
            decision="deny",
            rule_ids=["HOOK_DEADLINE_EXCEEDED"],
            blast_radius=100,
            reason=f"receiptd: hook deadline exceeded ({deadline_ms}ms)",
            policy_sha256=_CTX.get("policy_sha256", ""),
            prev_hash=prev_hash,
            extra_fields={"latency_ms": deadline_ms, "tool_input": tool_input},
        )
        append_ledger_entry(ledger_path, receipt)
        record_ledger_anchor(receipt["seq"], receipt["hash"], ledger_path=ledger_path)


def _on_deadline(deadline_ms: int) -> None:
    """Watchdog: deny when the gate has not decided in time."""
    killer = threading.Timer(DEADLINE_GRACE_S, os._exit, args=(2,))
    killer.daemon = True
    killer.start()
    try:
        if _LEDGER_LOCK.acquire(timeout=DEADLINE_GRACE_S / 2):
            if _CTX["finished"]:
                # The gate decided and recorded it just in time; let it return.
                killer.cancel()
                _LEDGER_LOCK.release()
                return
            sys.stderr.write(
                f"[RECEIPTD FAIL-CLOSED] Hook exceeded {deadline_ms}ms deadline; denying.\n"
            )
            sys.stderr.flush()
            if _CTX.get("ledger_path"):
                _write_deadline_receipt(deadline_ms)
        else:
            sys.stderr.write(
                f"[RECEIPTD FAIL-CLOSED] Hook exceeded {deadline_ms}ms deadline; denying.\n"
            )
            sys.stderr.flush()
    except Exception:
        pass
    os._exit(2)


def canonicalize_jcs(obj) -> str:
    """Deterministic canonical JSON serialization (sorted keys, compact)."""
    return canonical_json(obj).decode("utf-8")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def evaluate_payload(payload: dict, policy: HookPolicy | None = None) -> tuple[bool, int, list[str]]:
    """Score one tool call with the given policy. The default is the packaged file."""
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return True, 100, ["MISSING_REQUIRED_FIELD"]

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return True, 100, ["MISSING_REQUIRED_FIELD"]

    if policy is None:
        try:
            _, policy = load_policy_file(default_policy_path())
        except PolicyLoadError as exc:
            return True, 100, [exc.rule_id]

    tool_name = tool_name.strip()
    combined = f"{tool_name} {canonicalize_jcs(tool_input)}"

    score = policy.base_score
    triggered = []
    for rule in policy.rules:
        if rule.pattern.search(combined):
            score = min(100, score + rule.weight)
            triggered.append(rule.id)

    # Any matched rule denies. POL-03 matches edits to .claude/settings.json.
    blocked = len(triggered) > 0 or score >= policy.deny_at
    return blocked, score, triggered


def main() -> int:
    deadline_ms = resolve_deadline_ms()
    _CTX.clear()
    _CTX["finished"] = False
    watchdog = threading.Timer(deadline_ms / 1000.0, _on_deadline, args=(deadline_ms,))
    watchdog.daemon = True
    watchdog.start()
    try:
        return _run()
    finally:
        if _LEDGER_LOCK.acquire(timeout=DEADLINE_GRACE_S):
            _CTX["finished"] = True
            _LEDGER_LOCK.release()
        watchdog.cancel()


def _run() -> int:
    t0 = time.perf_counter()
    try:
        _CTX["ledger_path"] = _resolve_ledger_path(sys.argv)
        # One read of one path. The digest and the rules both come from those bytes.
        policy, policy_sha256, policy_error = load_policy_from_argv(sys.argv)
        if policy is None and policy_error is None:
            policy_error = PolicyLoadError("invalid", "policy did not load")
        _CTX["policy_sha256"] = policy_sha256

        raw_stdin = sys.stdin.read()
        if not raw_stdin.strip():
            sys.stderr.write("[RECEIPTD FAIL-CLOSED] Empty stdin frame rejected.\n")
            return 2

        payload = json.loads(raw_stdin)
        if not isinstance(payload, dict):
            sys.stderr.write("[RECEIPTD FAIL-CLOSED] Payload must be a JSON object.\n")
            return 2

        if policy is None:
            assert policy_error is not None
            blocked, score, triggered = True, 100, [policy_error.rule_id]
            decision = "deny"
            reason = policy_error.reason
            sys.stderr.write(f"[RECEIPTD FAIL-CLOSED] {policy_error}\n")
        else:
            blocked, score, triggered = evaluate_payload(payload, policy)
            decision = "deny" if blocked else "allow"
            reason = f"triggered rules: {', '.join(triggered)}" if blocked else "allowed"

        ledger_path = _CTX["ledger_path"]

        # Checkpoint interval
        checkpoint_interval = 100
        for i, arg in enumerate(sys.argv):
            if arg == "--checkpoint-interval" and i + 1 < len(sys.argv):
                try:
                    checkpoint_interval = int(sys.argv[i + 1])
                except ValueError:
                    pass
                break
        if "RECEIPTD_CHECKPOINT_INTERVAL" in os.environ:
            try:
                checkpoint_interval = int(os.environ["RECEIPTD_CHECKPOINT_INTERVAL"])
            except ValueError:
                pass

        tool_name = str(payload.get("tool_name", ""))
        tool_input = payload.get("tool_input", {})
        args_sha256 = sha256_hex(canonical_json(tool_input))
        session_id = str(payload.get("session_id") or os.environ.get("RECEIPTD_SESSION_ID", "default"))
        _CTX.update(
            tool_name=tool_name,
            tool_input=tool_input,
            session_id=session_id,
            policy_sha256=policy_sha256,
        )

        # Attempt to load signing key before acquiring ledger lock (so if key loading hangs, the lock is not held)
        sk: SigningKey | None = None
        signing_failed = False
        try:
            sk = get_signing_key()
        except Exception:
            signing_failed = True

        # Read existing ledger state and write next receipt under exclusive inter-process lock
        with lock_ledger(ledger_path):
            prev_hash, last_cp_hash, receipt_count, last_cp_seq, uncheckpointed = read_ledger_state(ledger_path)
            seq = receipt_count + 1
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)

            if signing_failed or sk is None:
                # Signing failure must fail-closed with exit 2 and write an unsigned deny receipt
                unsigned_receipt = build_unsigned_signing_error_receipt(
                    v=1,
                    seq=seq,
                    ts=datetime.now(timezone.utc).isoformat(),
                    session_id=session_id,
                    tool=tool_name,
                    args_sha256=args_sha256,
                    decision="deny",
                    rule_ids=triggered,
                    blast_radius=score,
                    reason="receiptd: signing unavailable",
                    policy_sha256=policy_sha256,
                    prev_hash=prev_hash,
                    extra_fields={"latency_ms": latency_ms, "tool_input": tool_input},
                )
                with _LEDGER_LOCK:
                    append_ledger_entry(ledger_path, unsigned_receipt)
                    record_ledger_anchor(unsigned_receipt["seq"], unsigned_receipt["hash"], ledger_path=ledger_path)
                    _CTX["finished"] = True
                sys.stderr.write("receiptd: signing unavailable\n")
                return 2

            # Key loaded successfully: construct signed receipt
            receipt = build_signed_receipt(
                sk=sk,
                v=1,
                seq=seq,
                ts=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                tool=tool_name,
                args_sha256=args_sha256,
                decision=decision,
                rule_ids=triggered,
                blast_radius=score,
                reason=reason,
                policy_sha256=policy_sha256,
                prev_hash=prev_hash,
                extra_fields={"latency_ms": latency_ms, "tool_input": tool_input},
            )
            # Receipt, checkpoint, and "finished" go in one locked block so the
            # watchdog sees either nothing written or the whole decision.
            with _LEDGER_LOCK:
                try:
                    record_ledger_anchor(receipt["seq"], receipt["hash"], ledger_path=ledger_path, sk=sk)
                except Exception as exc:
                    sys.stderr.write(f"receiptd: anchor write failed: {exc}\n")
                    _CTX["finished"] = True
                    return 2

                append_ledger_entry(ledger_path, receipt)

                # Write Merkle checkpoint if interval reached
                uncheckpointed_hashes = [r["hash"] for r in uncheckpointed] + [receipt["hash"]]
                if len(uncheckpointed_hashes) >= checkpoint_interval:
                    from_seq = last_cp_seq + 1
                    to_seq = seq
                    cp = build_signed_checkpoint(
                        sk=sk,
                        from_seq=from_seq,
                        to_seq=to_seq,
                        leaf_hashes=uncheckpointed_hashes,
                        prev_checkpoint_hash=last_cp_hash,
                    )
                    append_ledger_entry(ledger_path, cp)
                _CTX["finished"] = True

        if blocked:
            sys.stderr.write(
                f"\n[RECEIPTD HARD BLOCK] {decision.upper()} in {latency_ms}ms\n"
                f"  ├─ Tool: {tool_name}\n"
                f"  ├─ Blast Score: {score}/100 ({', '.join(triggered)})\n"
                f"  └─ Signed Receipt SHA-256: {receipt['hash'][:24]}...\n"
            )
            return 2  # Exit code 2 deterministically halts Claude Code tool execution

        return 0

    except Exception as exc:
        # Fail-closed guarantee: any parser/IO error halts execution
        sys.stderr.write(f"[RECEIPTD FAIL-CLOSED EXCEPTION] Execution halted: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
