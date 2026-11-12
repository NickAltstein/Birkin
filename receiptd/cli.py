#!/usr/bin/env python3
"""
Birkin CLI: Zero-Trust Agent Authorization & Evidence Layer
Commands:
  - birkin init --claude-code : Wires .claude/settings.json PreToolUse hooks + skills
  - birkin verify --ledger   : Audits SHA-256 hash chains, Ed25519 signatures, & tamper diffs
  - birkin verify <package>  : Offline-verify an exported run package (.json)
  - birkin demo              : Run end-to-end vertical slice demo
  - birkin attack <1|2|3>    : Run attack demonstration
  - birkin keys              : Generate fresh signing keypair
  - birkin run               : Run single governed tool invocation
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer

# Allow ``birkin demo`` and ``birkin attack`` to import the demos/ package
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from . import __version__
from .crypto import (
    SigningKey,
    canonical_json,
    canonical_json_subset,
    get_public_key_pem,
    get_pubkey_id,
    get_signing_key,
    merkle_root,
    verify_ed25519,
)
from .ledger import (
    CHECKPOINT_SIGNABLE_FIELDS,
    GENESIS_HASH,
    SIGNABLE_RECEIPT_FIELDS,
    read_ledger_anchor,
)
from .verify import render_report, verify_file

app = typer.Typer(
    name="receiptd",
    help="Receiptd — Cryptographic authorization receipts & fail-closed PreToolUse hooks.",
    no_args_is_help=True,
    add_completion=False,
)
cli = app


# ---------------------------------------------------------------------------
# Cryptographic & Canonicalization Helpers (canonical JSON, sorted keys)
# ---------------------------------------------------------------------------

def canonicalize_jcs(obj) -> str:
    """Canonical JSON (sorted keys, compact separators). Not full RFC 8785."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_ascii_table(headers: list[str], rows: list[list[str]]) -> str:
    """Zero-dependency fallback ASCII table formatter."""
    col_widths = [max(len(str(item)) for item in col) for col in zip(*(rows + [headers]))]

    def format_row(row):
        return " | ".join(str(val).ljust(width) for val, width in zip(row, col_widths))

    separator = "-+-".join("-" * width for width in col_widths)
    lines = [format_row(headers), separator]
    for row in rows:
        lines.append(format_row(row))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command: `birkin version`
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print the Receiptd version."""
    typer.echo(f"receiptd {__version__}")


# ---------------------------------------------------------------------------
# Command: `receiptd init --claude-code`
# ---------------------------------------------------------------------------

@app.command("init")
def init(
    claude_code: bool = typer.Option(True, "--claude-code", help="Wire .claude/settings.json PreToolUse hook gate."),
    policy_path: str = typer.Option(
        ".birkin/pretooluse.policy.json",
        "--policy-path",
        help="Path of the PreToolUse policy JSON the hook loads and hashes.",
    ),
) -> None:
    """Initialize Receiptd runtime hooks and audit structures in the local repository."""
    typer.echo("Initializing Receiptd Zero-Trust Agent Firewall...")

    os.makedirs(".birkin", exist_ok=True)

    # 1. Write the packaged PreToolUse policy if the project file is missing.
    # The hook reads this path once and both enforces and hashes those bytes.
    if not os.path.exists(policy_path):
        from .hooks.claude_code_gate import default_policy_path

        policy_bytes = default_policy_path().read_bytes()
        with open(policy_path, "wb") as f:
            f.write(policy_bytes)
        typer.echo(f"  [+] Created default policy: {policy_path}")

    # 2. Wire Claude Code PreToolUse Hook if requested
    if claude_code:
        os.makedirs(".claude", exist_ok=True)
        settings_path = ".claude/settings.json"

        settings = {}
        if os.path.exists(settings_path):
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
            except Exception:
                typer.echo("  [!] Warning: Existing .claude/settings.json was malformed. Overwriting hooks.")

        hooks_config = settings.setdefault("hooks", {})
        pre_tool_use = hooks_config.setdefault("PreToolUse", [])

        hook_entry = {
            "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"python3 -m receiptd.hooks.claude_code_gate --policy {policy_path} --ledger .birkin/receipts.jsonl",
                    # Seconds. Must stay above the gate's internal deadline
                    # (RECEIPTD_HOOK_DEADLINE_MS, default 5000) so the gate
                    # denies before Claude Code's timeout lets the call through.
                    "timeout": 10,
                }
            ],
        }

        # Avoid duplicate hook registration
        if not any(isinstance(h, dict) and h.get("matcher") == hook_entry["matcher"] for h in pre_tool_use):
            pre_tool_use.append(hook_entry)
            typer.echo(f"  [✓] Wired PreToolUse deterministic gate into {settings_path}")
        else:
            typer.echo("  [i] PreToolUse hook already registered in .claude/settings.json")

        # 3. Wire Claude Code Stop Hook (exit 2 prevents completion while tests fail)
        stop_hooks = hooks_config.setdefault("Stop", [])
        stop_entry = {
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 -m receiptd.hooks.claude_code_stop_gate --ledger .birkin/receipts.jsonl",
                }
            ]
        }
        if not stop_hooks:
            stop_hooks.append(stop_entry)
            typer.echo(f"  [✓] Wired Stop deterministic completion gate into {settings_path}")
        else:
            typer.echo("  [i] Stop hook already registered in .claude/settings.json")

        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)

        # 4. Create audit skill placeholder
        skill_dir = ".claude/skills/birkin-audit"
        os.makedirs(skill_dir, exist_ok=True)
        skill_path = os.path.join(skill_dir, "SKILL.md")
        with open(skill_path, "w", encoding="utf-8") as f:
            f.write(
                "---\n"
                "name: birkin-audit\n"
                "description: Verify cryptographic execution receipts and audit the local SHA-256 hash chain.\n"
                "---\n\n"
                "Run `birkin verify --ledger .birkin/receipts.jsonl` to audit agent session integrity.\n"
            )
        typer.echo(f"  [✓] Installed /birkin-audit skill in {skill_dir}")

    typer.echo("\nBirkin initialization complete. AuditGPT / Birkin active.")


# ---------------------------------------------------------------------------
# Command: `receiptd pubkey`
# ---------------------------------------------------------------------------

@app.command("pubkey")
def pubkey(
    format: str = typer.Option("pem", "--format", "-f", help="Output format: pem, b64, or json"),
    key_dir: Optional[str] = typer.Option(None, "--key-dir", help="Directory containing keys"),
) -> None:
    """Export the Receiptd Ed25519 public key."""
    kd = Path(key_dir) if key_dir else None
    sk = get_signing_key(key_dir=kd)
    pub_pem = sk.public_pem_bytes.decode("ascii").strip()
    pub_b64 = sk.public_b64
    pub_id = get_pubkey_id(sk)

    if format == "b64":
        typer.echo(pub_b64)
    elif format == "json":
        typer.echo(json.dumps({"pubkey_id": pub_id, "public_b64": pub_b64, "public_pem": pub_pem}, indent=2))
    else:
        typer.echo(pub_pem)


# ---------------------------------------------------------------------------
# Command: `birkin verify --ledger` / `birkin verify <package>`
# ---------------------------------------------------------------------------

def _verify_ledger_file(
    ledger_path: Path,
    format_type: str = "table",
    pubkey: Optional[str] = None,
    allow_unanchored: bool = False,
    key_dir: Optional[Path] = None,
) -> bool:
    if not ledger_path.exists():
        typer.echo(f"Error: Ledger file not found at {ledger_path}", err=True)
        return False

    typer.echo(f"Auditing cryptographic ledger: {ledger_path}...\n")

    entries = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception as e:
                typer.echo(f"[-] Malformed JSON on line {line_num}: {e}", err=True)
                return False

    if not entries:
        if not allow_unanchored:
            kd = key_dir or Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
            state_file = kd / "ledger_state.json"
            if not state_file.exists():
                legacy_file = kd / "state.json"
                if legacy_file.exists():
                    state_file = legacy_file
            if state_file.exists():
                try:
                    raw_data = json.loads(state_file.read_text(encoding="utf-8"))
                    norm_ledger = str(ledger_path.resolve())
                    ledger_anchor = None
                    if isinstance(raw_data.get("ledgers"), dict) and norm_ledger in raw_data["ledgers"]:
                        ledger_anchor = raw_data["ledgers"][norm_ledger]
                    elif raw_data.get("ledger_path") == norm_ledger:
                        ledger_anchor = raw_data
                    if ledger_anchor:
                        anchor_seq = int(ledger_anchor.get("last_seq", 0))
                        if anchor_seq > 0:
                            typer.echo("=" * 65)
                            typer.echo(f"✗ TAMPER DETECTED: Ledger is empty, but recorded state expects sequence #{anchor_seq}")
                            typer.echo("=" * 65)
                            typer.echo("Audit failed. Ledger cryptographic integrity invalidated.")
                            return False
                except Exception:
                    pass
        typer.echo("Ledger is empty. No execution frames recorded.")
        return True

    # Resolve public key for verifying Ed25519 signatures
    kd = key_dir or Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
    pubkey_target = pubkey
    if not pubkey_target:
        pubkey_target = os.environ.get("RECEIPTD_PUBLIC_KEY")
    if not pubkey_target:
        try:
            pubkey_target = get_public_key_pem(key_dir=kd)
        except Exception:
            pubkey_target = None
        except Exception:
            pubkey_target = None

    expected_prev_hash = GENESIS_HASH
    expected_prev_cp_hash = GENESIS_HASH
    receipts_by_seq: dict[int, dict] = {}
    receipt_count = 0
    checkpoint_count = 0
    unsigned_deny_count = 0
    last_checkpointed_seq = 0
    table_rows = []

    tamper_detected = False
    tamper_reason = ""

    for idx, entry in enumerate(entries):
        is_checkpoint = (entry.get("type") == "checkpoint")

        if is_checkpoint:
            checkpoint_count += 1
            from_seq = entry.get("from_seq", 0)
            to_seq = entry.get("to_seq", 0)
            stored_root = entry.get("merkle_root", "")
            stored_prev_cp = entry.get("prev_checkpoint_hash", "")
            stored_cp_hash = entry.get("hash") or entry.get("checkpoint_hash", "")
            cp_sig = entry.get("sig", "")

            # 1. Checkpoint hash chain
            if stored_prev_cp != expected_prev_cp_hash:
                tamper_detected = True
                tamper_reason = (
                    f"Checkpoint Hash Chain Break at checkpoint #{checkpoint_count}: "
                    f"Expected prev_checkpoint_hash {expected_prev_cp_hash[:16]}..., got {stored_prev_cp[:16]}..."
                )
                break

            # 2. Checkpoint signature
            if cp_sig and pubkey_target:
                cp_signable = canonical_json_subset(entry, CHECKPOINT_SIGNABLE_FIELDS)
                if not verify_ed25519(pubkey_target, cp_sig, cp_signable):
                    tamper_detected = True
                    tamper_reason = f"Invalid Ed25519 signature on checkpoint (range {from_seq}..{to_seq})"
                    break

            # 3. Checkpoint Merkle root against receipts in range
            range_hashes = []
            missing = []
            for s in range(from_seq, to_seq + 1):
                if s in receipts_by_seq:
                    range_hashes.append(receipts_by_seq[s]["hash"])
                else:
                    missing.append(s)

            if missing:
                tamper_detected = True
                tamper_reason = f"Checkpoint range {from_seq}..{to_seq} references missing receipt sequence #{missing[0]}"
                break

            recomputed_root = merkle_root(range_hashes)
            if recomputed_root != stored_root:
                tamper_detected = True
                tamper_reason = (
                    f"Checkpoint Merkle root mismatch for range {from_seq}..{to_seq}: "
                    f"Stored {stored_root[:16]}... != Recomputed {recomputed_root[:16]}..."
                )
                break

            # 4. Checkpoint record payload hash
            cp_copy = {k: v for k, v in entry.items() if k not in ("hash", "checkpoint_hash")}
            recomputed_cp_hash = sha256_hex(canonical_json(cp_copy))
            if stored_cp_hash and recomputed_cp_hash != stored_cp_hash:
                tamper_detected = True
                tamper_reason = f"Checkpoint record mutation detected (range {from_seq}..{to_seq})"
                break

            expected_prev_cp_hash = stored_cp_hash or recomputed_cp_hash
            last_checkpointed_seq = max(last_checkpointed_seq, to_seq)

        else:
            # Regular receipt
            receipt_count += 1
            seq = entry.get("seq", receipt_count)
            stored_hash = entry.get("hash") or entry.get("receipt_sha256", "")
            stored_prev = entry.get("prev_hash") or entry.get("prev_receipt_hash", "")
            sig = entry.get("sig")
            is_signing_error = bool(entry.get("signing_error", False))

            # 1. Receipt Hash Chain
            if stored_prev != expected_prev_hash:
                tamper_detected = True
                tamper_reason = (
                    f"Hash Chain Break at Frame sequence #{seq} (T+{receipt_count - 1}): "
                    f"Expected prev_hash {expected_prev_hash[:16]}..., got {stored_prev[:16]}..."
                )
                break

            # 2. Payload Mutation (hash integrity)
            rec_copy = {k: v for k, v in entry.items() if k not in ("hash", "receipt_sha256")}
            recomputed_hash = sha256_hex(canonical_json(rec_copy))
            if stored_hash and recomputed_hash != stored_hash:
                tamper_detected = True
                tamper_reason = (
                    f"Payload Mutation Detected at Frame sequence #{seq} (T+{receipt_count - 1}): "
                    f"Stored hash {stored_hash[:16]}... != Recomputed {recomputed_hash[:16]}..."
                )
                break

            # 3. Signature verification
            if sig:
                if not pubkey_target:
                    tamper_detected = True
                    tamper_reason = f"Receipt at sequence #{seq} is signed but no public key available to verify signature"
                    break
                signable_bytes = canonical_json_subset(entry, SIGNABLE_RECEIPT_FIELDS)
                if not verify_ed25519(pubkey_target, sig, signable_bytes):
                    tamper_detected = True
                    tamper_reason = f"Invalid Ed25519 signature at receipt sequence #{seq}"
                    break
            else:
                # Receipt without sig is ONLY allowed if signing_error: true AND decision == "deny"
                decision = entry.get("decision", "UNKNOWN")
                if is_signing_error and decision == "deny":
                    unsigned_deny_count += 1
                else:
                    tamper_detected = True
                    if is_signing_error and decision != "deny":
                        tamper_reason = f"Unsigned receipt at sequence #{seq} has decision '{decision}' (only deny allowed with signing_error: true)"
                    else:
                        tamper_reason = f"Unsigned receipt at sequence #{seq} (missing Ed25519 signature)"
                    break

            tool = entry.get("tool") or entry.get("tool_name", "unknown")
            decision = entry.get("decision", "UNKNOWN")
            score = entry.get("blast_radius") if entry.get("blast_radius") is not None else entry.get("blast_radius_score", 0)
            latency = f"{entry.get('latency_ms', 0)}ms"

            table_rows.append([f"Seq #{seq}", tool, decision, f"{score}/100", latency, (stored_hash or recomputed_hash)[:16] + "..."])
            expected_prev_hash = stored_hash or recomputed_hash
            receipts_by_seq[seq] = {"hash": stored_hash or recomputed_hash, "entry": entry}

    if format_type == "table" and table_rows:
        headers = ["Frame", "Tool Invocation", "Decision", "Blast Score", "Latency", "SHA-256 Receipt Fingerprint"]
        typer.echo(compute_ascii_table(headers, table_rows))
        typer.echo()

    if not tamper_detected and not allow_unanchored:
        kd = key_dir or Path(os.environ.get("RECEIPTD_KEY_DIR", Path.home() / ".receiptd"))
        state_file = kd / "ledger_state.json"
        if not state_file.exists():
            legacy_file = kd / "state.json"
            if legacy_file.exists():
                state_file = legacy_file

        if not state_file.exists():
            if receipt_count > 0:
                tamper_detected = True
                tamper_reason = (
                    f"Missing signed ledger anchor: ledger has {receipt_count} receipts "
                    f"but anchor state file {state_file} not found"
                )
        else:
            try:
                anchor_data = json.loads(state_file.read_text(encoding="utf-8"))
            except Exception as exc:
                tamper_detected = True
                tamper_reason = f"Unreadable or corrupted ledger anchor in {state_file}: {exc}"
                anchor_data = None

            if anchor_data is not None:
                norm_ledger = str(ledger_path.resolve())
                ledger_anchor = None
                ledgers = anchor_data.get("ledgers")
                if isinstance(ledgers, dict) and norm_ledger in ledgers:
                    ledger_anchor = ledgers[norm_ledger]
                elif norm_ledger in anchor_data and isinstance(anchor_data[norm_ledger], dict):
                    ledger_anchor = anchor_data[norm_ledger]
                elif anchor_data.get("ledger_path") == norm_ledger:
                    ledger_anchor = anchor_data
                elif "last_seq" in anchor_data and not anchor_data.get("ledger_path"):
                    ledger_anchor = anchor_data

                if ledger_anchor is None:
                    if receipt_count > 0:
                        tamper_detected = True
                        tamper_reason = (
                            f"Missing signed ledger anchor for {norm_ledger}: "
                            f"anchor state file exists but contains no anchor for this ledger path"
                        )
                else:
                    sig = ledger_anchor.get("sig")
                    if not sig:
                        tamper_detected = True
                        tamper_reason = f"Ledger anchor in {state_file} is unsigned (missing Ed25519 signature)"
                    else:
                        signable = {
                            "last_hash": str(ledger_anchor.get("last_hash", "")),
                            "last_seq": int(ledger_anchor.get("last_seq", 0)),
                            "ledger_path": str(ledger_anchor.get("ledger_path", "")),
                        }
                        canonical_bytes = canonical_json(signable)
                        if not pubkey_target or not verify_ed25519(pubkey_target, sig, canonical_bytes):
                            tamper_detected = True
                            tamper_reason = f"Invalid Ed25519 signature on ledger anchor in {state_file}"
                        else:
                            anchor_path = ledger_anchor.get("ledger_path")
                            if anchor_path and anchor_path != norm_ledger:
                                tamper_detected = True
                                tamper_reason = f"Ledger anchor path mismatch: recorded {anchor_path}, verifying {norm_ledger}"
                            else:
                                anchor_seq = int(ledger_anchor.get("last_seq", 0))
                                anchor_hash = str(ledger_anchor.get("last_hash", ""))
                                if receipt_count < anchor_seq:
                                    tamper_detected = True
                                    tamper_reason = (
                                        f"Ledger tail truncation detected: ledger ends at sequence #{receipt_count}, "
                                        f"but recorded state expects sequence #{anchor_seq}"
                                    )
                                elif receipt_count == 0 and anchor_seq > 0:
                                    tamper_detected = True
                                    tamper_reason = f"Ledger is empty, but recorded state expects sequence #{anchor_seq}"
                                elif receipt_count > 0 and anchor_seq in receipts_by_seq:
                                    actual_hash = receipts_by_seq[anchor_seq]["hash"]
                                    if actual_hash != anchor_hash:
                                        tamper_detected = True
                                        tamper_reason = (
                                            f"Ledger anchor hash mismatch at sequence #{anchor_seq}: "
                                            f"expected hash {anchor_hash[:16]}..., got {actual_hash[:16]}..."
                                        )

    if tamper_detected:
        typer.echo("=" * 65)
        typer.echo(f"✗ TAMPER DETECTED: {tamper_reason}")
        typer.echo("=" * 65)
        typer.echo(f"Audit failed. Ledger cryptographic integrity invalidated.")
        return False

    # Check for uncheckpointed tail
    if last_checkpointed_seq < receipt_count and receipt_count > 0:
        tail_start = last_checkpointed_seq + 1
        typer.echo(
            f"Warning: Uncheckpointed tail: receipts {tail_start} to {receipt_count} "
            f"have not been sealed in a Merkle checkpoint. "
            f"Missing receipts after the last checkpoint cannot be proven.\n"
        )

    typer.echo("=" * 65)
    typer.echo(f"✓ VERDICT: AUTHENTIC — {receipt_count} receipts, {checkpoint_count} checkpoints verified, 0 chain breaks.")
    typer.echo(f"Unsigned deny receipts accepted: {unsigned_deny_count}")
    typer.echo("=" * 65)
    return True


@app.command("anchor")
def anchor(
    ledger: str = typer.Option(..., "--ledger", help="Path to the JSONL receipt ledger to anchor."),
    force_reanchor: bool = typer.Option(False, "--force-reanchor", help="Replace an existing anchor for this ledger."),
) -> None:
    """Fully verify a ledger, then write a signed anchor for its last receipt."""
    from .ledger import record_ledger_anchor

    ledger_path = Path(ledger)
    if not ledger_path.exists():
        typer.echo(f"error: ledger not found: {ledger}", err=True)
        raise typer.Exit(code=2)

    if not force_reanchor and read_ledger_anchor(ledger_path=ledger_path) is not None:
        typer.echo(
            f"error: an anchor for {ledger_path.resolve()} already exists; "
            "pass --force-reanchor to replace it",
            err=True,
        )
        raise typer.Exit(code=2)

    # Chain + signature verification only; the anchor itself is what we are creating.
    if not _verify_ledger_file(ledger_path, allow_unanchored=True):
        typer.echo("error: ledger failed verification; refusing to anchor", err=True)
        raise typer.Exit(code=2)

    last = None
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("type") != "checkpoint":
                last = entry
    if last is None:
        typer.echo("error: ledger has no receipts to anchor", err=True)
        raise typer.Exit(code=2)

    seq = int(last.get("seq", 0))
    r_hash = last.get("hash") or last.get("receipt_sha256", "")
    try:
        record_ledger_anchor(seq, r_hash, ledger_path=ledger_path)
    except Exception as exc:
        typer.echo(f"error: could not write anchor: {exc}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"Anchored {ledger_path.resolve()} at sequence #{seq}")


@app.command("verify")
def verify(
    package: Optional[str] = typer.Argument(None, help="Path to a receiptd or birkin run package (.json)"),
    ledger: Optional[str] = typer.Option(None, "--ledger", help="Path to the JSONL receipt ledger."),
    pubkey: Optional[str] = typer.Option(None, "--pubkey", help="Path or string of Ed25519 public key for verification."),
    allow_unanchored: bool = typer.Option(False, "--allow-unanchored", help="Allow verification without comparing against local recorded anchor state."),
    format: str = typer.Option("table", "--format", help="Output format: table or json"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print verdict only"),
) -> None:
    """Audit the append-only SHA-256 hash chain and perform cryptographic tamper diffing."""
    if not ledger and not package:
        if Path(".receiptd/receipts.jsonl").exists():
            ledger = ".receiptd/receipts.jsonl"
        elif Path(".birkin/receipts.jsonl").exists():
            ledger = ".birkin/receipts.jsonl"

    if ledger:
        ok = _verify_ledger_file(Path(ledger), format_type=format, pubkey=pubkey, allow_unanchored=allow_unanchored)
        if not ok:
            raise typer.Exit(code=2)
        return

    if not package:
        typer.echo("error: Provide either a run package path or --ledger <path>", err=True)
        raise typer.Exit(code=2)

    path = Path(package)
    if not path.exists():
        typer.echo(f"error: package not found: {package}", err=True)
        raise typer.Exit(code=2)

    report = verify_file(path)
    if quiet:
        typer.echo(report.verdict)
    else:
        typer.echo(render_report(report))
    if report.verdict != "AUTHENTIC":
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Command: `receiptd card` (Signed Trifecta Card)
# ---------------------------------------------------------------------------

@app.command("card")
def card(
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Direct path to a .jsonl session log (Claude Code or Codex)."),
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Alias for --session."),
    last: Optional[int] = typer.Option(None, "--last", "-n", help="Analyze the N most recent sessions (default: 1 if no session given)."),
    out: str = typer.Option("card.png", "--out", "-o", help="Output image path (default: card.png; companion .svg and signed .json written too)."),
    redact_paths: bool = typer.Option(False, "--redact-paths", help="Hash path components in evidence targets."),
    days: int = typer.Option(30, "--days", "-d", help="Analysis window in days (backward compatibility)."),
    no_png: bool = typer.Option(False, "--no-png", help="Skip PNG rendering and print terminal card only."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Output verdict only (RED, YELLOW, GREEN)."),
) -> None:
    """Audit agent session logs for the lethal Trifecta hazard (private data + untrusted input + egress)."""
    from receiptd.card.pipeline import analyze_last, analyze_paths
    from receiptd.card.render_terminal import render_terminal
    from receiptd.card.render_card import render_card_files

    target_session = session or path
    try:
        if target_session:
            report = analyze_paths([target_session], redacted=redact_paths)
        else:
            n = last if last is not None else 1
            report = analyze_last(n, redacted=redact_paths)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    if quiet:
        typer.echo(report.level)
        return

    # Print terminal card
    json_name = Path(out).with_suffix(".json").name
    render_terminal(report, card_json_name=json_name)

    if not no_png:
        try:
            rendered = render_card_files(report, out)
            typer.echo(f"\n  [✓] Signed Trifecta Card exported to: {rendered['png']}")
            typer.echo(f"  [✓] Companion signature record:      {rendered['json']}")
        except Exception as e:
            typer.echo(f"  [!] Note: Card rendering skipped ({e})", err=True)


# ---------------------------------------------------------------------------
# Command: `receiptd verify-card` (Signature & Digest Verification)
# ---------------------------------------------------------------------------

@app.command("verify-card")
def verify_card(
    card_json: str = typer.Argument(..., help="Path to signed card JSON file."),
    pubkey_id: Optional[str] = typer.Option(None, "--pubkey-id", help="Expected 64-character hex ID of the signer public key."),
    pubkey_file: Optional[str] = typer.Option(None, "--pubkey-file", help="Path to PEM file of the expected signer public key."),
) -> None:
    """Verify an Ed25519 signed Trifecta Card JSON document."""
    from receiptd.card.signing import verify_card_file
    from receiptd.crypto import get_pubkey_id

    expected_id = pubkey_id.strip() if pubkey_id else None
    if pubkey_file:
        p = Path(pubkey_file)
        if not p.is_file():
            typer.echo(f"error: public key file not found: {pubkey_file}", err=True)
            raise typer.Exit(code=1)
        expected_id = get_pubkey_id(p.read_text(encoding="utf-8"))

    ok, message = verify_card_file(card_json, expected_pubkey_id=expected_id)
    typer.echo(message)
    if not ok:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Additional Commands: demo, attack, keys, run
# ---------------------------------------------------------------------------

@app.command()
def demo(
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Write the run package to this path"),
    show_events: bool = typer.Option(False, "--show-events", help="Print the full event ledger"),
) -> None:
    """Run the end-to-end vertical slice in <60s and print the verdict."""
    from demos.end_to_end import run_demo
    run_demo(out_path=out, show_events=show_events)


@app.command()
def attack(
    n: int = typer.Argument(..., help="Attack number: 1, 2, or 3"),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Write the tampered package to this path"),
) -> None:
    """Run one of the three attack demonstrations."""
    from demos import attacks
    if n == 1:
        attacks.attack_1_prompt_injection(out_path=out)
    elif n == 2:
        attacks.attack_2_privilege_escalation(out_path=out)
    elif n == 3:
        attacks.attack_3_policy_tampering(out_path=out)
    else:
        typer.echo(f"error: unknown attack {n}", err=True)
        raise typer.Exit(code=2)


@app.command("stop-gate")
def stop_gate_cmd(
    test_cmd: Optional[str] = typer.Option(None, "--test-cmd", "-t", help="Verification command to execute (defaults to auto-detection)."),
    ledger: str = typer.Option(".receiptd/receipts.jsonl", "--ledger", "-l", help="Path to audit ledger."),
    timeout: int = typer.Option(120, "--timeout", help="Test timeout in seconds."),
    max_retries: int = typer.Option(3, "--max-retries", help="Max retry blocks before giving up when stop_hook_active is true."),
    session_id: Optional[str] = typer.Option(None, "--session-id", help="Session ID for tracking retry attempts."),
    stop_hook_active: Optional[bool] = typer.Option(None, "--stop-hook-active", help="Flag indicating stop hook is already active."),
) -> None:
    """Gate agent completion: exit 0 if tests pass, exit 2 if tests fail, recording signed receipts."""
    from .hooks.claude_code_stop_gate import run_stop_gate
    code = run_stop_gate(
        test_cmd=test_cmd,
        ledger_path=ledger,
        timeout_sec=timeout,
        max_retries=max_retries,
        session_id=session_id,
        stop_hook_active=stop_hook_active,
    )
    if code != 0:
        raise typer.Exit(code=code)


@app.command()
def keys() -> None:
    """Generate and print a fresh Birkin control-plane signing key."""
    sk = SigningKey.generate()
    typer.echo(json.dumps(
        {
            "private_b64": sk.private_b64,
            "public_b64": sk.public_b64,
            "algorithm": "Ed25519",
        },
        indent=2,
    ))
    typer.echo("# store private_b64 as BIRKIN_SIGNING_KEY (env). Distribute public_b64.", err=True)


@app.command()
def run(
    tool: str = typer.Option(..., "--tool", help="Tool name"),
    args_json: str = typer.Option("{}", "--args", help="JSON args"),
    agent_id: str = typer.Option("demo-agent", "--agent-id"),
    out: str = typer.Option("run_package.json", "--out", "-o"),
    policy: Optional[str] = typer.Option(None, "--policy", help="Path to policy JSON"),
) -> None:
    """Run a single tool under Birkin governance and export a run package."""
    from .engine import Engine
    from .policy import PolicySpec, DEFAULT_POLICY_PATH
    from .adapters.hermes import HermesAdapter

    sk_env = os.environ.get("BIRKIN_SIGNING_KEY")
    sk = SigningKey.from_private_b64(sk_env) if sk_env else SigningKey.generate()

    spec = PolicySpec.load(policy or DEFAULT_POLICY_PATH)
    adapter = HermesAdapter()
    identity = adapter.make_identity(agent_id=agent_id, policy_ref=spec.ref)
    engine = Engine(birkin_signing_key=sk, policy=spec, adapter=adapter)
    engine.start_session(identity)
    request = adapter.build_action_request(
        tool=tool, args=json.loads(args_json), justification="cli run"
    )
    receipt = engine.attempt_action(identity, request)
    if receipt.decision == "allow":
        engine.execute(identity, request, receipt)
    engine.checkpoint()
    engine.end_session(identity)
    engine.export_to_file(out, identity=identity)
    typer.echo(
        f"wrote {out}  decision={receipt.decision}  rule={receipt.rule}  risk={receipt.risk_score}"
    )


def main(argv=None) -> int:
    """Entrypoint supporting programmatic and CLI invocations."""
    if argv is not None:
        from typer.testing import CliRunner
        runner = CliRunner()
        res = runner.invoke(app, argv, catch_exceptions=False)
        return res.exit_code
    return app()


if __name__ == "__main__":
    main()
