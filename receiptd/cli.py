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
from .crypto import SigningKey
from .verify import render_report, verify_file

app = typer.Typer(
    name="receiptd",
    help="Receiptd — Cryptographic authorization receipts & fail-closed PreToolUse hooks.",
    no_args_is_help=True,
    add_completion=False,
)
cli = app


# ---------------------------------------------------------------------------
# Cryptographic & Canonicalization Helpers (RFC-8785)
# ---------------------------------------------------------------------------

def canonicalize_jcs(obj) -> str:
    """RFC-8785 deterministic JSON key sorting and serialization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


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
    policy_path: str = typer.Option(".birkin/strict.yaml", "--policy-path", help="Path to fail-closed policy configuration."),
) -> None:
    """Initialize Receiptd runtime hooks and audit structures in the local repository."""
    typer.echo("Initializing Receiptd Zero-Trust Agent Firewall...")

    os.makedirs(".birkin", exist_ok=True)

    # 1. Write default strict policy if missing
    if not os.path.exists(policy_path):
        default_policy = (
            "version: '1.0'\n"
            "mode: FAIL_CLOSED\n"
            "rules:\n"
            "  - id: POL-01\n"
            "    name: NO_ENV_EXFILTRATION\n"
            "    pattern: '(\\.env|AWS_SECRET|PRIVATE_KEY|curl.*-d)'\n"
            "    action: BLOCK_FAIL_CLOSED\n"
            "  - id: POL-02\n"
            "    name: NO_DESTRUCTIVE_DDL\n"
            "    pattern: '(DROP\\s+TABLE|TRUNCATE|rm\\s+-rf)'\n"
            "    action: BLOCK_FAIL_CLOSED\n"
        )
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(default_policy)
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
                }
            ],
        }

        # Avoid duplicate hook registration
        if not any(isinstance(h, dict) and h.get("matcher") == hook_entry["matcher"] for h in pre_tool_use):
            pre_tool_use.append(hook_entry)
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
            typer.echo(f"  [✓] Wired PreToolUse deterministic gate into {settings_path}")
        else:
            typer.echo("  [i] PreToolUse hook already registered in .claude/settings.json")

        # 3. Create audit skill placeholder
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
# Command: `birkin verify --ledger` / `birkin verify <package>`
# ---------------------------------------------------------------------------

def _verify_ledger_file(ledger_path: Path, format_type: str = "table") -> bool:
    if not ledger_path.exists():
        typer.echo(f"Error: Ledger file not found at {ledger_path}", err=True)
        return False

    typer.echo(f"Auditing cryptographic ledger: {ledger_path}...\n")

    receipts = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                receipts.append(json.loads(line))
            except Exception as e:
                typer.echo(f"[-] Malformed JSON on line {line_num}: {e}", err=True)
                return False

    if not receipts:
        typer.echo("Ledger is empty. No execution frames recorded.")
        return True

    # Hash-Chain & Tamper Audit Loop
    expected_prev_hash = "0" * 64
    tamper_detected = False
    tamper_index = -1
    tamper_reason = ""
    table_rows = []

    for idx, rec in enumerate(receipts):
        stored_hash = rec.get("receipt_sha256", "")
        stored_prev = rec.get("prev_receipt_hash", "")

        if stored_prev != expected_prev_hash:
            tamper_detected = True
            tamper_index = idx
            tamper_reason = (
                f"Hash Chain Break at Frame T+{idx}: "
                f"Expected prev_hash {expected_prev_hash[:16]}..., got {stored_prev[:16]}..."
            )
            break

        rec_copy = dict(rec)
        rec_copy.pop("receipt_sha256", None)
        recomputed_hash = sha256_hex(canonicalize_jcs(rec_copy))

        if recomputed_hash != stored_hash:
            tamper_detected = True
            tamper_index = idx
            tamper_reason = (
                f"Payload Mutation Detected at Frame T+{idx}: "
                f"Stored hash {stored_hash[:16]}... != Recomputed {recomputed_hash[:16]}... (1-byte ledger modification)"
            )
            break

        tool = rec.get("tool_name", "unknown")
        decision = rec.get("decision", "UNKNOWN")
        score = rec.get("blast_radius_score", 0)
        latency = f"{rec.get('latency_ms', 0)}ms"

        table_rows.append([f"T+{idx}", tool, decision, f"{score}/100", latency, stored_hash[:16] + "..."])
        expected_prev_hash = stored_hash

    if format_type == "table" and table_rows:
        headers = ["Frame", "Tool Invocation", "Decision", "Blast Score", "Latency", "SHA-256 Receipt Fingerprint"]
        typer.echo(compute_ascii_table(headers, table_rows))
        typer.echo()

    if tamper_detected:
        typer.echo("=" * 65)
        typer.echo(f"✗ TAMPER DETECTED: {tamper_reason}")
        typer.echo("=" * 65)
        typer.echo(f"Audit failed at frame index {tamper_index}. Ledger cryptographic integrity invalidated.")
        return False
    else:
        typer.echo("=" * 65)
        typer.echo(f"✓ VERDICT: AUTHENTIC — {len(receipts)} frames verified, 0 chain breaks.")
        typer.echo("=" * 65)
        return True


@app.command("verify")
def verify(
    package: Optional[str] = typer.Argument(None, help="Path to a receiptd or birkin run package (.json)"),
    ledger: Optional[str] = typer.Option(None, "--ledger", help="Path to the JSONL receipt ledger."),
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
        ok = _verify_ledger_file(Path(ledger), format_type=format)
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


if __name__ == "__main__":
    app()
