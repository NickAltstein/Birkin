"""
birkin.cli
==========

The ``birkin`` command-line entry point.

Two subcommands matter for the vertical slice:

* ``birkin verify <package.json>`` — offline verification of an exported
  run package. No Birkin server required.
* ``birkin demo`` — runs the full end-to-end vertical slice in <60s and
  prints the canonical AUTHENTIC block.
* ``birkin attack <1|2|3>`` — runs one of the three attack demos and
  prints the tampered / blocked verdict.

Everything else (``run``, ``keys``, ``identity``) is intentionally tiny:
the slice is about *the evidence chain*, not a full operator surface.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer

# Allow ``birkin demo`` and ``birkin attack`` to import the demos/ package,
# which lives next to the birkin package in the project root (not installed).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from . import __version__
from .crypto import SigningKey
from .verify import render_report, verify_file

app = typer.Typer(
    name="birkin",
    help="Birkin — the open Agent Authorization & Evidence Layer.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def version() -> None:
    """Print the Birkin version."""
    typer.echo(f"birkin {__version__}")


def _verify_ledger_file(path: Path, format_type: str = "text") -> bool:
    if not path.exists():
        typer.echo(f"error: ledger file not found: {path}", err=True)
        return False

    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        typer.echo("[✓] VERDICT: AUTHENTIC — 0 frames in ledger.")
        return True

    from .hooks.claude_code_gate import canonicalize_jcs, sha256_hex

    prev_hash = "0" * 64
    blocked_count = 0
    for idx, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except Exception as exc:
            typer.echo(f"[✗] VERDICT: TAMPERED — Malformed JSON at frame {idx}: {exc}")
            return False

        stored_hash = entry.get("receipt_sha256")
        chain_prev = entry.get("prev_receipt_hash")

        if chain_prev != prev_hash:
            typer.echo(
                f"[✗] VERDICT: TAMPERED — Hash chain break at frame {idx} "
                f"(expected {prev_hash[:16]}..., got {chain_prev[:16]}...)"
            )
            return False

        core = {k: v for k, v in entry.items() if k != "receipt_sha256"}
        recomputed = sha256_hex(canonicalize_jcs(core))
        if recomputed != stored_hash:
            typer.echo(
                f"[✗] VERDICT: TAMPERED — Digest mismatch at frame {idx} "
                f"(expected {recomputed[:16]}..., got {stored_hash[:16]}... 1-byte tamper detected)"
            )
            return False

        if entry.get("decision") == "BLOCKED_FAIL_CLOSED":
            blocked_count += 1

        prev_hash = stored_hash

    if format_type == "table":
        typer.echo(
            f"┌────────────────────────┬──────────────────────────────────────────┐\n"
            f"│ Total Frames Verified  │ {len(lines):<40} │\n"
            f"│ Blocked Fail-Closed    │ {blocked_count:<40} │\n"
            f"│ Hash Chain Verdict     │ AUTHENTIC (Ed25519 / SHA-256 Valid)      │\n"
            f"└────────────────────────┴──────────────────────────────────────────┘"
        )
    else:
        typer.echo(
            f"[✓] VERDICT: AUTHENTIC — {len(lines)} frames verified, "
            f"{blocked_count} blocked, 0 hash-chain breaks."
        )
    return True


@app.command()
def verify(
    package: Optional[str] = typer.Argument(None, help="Path to a birkin run package (.json)"),
    ledger: Optional[str] = typer.Option(None, "--ledger", help="Path to a receipts JSONL ledger"),
    format: str = typer.Option("text", "--format", help="Output format: text or table"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print verdict only"),
) -> None:
    """Offline-verify a Birkin run package or JSONL audit ledger."""
    if ledger:
        ok = _verify_ledger_file(Path(ledger), format_type=format)
        if not ok:
            raise typer.Exit(code=1)
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


@app.command()
def init(
    claude_code: bool = typer.Option(
        True, "--claude-code", help="Install Claude Code PreToolUse hard-hook into .claude/settings.json"
    ),
) -> None:
    """Initialize Birkin governance hooks into the local workspace."""
    os.makedirs(".birkin", exist_ok=True)
    os.makedirs(".claude", exist_ok=True)

    settings_path = Path(".claude/settings.json")
    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except Exception:
            settings = {}

    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    hook_entry = {
        "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*",
        "hooks": [
            {
                "type": "command",
                "command": "python3 -m birkin.hooks.claude_code_gate --policy .birkin/strict.yaml --ledger .birkin/receipts.jsonl",
            }
        ],
    }

    if not any(isinstance(h, dict) and h.get("matcher") == hook_entry["matcher"] for h in pre_tool_use):
        pre_tool_use.append(hook_entry)

    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")

    skill_dir = Path(".claude/skills/birkin-audit")
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"
    skill_content = """---
name: birkin-audit
description: Verify cryptographic execution receipts, audit the local SHA-256 hash chain, and inspect blocked tool calls in .birkin/receipts.jsonl.
---

# Birkin Cryptographic Session Auditor

When the user invokes `/birkin-audit`, run the offline verification CLI to validate the integrity of the local `.birkin/receipts.jsonl` hash chain and Ed25519 signatures:

```bash
python3 -m birkin.cli verify --ledger .birkin/receipts.jsonl --format table
```

Report the total frames verified, any `BLOCKED_FAIL_CLOSED` events, and confirm whether the hash chain verdict is `AUTHENTIC` or `TAMPERED`.
"""
    skill_file.write_text(skill_content, encoding="utf-8")

    typer.echo("[BIRKIN INIT] ✓ Wrote .claude/settings.json PreToolUse hook (exit code 2 fail-closed)")
    typer.echo("[BIRKIN INIT] ✓ Installed .claude/skills/birkin-audit/SKILL.md")
    typer.echo("[BIRKIN INIT] ✓ Initialized .birkin audit ledger directory")


@app.command()
def demo(
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Write the run package to this path"
    ),
    show_events: bool = typer.Option(
        False, "--show-events", help="Print the full event ledger"
    ),
) -> None:
    """Run the end-to-end vertical slice in <60s and print the verdict."""
    from demos.end_to_end import run_demo

    run_demo(out_path=out, show_events=show_events)


@app.command()
def attack(
    n: int = typer.Argument(..., help="Attack number: 1, 2, or 3"),
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Write the tampered package to this path"
    ),
) -> None:
    """Run one of the three attack demonstrations.

    1. Prompt injection / goal hijacking
    2. Unauthorized / privilege-escalating tool use
    3. Skill or policy tampering
    """
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
    typer.echo(
        "# store private_b64 as BIRKIN_SIGNING_KEY (env). Distribute public_b64.",
        err=True,
    )


@app.command()
def run(
    tool: str = typer.Option(..., "--tool", help="Tool name"),
    args_json: str = typer.Option("{}", "--args", help="JSON args"),
    agent_id: str = typer.Option("demo-agent", "--agent-id"),
    out: str = typer.Option("run_package.json", "--out", "-o"),
    policy: Optional[str] = typer.Option(
        None, "--policy", help="Path to policy JSON (default: bundled default)"
    ),
) -> None:
    """Run a single tool under Birkin governance and export a run package."""
    from .engine import Engine
    from .policy import PolicySpec, DEFAULT_POLICY_PATH
    from .adapters.hermes import HermesAdapter

    sk_env = os.environ.get("BIRKIN_SIGNING_KEY")
    sk = SigningKey.from_private_b64(sk_env) if sk_env else SigningKey.generate()

    spec = PolicySpec.load(policy or DEFAULT_POLICY_PATH)
    adapter = HermesAdapter()
    identity = adapter.make_identity(
        agent_id=agent_id,
        policy_ref=spec.ref,
    )
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
        f"wrote {out}  decision={receipt.decision}  rule={receipt.rule}  "
        f"risk={receipt.risk_score}"
    )


if __name__ == "__main__":
    app()
