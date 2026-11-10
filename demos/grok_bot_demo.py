#!/usr/bin/env python3
"""
Grok Bot / Hermes-style demo.

Shows the exact pattern a Grok Bot (or Hermes agent) should use:
1. Create identity
2. For every tool call, build request → attempt_action → only execute if allow
3. Export package and verify offline.

Run:
    python demos/grok_bot_demo.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from receiptd import (
    Engine,
    PolicySpec,
    SigningKey,
    load_default_policy,
    render_report,
    verify_package,
)
from receiptd.adapters.grok_bot import GrokBotAdapter
from receiptd.verify import load_run_package


def main() -> None:
    print("=" * 60)
    print("BIRKIN × GROK BOT / HERMES DEMO")
    print("=" * 60)

    birkin_sk = SigningKey.generate()
    policy = load_default_policy()
    adapter = GrokBotAdapter()
    engine = Engine(birkin_signing_key=birkin_sk, policy=policy, adapter=adapter)

    identity = adapter.make_identity(
        agent_id="grok-bot-demo",
        policy_ref=policy.ref,
        ttl_seconds=600,
    )
    engine.start_session(identity)

    intent = adapter.declare_intent(
        identity,
        text="Read a status file under the sandbox, then stop.",
    )
    engine.declare_intent(identity, intent)

    # Allowed tool (fs.read is allowed by default policy)
    req1 = adapter.build_action_request(
        tool="fs.read",
        args={"path": "/tmp/birkin/status.txt"},
        justification="read status",
    )
    rec1 = engine.attempt_action(identity, req1)
    print(f"fs.read    → {rec1.decision} ({rec1.rule})")
    if rec1.decision == "allow":
        adapter.execute(identity, req1, rec1)

    # Denied tool (shell)
    req2 = adapter.build_action_request(
        tool="bash",
        args={"command": "rm -rf /"},
        justification="should be denied",
    )
    rec2 = engine.attempt_action(identity, req2)
    print(f"bash       → {rec2.decision} ({rec2.rule})")

    engine.checkpoint()
    engine.end_session(identity)

    out = Path(tempfile.mkdtemp(prefix="birkin-grok-")) / "run_package.json"
    engine.export_to_file(str(out), identity=identity)
    pkg = load_run_package(str(out))
    report = verify_package(pkg)

    print("-" * 60)
    print(render_report(report))
    print(f"package: {out}")
    print("=" * 60)


if __name__ == "__main__":
    main()
