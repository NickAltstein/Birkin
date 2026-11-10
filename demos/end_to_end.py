"""
End-to-end Birkin vertical slice demo.

This is the script referenced by ``birkin demo``. It exercises the full
chain in under 60 seconds and produces a clean AUTHENTIC verdict::

    Agent
      → Birkin Identity
      → Declared Intent
      → Policy Engine
      → Capability check (policy decision)
      → Tool / action attempt
      → Authorization Receipt (signed)
      → Action (allow)
      → Signed Audit Event
      → Simple Merkle Checkpoint
      → birkin verify → VERDICT: AUTHENTIC
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

# Allow running as a script (python demos/end_to_end.py) or as a module.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from receiptd import (  # noqa: E402
    Engine,
    HermesAdapter,
    PolicySpec,
    SigningKey,
    load_default_policy,
    render_report,
    verify_package,
)


def run_demo(
    *,
    out_path: Optional[str] = None,
    show_events: bool = False,
    sandbox_dir: Optional[str] = None,
) -> int:
    """Run the end-to-end slice and return the number of events emitted."""
    sandbox = Path(sandbox_dir or tempfile.mkdtemp(prefix="birkin-e2e-"))
    sandbox.mkdir(parents=True, exist_ok=True)
    # Ensure the policy sandbox exists for fs.write demo.
    policy_sandbox = Path("/tmp/birkin")
    policy_sandbox.mkdir(parents=True, exist_ok=True)

    # 1. Birkin control-plane signing key (would come from env in production).
    birkin_sk = SigningKey.generate()

    # 2. Load policy.
    policy = load_default_policy()

    # 3. Hermes adapter — the first concrete AgentAdapter.
    adapter = HermesAdapter()

    # 4. Engine wires it all together.
    engine = Engine(birkin_signing_key=birkin_sk, policy=policy, adapter=adapter)

    # 5. Identity / Passport
    identity = adapter.make_identity(
        agent_id="demo-agent-01",
        policy_ref=policy.ref,
        ttl_seconds=600,
    )

    # 6. Start session
    engine.start_session(identity)

    # 7. Declared intent — preferred before any side effect.
    intent = adapter.declare_intent(
        identity,
        text=(
            "Write a status report to /tmp/birkin/status.txt, "
            "then read it back to confirm."
        ),
        extras={"task_id": "demo-task-01"},
    )
    engine.declare_intent(identity, intent)

    # 8. Action 1: fs.write to /tmp/birkin/status.txt  → allow (sandboxed)
    req_write = adapter.build_action_request(
        tool="fs.write",
        args={
            "path": "/tmp/birkin/status.txt",
            "data": "Birkin vertical slice: AUTHENTIC.\n",
        },
        justification="write status report to sandbox",
    )
    receipt_write = engine.attempt_action(identity, req_write)
    assert receipt_write.decision == "allow", receipt_write.reason
    result_write, _ = engine.execute(identity, req_write, receipt_write)
    assert result_write.ok, result_write.error

    # 9. Action 2: fs.read  → allow
    req_read = adapter.build_action_request(
        tool="fs.read",
        args={"path": "/tmp/birkin/status.txt"},
        justification="read back the status report",
    )
    receipt_read = engine.attempt_action(identity, req_read)
    assert receipt_read.decision == "allow", receipt_read.reason
    result_read, _ = engine.execute(identity, req_read, receipt_read)
    assert result_read.ok and "AUTHENTIC" in (result_read.output or ""), result_read

    # 10. Action 3: http.get  → allow
    req_get = adapter.build_action_request(
        tool="http.get",
        args={"url": "https://example.com/healthz"},
        justification="liveness check",
    )
    receipt_get = engine.attempt_action(identity, req_get)
    assert receipt_get.decision == "allow"
    result_get, _ = engine.execute(identity, req_get, receipt_get)
    assert result_get.ok

    # 11. Checkpoint + end session
    engine.checkpoint()
    engine.end_session(identity)

    # 12. Export run package
    package_path = out_path or str(sandbox / "run_package.json")
    engine.export_to_file(package_path, identity=identity, notes="end-to-end vertical slice")

    # 13. birkin verify (offline)
    with open(package_path, "r", encoding="utf-8") as fh:
        pkg = json.load(fh)
    # Use the loader to coerce into models.
    from receiptd.verify import load_run_package
    pkg_obj = load_run_package(package_path)
    report = verify_package(pkg_obj)

    print("=" * 60)
    print("BIRKIN END-TO-END VERTICAL SLICE")
    print("=" * 60)
    print(f"agent:        {identity.agent_id}")
    print(f"runtime:      {identity.runtime}")
    print(f"policy:       {policy.ref}  (sha256 {policy.sha256[:12]}...)")
    print(f"session:      {identity.session_id}")
    print(f"events:       {len(engine.ledger)}")
    print(f"receipts:     {len(engine._receipts)}")
    print(f"checkpoints:  {len(engine._checkpoints)}")
    print(f"package:      {package_path}")
    print("-" * 60)
    print(render_report(report))
    print("-" * 60)
    if show_events:
        for ev in pkg_obj.events:
            print(f"  #{ev.sequence:02d}  {ev.type:24s}  {ev.event_hash[:16]}  receipt={ev.receipt_id[:8] if ev.receipt_id else '-'}")
    print("-" * 60)
    return len(engine.ledger)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--out", "-o", default=None)
    p.add_argument("--show-events", action="store_true")
    args = p.parse_args()
    run_demo(out_path=args.out, show_events=args.show_events)
    sys.exit(0)
