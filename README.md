# Birkin

> The open **Agent Authorization & Evidence Layer**.
> Runtime-agnostic control plane for autonomous agents: signed authorization receipts, a verifiable audit ledger with Merkle checkpoints, and offline verification of exported run packages.

Birkin is the *enforcement and cryptographic evidence plane* that sits between autonomous agents and the systems they can affect. For actions routed through Birkin-governed integrations, an agent cannot invoke a capability without producing a signed, verifiable receipt for what it attempted, why it was allowed (or denied), and under which policy. (Birkin enforces policy at the adapter and tool-dispatch seam; it complements rather than replaces OS-level kernel sandboxing or container boundaries.)

---

## The promise, and the proof

Every agent run under Birkin produces a single self-contained JSON file. Anyone, anywhere, can verify it offline — no Birkin server, no policy file, no agent runtime required. This is the credibility feature.

```bash
$ birkin demo --out run.json        # an agent runs under Birkin governance
$ birkin verify run.json            # anyone, offline, re-derives the verdict
BIRKIN VERIFICATION
✓ Manifest + schema versions
✓ Event chain valid
✓ Signatures valid
✓ Policy version verified
✓ Identity verified
✓ No missing events
✓ Checkpoint matches
✓ Authorization receipts valid
✓ Identity bound to run
VERDICT: AUTHENTIC
```

The verdict is `AUTHENTIC` only if all **nine** independent checks pass. The same file, mutated in any of six realistic ways, flips to `VERDICT: TAMPERED` — and the verifier tells you exactly which check caught it.

This repository ships that closed surface: working code, signed receipts, three blocked attacks, a six-attack tamper matrix, twelve-binding receipt strength matrix, a second adapter proving the runtime seam, a manifest gate, and a CI smoke gate that fails the release on any regression.

## Run it in 60 seconds

```bash
git clone https://github.com/nickainyc/birkin.git
cd birkin
pip install -e .
./demo.sh
```

A separate static page, [birkin-sandbox](https://github.com/NickAltstein/birkin-sandbox), runs the same class of check in the browser: WebCrypto Ed25519 (HMAC-SHA256 if Ed25519 is unavailable), lexicographic JSON, a Merkle root, and a one-byte parameter flip that fail-closes. It does not replace `birkin verify`. Tool calls on that page are fixtures and are not executed.

You will see, in order:

1. A clean end-to-end run producing `VERDICT: AUTHENTIC`.
2. Three concrete attacks, each **blocked**, **recorded**, and **independently verifiable** — including a ledger-tampering attack that flips the verdict to `VERDICT: TAMPERED`.

The full chain exercised by every demo:

<p align="center">
  <img src="assets/architecture.svg" alt="Birkin System Architecture" width="100%" />
</p>

### Three attacks that are blocked + recorded + verifiable

| # | Attack | What happens | Verdict |
|---|-------|--------------|---------|
| 1 | Prompt injection / goal hijacking | A smuggled "[SYSTEM OVERRIDE]" instruction tries to coerce the agent into `shell.exec('rm -rf /etc /var /home')`. Policy denies; receipt + audit event record the attempt. | AUTHENTIC (attack blocked) |
| 2 | Unauthorized / privilege-escalating tool use | Agent attempts `fs.write` to `/etc/passwd` (denied), then `/home/user/.bashrc` (gated to `require_approval`, never executed), then a legitimate `/tmp/birkin/` write (allowed). | AUTHENTIC (escalation blocked) |
| 3 | Skill or policy tampering | A clean run is exported; one audit-event payload is then mutated to pretend the executed tool was `shell.exec`. `birkin verify` detects the event_hash mismatch. | TAMPERED (tampering detected) |

Run any single attack:

```bash
birkin attack 1   # prompt injection
birkin attack 2   # privilege escalation
birkin attack 3   # tampering detection
```

### `birkin verify` works offline

```bash
# Export a run package
birkin demo --out run.json

# Verify it offline — no Birkin server, no policy file, no agent runtime required.
birkin verify run.json
```

A run package is a self-contained JSON artifact. Everything required to recompute the verdict is embedded: the Birkin control-plane public key, the agent passport, the policy spec, the full audit ledger, and the Merkle checkpoint.

### CI smoke gate

```bash
bash scripts/ci_smoke.sh
```

This is the gate that has to stay green. It runs seven checks, fail-fast, and exits non-zero on any regression:

1. `pytest tests/` — the full unit + binding + tamper-matrix suite.
2. `birkin demo` — produces `VERDICT: AUTHENTIC`.
3. `birkin verify <demo.json>` — offline verify is `AUTHENTIC`.
4. `birkin attack 1` — prompt injection is **blocked** + `AUTHENTIC`.
5. `birkin attack 2` — privilege escalation produces all three decisions + `AUTHENTIC`.
6. `birkin attack 3` — clean is `AUTHENTIC`, tampered is `TAMPERED`, side by side.
7. `NullAgent` second-adapter proof — same engine, same verifier, `AUTHENTIC`.

The workflow in `.github/workflows/ci.yml` runs this gate on every push and PR. **If `scripts/ci_smoke.sh` ever exits non-zero, the release is red. No exceptions.**

---

## What this slice ships

Concrete, working, signed, and tested:

- **`birkin.crypto`** — Ed25519 sign/verify, deterministic canonical JSON, SHA-256, and a Merkle root implementation. The root of every claim Birkin makes.
- **`birkin.models`** — Pydantic v2 models for every artifact in the chain:
  - `AgentIdentity` — self-signed passport (public key + agent_id + runtime + policy + session + TTL).
  - `PolicyDecision` — `{decision, policy, rule, risk_score, reason}`.
  - `AuthorizationReceipt` — signed, portable proof of an allow/deny/require_approval.
  - `AuditEvent` — hash-chained (`prev_hash` → `event_hash`) and individually signed.
  - `MerkleCheckpoint` — signed Merkle root over a contiguous event range, with an anchor seam.
  - `RunPackage` — the offline-verifiable export artifact.
- **`birkin.policy`** — a real structured policy engine (not a shell script). Loads a JSON spec, evaluates rules top-down, returns a `PolicyDecision`. Ships with a safe-by-default policy (`policies/default.policy.json`).
- **`birkin.adapter`** — the `AgentAdapter` interface. Hermes becomes the first adapter (`birkin/adapters/hermes.py`), not the product. Adding a new runtime is a matter of implementing the protocol.
- **`birkin.audit`** — append-only ledger with `prev_hash` chaining and Merkle checkpoint issuance.
- **`birkin.engine`** — the control plane. Wires identity → intent → policy → receipt → action → audit → checkpoint → export.
- **`birkin.verify`** — the offline verifier. Seven checks, deterministic verdict, pasteable output.
- **`birkin.cli`** — the `birkin` command: `verify`, `demo`, `attack`, `run`, `keys`.

## The new primitive: the Authorization Receipt

Every side-effecting action — or refusal of one — produces exactly one signed `AuthorizationReceipt`. A receipt is portable: it can be presented to a downstream system, a human reviewer, or an offline verifier, and it stands on its own as cryptographic evidence that:

* the action was attempted under a specific agent identity;
* the arguments were exactly these (the receipt signs `args_hash`);
* the policy engine evaluated the request and returned a specific decision;
* the decision was bound to a specific `policy@version` and `rule`;
* the Birkin control plane vouches for all of the above via an Ed25519 signature.

A receipt is the smallest unit of agent accountability. Everything else in Birkin is built to make receipts unforgeable, un-replayable, and un-deniable.

---

## Credibility proof: tamper surface, binding strength, adapter seam

The credibility claim has three legs. Each is exercised by a dedicated test file and asserted by `scripts/ci_smoke.sh`.

### 1. Tamper surface completeness

Every realistic mutation of an exported run package must flip the verdict to `TAMPERED` (or `INVALID` for structural breakage). If any of the six attacks below still verifies as `AUTHENTIC`, the claim is incomplete.

| # | Attack | Mutation | Caught by | Verdict |
|---|--------|----------|-----------|---------|
| A | Receipt signature flip | Flip one byte of a receipt's `signature` | Signatures valid | TAMPERED |
| B | Identity rewrite | Replace `identity.json` with a freshly self-signed passport claiming a different `public_key` | **Identity bound to run** | TAMPERED |
| C | Policy version swap | Replace `policy.spec` with a more permissive policy, leave `policy.sha256` unchanged | Policy version verified | TAMPERED |
| D | Checkpoint root rewrite | Flip one hex char of `final_checkpoint.root` | Checkpoint matches | TAMPERED |
| E | Missing event | Delete event #7 from the middle of the chain | No missing events + Event chain valid + Checkpoint matches | TAMPERED |
| F | Reordered event | Swap events at positions 6 and 7 without rewriting hashes | Event chain valid + No missing events | TAMPERED |

`tests/test_tamper_matrix.py` runs every attack and asserts the verdict. Run `pytest tests/test_tamper_matrix.py -s` to see the printed matrix.

### 2. Receipt binding strength

A receipt's signature must cover *every* piece of context the credibility story depends on. Weak binding is the most common way these systems get dismissed — "the receipt says allow, but for which agent? under which intent? at which point in the chain?" — so every binding is asserted by a parametrized test.

The signed material on every receipt covers:

| Field | Binds |
|-------|-------|
| `agent_id` + `agent_public_key` | **which** agent (by stable id AND specific keypair) |
| `session_id` | **which** execution of that agent |
| `intent_hash` | **what** the agent publicly said it would do, before any action |
| `action` + `tool` | **which** capability was attempted |
| `args_hash` | **what** arguments were passed (SHA-256 over canonical JSON) |
| `decision` + `policy` + `rule` | **what** the policy engine decided, under which version, by which rule |
| `risk_score` + `reason` | the structured risk output |
| `prior_event_hash` | **where** in the audit chain this receipt was issued (prevents lift-and-replay into a different run) |

`tests/test_receipt_binding.py::test_receipt_binds` is parametrized over 12 mutations. Each test mints an AUTHENTIC receipt, mutates exactly one field, and asserts the signature no longer verifies. Run `pytest tests/test_receipt_binding.py -s` to see the printed binding-strength table.

### 3. Adapter seam reality

`AgentAdapter` is a Protocol; that alone is a claim. The proof is that a *second*, deliberately trivial adapter sits under the same Birkin control plane, produces the same kind of signed receipts, and verifies `AUTHENTIC` through the same offline verifier.

`birkin/adapters/null_agent.py` is that second adapter. It exposes exactly one tool, `null.ping`, which has no side effect. The point is not the tool — the point is that the same `Engine`, `AuditLedger`, `AuthorizationReceipt`, `MerkleCheckpoint`, and `verify_package` flow that governs Hermes also governs NullAgent without a single branch.

`tests/test_null_adapter.py::test_null_agent_and_hermes_produce_compatible_packages` runs both adapters through the same engine and asserts both verify `AUTHENTIC`:

```
============================================================
CROSS-ADAPTER COMPATIBILITY — same engine, same verifier
============================================================
  hermes      ->  AUTHENTIC
  null        ->  AUTHENTIC
============================================================
```

The next adapter — an MCP stub, a managed runtime, a custom bot — drops in by implementing the same Protocol. Nothing else changes.

---

## Export package hygiene: the manifest

Every `RunPackage` carries a `manifest` as its first field. The verifier reads it *before* any signature check; if the manifest references a schema the verifier doesn't know, the verdict is `TAMPERED` (or `INVALID` if the manifest is missing entirely) — never silently `AUTHENTIC`.

```json
{
  "schema": "birkin.run.package@1",
  "manifest": {
    "evidence_format": "birkin.run.package@1",
    "identity_scheme": "birkin.identity@1",
    "receipt_scheme":  "birkin.receipt@1",
    "audit_event_scheme": "birkin.audit@1",
    "checkpoint_scheme": "birkin.checkpoint@1",
    "policy_decision_scheme": "birkin.policy.decision@1",
    "verifier_min_version": "0.1.0"
  },
  "birkin_version": "0.1.0",
  "run_id": "...",
  "..."
}
```

`tests/test_manifest.py` proves that an unknown receipt scheme, a missing manifest key, or a missing manifest entirely all flip the verdict. Future Birkin versions that change a schema MUST bump the corresponding manifest entry; otherwise old verifiers will refuse to verify the new package rather than misinterpreting the bytes.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                              Agent runtime                            │
│                       (Hermes today, others tomorrow)                 │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  AgentAdapter (Protocol)
                               │  make_identity / declare_intent /
                               │  build_action_request / execute
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                              Birkin Engine                            │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────────────────┐   │
│  │  Identity   │   │ PolicyEngine │   │      AuditLedger          │   │
│  │  (passport) │──▶│              │──▶│ prev_hash → event_hash    │   │
│  └────────────┘   │  structured   │   │ signed events             │   │
│                   │  decisions    │   │ MerkleCheckpoint          │   │
│                   └──────┬───────┘   └──────────────────────────┘   │
│                          │                                          │
│                          ▼                                          │
│               ┌──────────────────────┐                              │
│               │ AuthorizationReceipt  │  (signed, portable)         │
│               └──────────────────────┘                              │
└──────────────────────────────────────────────────────────────────────┘
                               │
                               ▼  export
┌──────────────────────────────────────────────────────────────────────┐
│                          RunPackage (.json)                           │
│  identity · policy · events · receipts · checkpoints                  │
│  birkin verify  →  AUTHENTIC | TAMPERED | INVALID                     │
└──────────────────────────────────────────────────────────────────────┘
```

## Data models (canonical JSON shapes)

### AgentIdentity (passport)

```json
{
  "schema_version": "birkin.identity@1",
  "agent_id": "demo-agent-01",
  "public_key": "base64-ed25519",
  "runtime": "hermes-0.1.0",
  "policy": "default@1.0.0",
  "session_id": "uuid",
  "issued_at": "2026-08-21T...",
  "expires_at": "2026-08-21T...",
  "signature": "base64-ed25519 over the canonical subset above"
}
```

### PolicyDecision

```json
{
  "schema_version": "birkin.policy.decision@1",
  "decision": "allow",
  "policy": "default@1.0.0",
  "rule": "fs.write.sandbox.allow",
  "risk_score": 20,
  "reason": "Writes to the sandboxed /tmp/birkin/ directory are permitted."
}
```

### AuthorizationReceipt

```json
{
  "schema_version": "birkin.receipt@1",
  "receipt_id": "uuid",
  "agent_id": "demo-agent-01",
  "agent_public_key": "base64-ed25519",
  "session_id": "uuid",
  "intent_hash": "sha256-of-declared-intent-or-null",
  "action": "tool.invoke",
  "tool": "fs.write",
  "args_hash": "sha256-of-canonical-args",
  "decision": "allow",
  "policy": "default@1.0.0",
  "rule": "fs.write.sandbox.allow",
  "risk_score": 20,
  "reason": "...",
  "prior_event_hash": "sha256-of-most-recent-audit-event-at-issue-time",
  "issued_at": "...",
  "signature": "base64-ed25519 by the Birkin control plane over the above fields"
}
```

### AuditEvent

```json
{
  "schema_version": "birkin.audit@1",
  "event_id": "uuid",
  "sequence": 7,
  "timestamp": "...",
  "type": "tool.executed",
  "actor": "demo-agent-01",
  "session_id": "uuid",
  "receipt_id": "uuid",
  "prev_hash": "sha256-of-prior-event.event_hash",
  "payload": { "...": "..." },
  "event_hash": "sha256-of-canonical-subset",
  "signature": "base64-ed25519 over event_hash"
}
```

### MerkleCheckpoint

```json
{
  "schema_version": "birkin.checkpoint@1",
  "checkpoint_id": "uuid",
  "sequence_range": [1, 17],
  "leaf_count": 17,
  "root": "sha256-hex-of-merkle-root",
  "anchors": [{"kind": "local"}],
  "timestamp": "...",
  "signature": "base64-ed25519 by the Birkin control plane"
}
```

### RunPackage

```json
{
  "schema": "birkin.run.package@1",
  "manifest": {
    "evidence_format": "birkin.run.package@1",
    "identity_scheme": "birkin.identity@1",
    "receipt_scheme":  "birkin.receipt@1",
    "audit_event_scheme": "birkin.audit@1",
    "checkpoint_scheme": "birkin.checkpoint@1",
    "policy_decision_scheme": "birkin.policy.decision@1",
    "verifier_min_version": "0.1.0"
  },
  "birkin_version": "0.1.0",
  "run_id": "uuid",
  "exported_at": "...",
  "birkin_public_key": "base64-ed25519",
  "identity": { /* AgentIdentity */ },
  "policy": {"name": "default", "version": "1.0.0", "sha256": "...", "spec": { /* ... */ }},
  "intent": {"text": "...", "declared_at": "...", "extras": {}},
  "events": [ /* AuditEvent[] */ ],
  "receipts": [ /* AuthorizationReceipt[] */ ],
  "checkpoints": [ /* MerkleCheckpoint[] */ ],
  "final_checkpoint": { /* MerkleCheckpoint */ },
  "notes": "optional human-readable note"
}
```

---

## Verifier guarantees

`birkin verify` runs **nine** independent checks. The verdict is `AUTHENTIC` only if all nine pass.

| # | Check | What it proves |
|---|-------|----------------|
| 0 | Manifest + schema versions | The package's manifest declares schemas this verifier knows. Future format changes break loudly, not silently. |
| 1 | Event chain valid | No event was inserted, removed, or mutated (`prev_hash` linkage + `event_hash` self-consistency). |
| 2 | Signatures valid | Every event, receipt, and checkpoint is genuinely signed by the claimed Birkin control-plane key. |
| 3 | Policy version verified | The policy spec embedded in the package hashes to the value the run claims (`policy.sha256`). |
| 4 | Identity verified | The agent passport's self-signature verifies — the agent possessed the private key for the public key it claimed. |
| 5 | No missing events | Sequence numbers are dense `1..N`. |
| 6 | Checkpoint matches | The Merkle root recomputed from the in-range event hashes equals the signed checkpoint root, and the checkpoint signature is valid. |
| 7 | Authorization receipts valid | Every side-effecting audit event references a real, signature-valid receipt. |
| 8 | Identity bound to run | The identity's `public_key` matches what `session.start` recorded (signed by Birkin, cannot be tampered with), AND every receipt's `agent_public_key` / `agent_id` / `session_id` matches the package identity, AND every receipt's `prior_event_hash` exists in the audit chain. Catches identity-swap and lift-and-replay attacks. |

The output is deterministic and identical across machines and runs.

---

## CLI

```text
birkin version                       Print version.
birkin keys                          Generate a fresh Birkin control-plane Ed25519 keypair.
birkin run --tool fs.write \         Run a single tool under Birkin governance and export a run package.
        --args '{"path":"/tmp/birkin/x","data":"hi"}' \
        --agent-id demo --out run.json
birkin demo [--out run.json]         Run the end-to-end vertical slice and print the verdict.
birkin attack {1|2|3}                Run one of the three attack demos.
birkin verify <package.json>         Offline-verify a run package.
```

## Library

```python
from birkin import Engine, HermesAdapter, SigningKey, load_default_policy, verify_package

birkin_sk = SigningKey.generate()             # or load from env
policy    = load_default_policy()
adapter   = HermesAdapter()
engine    = Engine(birkin_signing_key=birkin_sk, policy=policy, adapter=adapter)

identity = adapter.make_identity(agent_id="my-bot", policy_ref=policy.ref)
engine.start_session(identity)
engine.declare_intent(identity, adapter.declare_intent(identity, "summarize the report"))

req     = adapter.build_action_request(tool="fs.write",
                                       args={"path": "/tmp/birkin/x", "data": "hi"})
receipt = engine.attempt_action(identity, req)
if receipt.decision == "allow":
    engine.execute(identity, req, receipt)

engine.checkpoint()
engine.end_session(identity)
pkg = engine.export(identity=identity)

report = verify_package(pkg)
assert report.verdict == "AUTHENTIC"
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite (40 tests across 5 files) covers:

* **`test_vertical_slice.py`** — crypto round-trips, model self-verification, policy evaluation for every decision type, the end-to-end AUTHENTIC path, and tamper detection (event payload mutation, receipt mutation).
* **`test_tamper_matrix.py`** — the six-attack tamper surface matrix (signature flip, identity rewrite, policy swap, checkpoint root rewrite, missing event, reordered event).
* **`test_receipt_binding.py`** — 12-binding strength matrix proving every receipt field is cryptographically bound.
* **`test_null_adapter.py`** — the second-adapter proof (Hermes + NullAgent both AUTHENTIC via the same engine + verifier).
* **`test_manifest.py`** — manifest + schema-version gate (unknown scheme, missing key, missing manifest).

---

## Project layout

```
birkin/
├── birkin/
│   ├── __init__.py          # Public API surface
│   ├── crypto.py            # Ed25519, canonical JSON, SHA-256, Merkle root
│   ├── models.py           # AgentIdentity, Receipt, AuditEvent, Checkpoint, RunPackage, PACKAGE_MANIFEST
│   ├── policy.py           # PolicySpec + structured decisions
│   ├── adapter.py          # AgentAdapter Protocol + BaseAdapter
│   ├── adapters/
│   │   ├── hermes.py       # First concrete adapter
│   │   └── null_agent.py   # Second adapter — proves the seam
│   ├── audit.py            # AuditLedger + MerkleCheckpoint issuance
│   ├── engine.py           # The control plane
│   ├── verify.py           # Offline verifier (9 checks)
│   └── cli.py              # `birkin` command
├── policies/
│   └── default.policy.json
├── demos/
│   ├── end_to_end.py       # The 60-second AUTHENTIC demo
│   └── attacks.py          # The three attacks
├── tests/
│   ├── test_vertical_slice.py     # End-to-end + tamper detection
│   ├── test_tamper_matrix.py     # 6-attack tamper surface matrix
│   ├── test_receipt_binding.py   # 12-binding strength matrix
│   ├── test_null_adapter.py      # Second-adapter proof
│   └── test_manifest.py          # Manifest + schema-version gate
├── scripts/
│   ├── demo_all.py         # End-to-end + all attacks in one shot
│   └── ci_smoke.sh         # The CI gate (7 fail-fast checks)
├── .github/workflows/ci.yml # GitHub Actions: runs scripts/ci_smoke.sh on every push/PR
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Scope locks — what is *deliberately deferred to the next cycle*

This slice is intentionally narrow. The following are designed-in seams, not missing features:

* **Multi-bot roster + governed groups + war-room PWA** — `AgentAdapter` already supports multiple adapters (Hermes + NullAgent today); the group / war-room layer is not built.
* **Full MCP Gateway** — the seam is `AgentAdapter`; an MCP adapter is the natural next addition. NullAgent proves the seam; MCP is the production adapter. Only what the vertical slice needs is implemented.
* **External anchoring** — `MerkleCheckpoint.anchors` is a `list[dict]` today with `{"kind": "local"}` only. A transparency-log / timestamp-authority / on-chain anchor is a fill-in-the-list change.
* **Policy Replay UI** — events are already structured for replay; the UI is not built.
* **Attack Lab productization** — the three attacks in `demos/attacks.py` plus the six-attack tamper matrix in `tests/test_tamper_matrix.py` are evidence, not a productized attack lab.
* **Supply-chain hardening, OpenTelemetry, full operator surface** — out of scope until the slice is undeniable.
* **Policy versioning server, dynamic policy hot-reload** — policies are pinned per run via `policy.sha256` in the export package.

### Sacred tests — release blockers

Two test files encode the closed credibility surface that makes Birkin worth taking seriously:

* `tests/test_tamper_matrix.py` — six realistic tampering attacks; every one must verify as `TAMPERED` (or `INVALID`), never `AUTHENTIC`.
* `tests/test_receipt_binding.py` — twelve receipt fields, each cryptographically bound into the signed material; mutating any one alone must invalidate the signature.

**Any PR that removes, weakens, skips, or modifies a test in these two files in a way that accepts a previously-rejected mutation as `AUTHENTIC` is a release blocker.** See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rule and the design-discussion protocol for the rare case where a future schema change genuinely requires a previously-tampered mutation to verify as `AUTHENTIC`.

## Extension points

* **New runtime?** Implement `birkin.adapter.AgentAdapter`. Everything else is unchanged.
* **New tool?** Register it on the adapter's tool registry; the policy engine already dispatches by `tool` name.
* **New policy?** Drop a JSON file in `policies/` and pass `--policy` to `birkin run` or instantiate `PolicySpec.load(...)`.
* **External anchoring?** Subclass `MerkleCheckpoint` and append to `anchors`; the verifier only checks the signature over what is there.
* **A second Birkin deployment / federation?** Each deployment has its own `birkin_public_key`; receipts verify against whichever key issued them. The package format is already portable.

## Design principles

1. **The receipt is the primitive.** Everything else exists to make receipts unforgeable.
2. **The verifier needs nothing but the package.** Offline verification is non-negotiable.
3. **Default deny.** Any tool not explicitly allowed is blocked. No silent falls-through.
4. **Sign what you mean.** Every signature covers an explicit field set, so adding a field does not retroactively break old signatures.
5. **The chain is the evidence.** `prev_hash` + Merkle checkpoint means historical state is frozen at checkpoint time.
6. **Local-first.** Birkin does not phone home. Your agent's behavior is your evidence.
7. **MIT-licensed.** Fork it, embed it, audit it.

## License

MIT. See `LICENSE`.

---

Birkin is not finished. It is undeniable in this slice. The next cycle adds the rest of the destination — multi-bot groups, full MCP gateway, policy replay, external anchoring — on top of this evidence plane, not beside it.
