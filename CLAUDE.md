# Receiptd

Always explore + plan before editing.

## What this repo is

Receiptd is an MIT-licensed, fail-closed authorization gate for AI agent tool calls.

* `receiptd/hooks/claude_code_gate.py`: Claude Code PreToolUse hook. Reads JSON on stdin, applies policy plus a blast-radius score, exits 2 to block.
* `receiptd/hooks/claude_code_stop_gate.py`: Stop hook. Blocks "done" until tests pass; honors `stop_hook_active` with a retry cap and a `gave_up` receipt.
* `receiptd/crypto.py`: Ed25519 keys, signing, canonical JSON.
* `receiptd/audit.py`: hash-chained ledger and Merkle checkpoints.
* `receiptd/verify.py`: offline verification (`receiptd verify`).
* `receiptd/policy.py`, `engine.py`, `models.py`: policy rules and evaluation.
* `receiptd/card/`: `receiptd card` (signed Trifecta hazard card) and `receiptd verify-card`.
* `receiptd/cli.py`: Typer CLI. `birkin` is a backward-compatible alias of `receiptd`.
* `birkin/`: Backward-compatibility shim mapping all legacy `birkin.*` imports and CLI hooks to `receiptd`.

## Stack

* Python >= 3.10 (CI targets 3.10 to 3.12), setuptools, Typer, Pydantic v2, `cryptography`.
* Tests: pytest under `tests/`.
* No network calls in the hook path. No new runtime dependencies without asking.

## Must pass before any commit

```sh
pip install -e ".[dev]"
pytest -q -rs
```

* Zero failures, zero unexpected skips. Paste the summary line in your report.
* Security changes must also pass on Linux: `docker run --rm -v $PWD:/w -w /w python:3.11 sh -c 'pip install -e ".[dev]" && pytest -q -rs'`
* Ledger verify must pass clean and fail tampered: `receiptd verify --ledger .receiptd/receipts.jsonl` exits 0 on an untouched ledger and exits 2 after any 1-byte edit, deletion, or reorder, naming the receipt sequence.
* Benchmarks: `python benchmarks/benchmark_overhead.py`. Report in-process and cold-hook numbers together, never one alone.

## Fail-closed rules (non-negotiable)

1. Any exception, parse error, missing key, or signing failure in the PreToolUse hook means deny (exit 2) and write a deny receipt. Never exit 0 on error.
2. Never weaken, skip, or special-case a policy rule to make a test pass. Fix the code or ask.
3. Symlink cycles, ELOOP, and unresolvable paths deny on every OS.
4. Every decision is appended to the ledger; receipts are never edited, reordered, or deleted.
5. A verify failure exits non-zero and names the receipt sequence number.
6. The Stop hook must never loop forever: respect `stop_hook_active` and the retry cap.
7. Every new deny path gets a test that proves it denies.

## Never touch without explicit approval

* `~/.receiptd/` (private key, state, ledgers): never read the private key into output, logs, or commits.
* `LICENSE`, `THREAT_MODEL.md` threat definitions, `policies/` defaults.
* `migrations/`, `systemd/`, `nginx/`, `deploy.sh`, `install*.sh` (deployment surface).
* Removing or renaming the `birkin` alias.
* Anything under `bench/mcpvenom/` that would vendor, modify, or import mcpvenom code (license forbids it).

## Git

* Conventional commits, under 60 chars, no adjectives: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`.
* One commit per verified unit of work.
* Never push, force-push, rebase pushed history, or use `--no-verify` without approval.

## Claims and docs

* Only document what the code does on main. No invented metrics.
* Receiptd cannot see or prove which model answered. Never claim it does.
* Canonicalization is sorted-key compact JSON; do not call it RFC 8785 unless it is implemented.
* The Trifecta card is Ed25519-signed; verification is performed offline via `receiptd verify-card <card.json>`.

## Model use

Prefer Opus for routine work; use Fable only for complex multi-file security changes.

## Workflow

1. Explore: read the relevant files and tests first.
2. Plan: list the files you will change and the tests you will add.
3. Edit in small steps; run `pytest -q -rs` after each.
4. Report: what changed, test summary, anything left unverified.
5. Stop and ask when a change touches a never-touch path or loosens a fail-closed rule.
