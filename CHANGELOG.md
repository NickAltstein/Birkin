# Changelog

## [1.0.0] - 2026-11-10

### Added
- Signed Trifecta Card pipeline (`receiptd.card`) with deterministic rule classifier (`rules.yaml`), session parser, redact engine, and 1200x630 social preview card renderer (`card.png`, `card.svg`, `card.json`).
- `receiptd verify-card CARD.json` command: validates Ed25519 signature and JCS canonical digest; outputs `VALID (<verdict>)` or `TAMPERED (<reason>)`.
- `receiptd stop-gate` command and Claude Code `Stop` hook: halts task completion with exit code 2 if tests fail, requiring signed completion receipts.
- Demo fixtures for immediate verification without local session history (`fixtures/trifecta_demo/{red,yellow,green}.jsonl`).
- Network isolation test verifying zero outbound network calls and zero file content or prompt leakage.

### Changed
- Replaced legacy regex-based trifecta scanner (`receiptd/trifecta.py`) with full `receiptd.card` pipeline.
- Updated `receiptd card` command with `--session`, `--last`, `--out`, and `--redact-paths` flags.
- Package classifier updated to `Development Status :: 4 - Beta`.
- Updated benchmarks in package description to reflect measured 0.02ms in-process evaluation and ~67ms cold CLI hook latency.

## [0.2.0] - 2026-11-05

### Added
- Honest component status table in README.
- Explicit LIMITATIONS section (single-user, local-first, limited adapters, no production scheduler).
- Clarified one-sentence unique capability: offline-verifiable authorization evidence for agent side-effects.
- Pinned Python >=3.10 more clearly in install notes.
- Every major README claim now has a corresponding command or test name that a stranger can run in <5 minutes.

### Changed
- README lead sentence focuses on the authorization + evidence plane, not historical iMessage/Hermes remote control.
- Hermes is documented only as one example runtime adapter.

### Fixed
- Install instructions verified on clean clone with `pip install -e .`.

## [0.1.0] - earlier

Initial vertical slice: signed receipts, policy engine, hash-chained audit, Merkle checkpoints, offline verification, tamper matrix, receipt binding tests, NullAgent adapter.
