---
name: birkin-audit
description: Verify cryptographic execution receipts, audit the local SHA-256 hash chain, and inspect blocked tool calls in .birkin/receipts.jsonl.
---

# Birkin Cryptographic Session Auditor

When the user invokes `/birkin-audit`, run the offline verification CLI to validate the integrity of the local `.birkin/receipts.jsonl` hash chain and Ed25519 signatures:

```bash
python3 -m birkin.cli verify --ledger .birkin/receipts.jsonl --format table
```

Report the total frames verified, any `BLOCKED_FAIL_CLOSED` events, and confirm whether the hash chain verdict is `AUTHENTIC` or `TAMPERED`.
