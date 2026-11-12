# Show HN: Birkin — iPhone-controlled Hermes agent with hash-chained audit log and tamper detection

[Link to GitHub: https://github.com/NickAiNYC/Birkin]

I was worried my local AI agent would go rogue. So I built Birkin—a governance layer for Hermes with three features that aren't available anywhere else:

1. **Tamper-evident audit log** — every action is hashed into a chain. If someone (including the agent) tries to cover its tracks, the hash chain catches it. Unlike append-only logs, an altered record fails verification.

2. **Tamper test** — literally replace the audit.db file and run verify-chain.py. It detects the swap. Works in CI.

3. **Pre-execution kill switch** — intercept high-risk actions before they run. Telegram approval flows. Configurable timeout/deny policies.

It's open source, runs locally, and includes an iPhone PWA for emergency control from anywhere.

The threat model is honest about what it doesn't prevent (root-level host compromise, prompt injection on the model itself). But for the things it does cover—proving what your agent did, detecting tampering, stopping it from deleting files—there's nothing like it.

Looking for feedback on the threat model, and I'm curious if people would find RBAC per skill or distributed Merkle-tree anchoring useful.

[Demo: 45-second asciinema showing governance check → tamper simulation → detection]

<!--
Post on Tuesday or Wednesday morning US Eastern time (~9am).
Title must start with "Show HN:" for HN algorithm to pick it up.
Reply to EVERY comment in the first 24 hours.
Emphasize: tamper-evident (the hash chain), open source, no tokens, just engineering.
If asked "why not use X," have a ready answer (X doesn't have tamper detection / X isn't local-first / X requires trust in the provider).
-->
