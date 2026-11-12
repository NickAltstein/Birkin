# Birkin Launch Checklist

All content below is ready to copy-paste. You post — no credentials or tokens needed from me.

---

## Launch Checklist

- [ ] **Merge all branches** (done — see git log)
- [ ] **GitHub description + topics set** (done — `.github/GITHUB_SETUP_DONE`)
- [ ] **Demo GIF in README** (`static/tamper-demo.gif` — embedded at line ~53 of README.md)
- [ ] **Post to Show HN** — Tuesday or Wednesday, 9am US Eastern
- [ ] **Post Twitter/X thread** — same day as Show HN, within the hour
- [ ] **Post Reddit r/LocalLLaMA** — same day
- [ ] **Post Reddit r/MachineLearning** — same day (can use the same post)
- [ ] **Post Dev.to article** — write from `docs/social-media/devto-outline.md`
- [ ] **Monitor + reply** — respond to every comment for the first 24 hours

---

## Show HN Post

**Where:** https://news.ycombinator.com/submit  
**Best time:** Tuesday or Wednesday, 9am US Eastern  
**Title:** (must start with "Show HN:")

```
Show HN: Birkin — iPhone-controlled Hermes agent with hash-chained audit log and tamper detection
```

**Text body:**

```
I was worried my local AI agent would go rogue. So I built Birkin—a governance layer for Hermes with three features that aren't available anywhere else:

1. Tamper-evident audit log — every action is hashed into a chain. If someone (including the agent) tries to cover its tracks, the hash chain catches it. Unlike append-only logs, an altered record fails verification.

2. Tamper test — literally replace the audit.db file and run verify-chain.py. It detects the swap. Works in CI.

3. Pre-execution kill switch — intercept high-risk actions before they run. Telegram approval flows. Configurable timeout/deny policies.

It's open source, runs locally, and includes an iPhone PWA for emergency control from anywhere.

The threat model is honest about what it doesn't prevent (root-level host compromise, prompt injection on the model itself). But for the things it does cover—proving what your agent did, detecting tampering, stopping it from deleting files—there's nothing like it.

Looking for feedback on the threat model, and I'm curious if people would find RBAC per skill or distributed Merkle-tree anchoring useful.

Demo: 45-second asciinema showing governance check → tamper simulation → detection (static/tamper-demo.gif in the repo).
```

**URL to submit:** `https://github.com/NickAiNYC/Birkin`

**HN tips:**
- Reply to EVERY comment in the first 24 hours — HN ranks by engagement velocity
- If asked "why not use X": answer is X doesn't have tamper detection / X isn't local-first / X requires trust in the provider
- If crypto confusion appears: "No tokens, no DAO, no blockchain — just agentic AI security tooling"

Full draft: [`docs/social-media/show-hn-post.md`](docs/social-media/show-hn-post.md)

---

## Twitter / X Thread

Post as a thread. Replace `[GIF_LINK]` with the direct URL to `static/tamper-demo.gif` on GitHub.

**Tweet 1 — Hook**
```
Giving an AI agent access to your files, APIs, and shell is terrifying.

Hallucinations become destructive actions. A prompt injection can exfiltrate your secrets.

So I built Birkin: a hash-chained audit log + kill switch for local AI agents.

Open source. No tokens. Just provable safety. 🧵
```

**Tweet 2 — Demo**
```
Here's what it looks like when Birkin catches a tamper attempt:

[GIF_LINK]

Every row in the audit DB stores SHA-256(prev_hash || payload). Mutate one byte anywhere — even after bypassing database triggers — and verification fails.

One command proves it: ./tests/tamper-test.sh
```

**Tweet 3 — The 5-Gate Governance Check**
```
Birkin runs a 5-gate governance check against your agent:

1. Is the agent process running and responding?
2. Is the audit chain intact? (no tampered rows)
3. Are all skills git-versioned with committed changes?
4. Has the model drifted from its signed behavioral baseline?
5. Is the health endpoint reporting clean?

Pure deterministic logic. No AI guessing about AI.

./governance-check.sh → "BIRKIN GOVERNANCE INTACT"
```

**Tweet 4 — The Hard Problem**
```
The weakest link: what if an attacker replaces the entire audit.db?

verify-chain.py would verify the replacement chain as valid.

So Birkin posts the chain tip hash to Telegram hourly. Full DB replacement produces a new tip that doesn't match published history.

Tampering becomes provable even after the fact.
```

**Tweet 5 — CTA**
```
Birkin is open source, MIT licensed, runs on Docker.

If you run a local AI agent (Hermes, anything OpenAI-compatible), Birkin wraps it without touching your install.

GitHub: https://github.com/NickAiNYC/Birkin

Looking for feedback on the threat model — especially attack vectors I missed.

What would you want in a kill switch for your agent?
```

Full draft: [`docs/social-media/twitter-thread.md`](docs/social-media/twitter-thread.md)

---

## Reddit Posts

Use the same post for both **r/LocalLLaMA** and **r/MachineLearning** (post a few hours apart).

**Title:**
```
I was worried my local AI agent would go rogue, so I built a hash-chained audit log with a kill switch. Open source—looking for feedback on the threat model.
```

**Body:**
```
I've been running a local AI agent (Hermes from Nous Research) to handle real tasks: competitor monitoring, daily briefings, code governance checks. It has shell access, web access, file access.

That scared me. An agent that can do things can also do the wrong things.

So I built Birkin — a governance layer that wraps any Hermes-compatible agent without modifying the agent itself.

**What it does:**

- **Hash-chained SQLite audit log**: every action the agent takes is SHA-256 chained (SHA-256(prev_hash || payload)). Mutate any row — even after bypassing database triggers — and verify-chain.py catches it. CI-tested on every push.
- **5-gate deterministic governance check**: process liveness, audit chain integrity, skill version pinning, behavioral drift against a signed baseline, health endpoint.
- **Kill switches**: agent-stop.sh (graceful) and agent-lockdown.sh (network isolation). Both writes are themselves audit-logged.
- **Drift detection**: 5 benchmark questions, bigram cosine similarity, threshold 0.85. Catches model swaps and config changes that shift behavior.
- **iPhone PWA**: full-screen Open WebUI from Safari home screen.

**The honest threat model** (from THREAT_MODEL.md):

- ✅ Catches: row mutation, deletion, mid-chain insertion, mutation after trigger bypass
- ❌ Does NOT catch: attacker replacing the entire DB, log omission (agent action never logged), root-level host compromise, prompt injection on the agent itself

The DB replacement attack is the one I'm most worried about. The roadmap item is posting the chain tip hash to Telegram hourly — so a full replacement produces a tip that doesn't match published history.

**GitHub**: https://github.com/NickAiNYC/Birkin

**Not crypto**: I'm aware there's a "Hermes" crypto project. This is completely unrelated — no tokens, no DAO, no blockchain. Just agentic AI security tooling.

---

What I'm genuinely looking for:

1. Attack vectors I haven't thought of in the threat model
2. Opinions on the drift detection approach (bigram cosine vs. embedding similarity)
3. Anyone who's tried to solve the "prove your agent didn't do something bad" problem differently

Happy to discuss the architecture in comments.
```

Full draft: [`docs/social-media/reddit-post.md`](docs/social-media/reddit-post.md)

---

## Dev.to Article

**Where:** https://dev.to/new  
**Title:** `Why I added a kill-switch and hash-chained audit logs to my AI agent (and why you should too)`  
**Tags:** `ai`, `security`, `autonomousagents`, `opensource`

Write from the outline in [`docs/social-media/devto-outline.md`](docs/social-media/devto-outline.md).

Key assets to embed:
- `static/tamper-demo.gif` — the tamper-test demo (already in repo)
- Output of `./governance-check.sh` — paste as a code block
- Link to `THREAT_MODEL.md`

Cross-post canonical URL from your GitHub Pages or personal blog if you have one.

---

## Posting Order

1. **Tuesday or Wednesday, 9am Eastern** — Submit Show HN first
2. **Within 1 hour of Show HN** — Post Twitter thread (link to GitHub, not HN post)
3. **Same day, afternoon** — Post r/LocalLLaMA
4. **Same day, evening** — Post r/MachineLearning
5. **Day 2** — Publish Dev.to article, share link on Twitter

Monitor HN comments and reply within minutes when possible — early engagement drives ranking.
