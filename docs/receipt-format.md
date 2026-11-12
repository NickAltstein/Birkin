# Receiptd ledger receipt format

This document specifies the JSONL ledger that the PreToolUse hook (`receiptd/hooks/claude_code_gate.py`), the Stop hook (`receiptd/hooks/claude_code_stop_gate.py`), and `receiptd.ledger` write, and that `receiptd verify --ledger` checks. It matches those modules as of this commit. Another agent runtime can append the same lines and check them with the same rules.

The integer field `v` is the receipt version. Every writer in this tree sets `v` to `1`. `receiptd verify` does not read `v` and does not reject other values. The JSONL ledger has no version identifier besides that field.

Two other signed documents in this repository are different objects and are not this format:

- Trifecta `card.json` is signed by `receiptd.card.signing`. Its serializer is not used for ledger lines.
- `receiptd verify <package.json>` checks a run package (`birkin.receipt@1` and the schemas in `receiptd/models.py`). That command exits `1` when the verdict is not `AUTHENTIC`, and `2` when the file is missing. The field lists below do not apply to it.

## Canonical JSON (sorted keys)

Every signature, receipt hash, checkpoint hash, argument hash from the PreToolUse hook, and on-disk ledger line uses `receiptd.crypto.canonical_json`:

```text
json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
```

That is canonical JSON (sorted keys):

- Object keys are sorted in Python's default string order (Unicode code point order). Nested objects are sorted the same way.
- The separators are a comma and a colon, with no spaces.
- The encoding is UTF-8.
- String escaping is Python `json.dumps`: quotation marks, backslashes, and control characters are escaped; `/` is not escaped. Because `ensure_ascii` is false, non-ASCII characters are raw UTF-8, not `\u` escapes.
- Integers are encoded without a fraction. A non-integer uses Python `json.dumps` number encoding (`3.7`, not `3.70`).

This encoding is the output of that `json.dumps` call. It is not an RFC 8785 encoding.

`canonical_json_subset(obj, fields)` builds a new object containing each listed name that is actually present, then runs `canonical_json` on it. A listed name that is absent is omitted. It is not encoded as `null`.

The hooks' `canonicalize_jcs` returns those UTF-8 bytes decoded to a string. Signatures and hashes use the bytes.

## Ledger file

The ledger is UTF-8 JSONL. The reference writer appends one canonical JSON object and a newline (`\n`) per record. `receiptd verify` parses each non-blank line with `json.loads` and recomputes canonical bytes itself, so a line does not have to already be in canonical form for the hash check to pass. A line that is not JSON makes `receiptd verify` exit `2`. (The hook's chain cursor skips a line it cannot parse when choosing the next `prev_hash`. The verifier does not.)

A line whose `type` is the string `checkpoint` is a checkpoint. Every other JSON object is a receipt. Receipts do not carry `type`.

## Receipt fields

`build_signed_receipt` emits the fields below. The Ed25519 signature covers only the eleven names in **Signed fields**. The receipt hash covers the signed fields plus everything in **Outside the signature**, and does not cover `hash` or `receipt_sha256`.

### Signed fields

These eleven names are `SIGNABLE_RECEIPT_FIELDS`. The signature input is their canonical JSON.

| Field | Type | Meaning | Required |
| --- | --- | --- | --- |
| `v` | integer | Receipt version. Writers pass `1`. | Writer always sets it. Verifier does not inspect the value. If present, it is inside the signature. |
| `ts` | string | Timestamp from `datetime.now(timezone.utc).isoformat()`, for example `2026-11-12T09:08:43.095523+00:00`. | Writer always sets it. Verifier does not parse it. |
| `session_id` | string | `session_id` from the hook stdin object, else `RECEIPTD_SESSION_ID`, else `default`. | Writer always sets it. |
| `tool` | string | Tool name. The Stop hook uses the string `stop_gate`. | Writer always sets it. |
| `args_sha256` | string | 64 lowercase hex characters. PreToolUse: SHA-256 of the canonical JSON bytes of `tool_input` (missing input is hashed as `{}`). Stop hook: SHA-256 of the UTF-8 test-command string, not of a JSON object. | Writer always sets it. |
| `decision` | string | PreToolUse writes `allow` or `deny`. Stop hook writes `ALLOWED_VERIFIED` (tests passed), `BLOCKED_FAIL_CLOSED` (tests failed), or `gave_up` (retry cap reached). Signing failure forces `deny`. | Writer always sets it. Verifier constrains it only for an unsigned receipt: that decision must be `deny`. |
| `rule_ids` | array of strings | Rule ids that fired, in scan order. An allow with no match is `[]`. Stop hook writes `["RULE:TESTS_PASS"]`. | Writer always sets it. |
| `blast_radius` | integer | PreToolUse starts at `10`, adds the matched rule weights, and caps at `100`. A missing tool name or a non-object `tool_input` scores `100` and is denied. Any triggered rule denies, as does a score of `75` or more. Stop success writes `0`; stop failure writes `100`. | Writer always sets it. |
| `reason` | string | PreToolUse allow is `allowed`. A deny is `triggered rules: ` plus the ids joined by `", "`. | Writer always sets it. |
| `policy_sha256` | string | 64 lowercase hex characters. See [Limitations](#limitations). Not a hash of the regexes that ran. | Writer always sets it. |
| `prev_hash` | string | 64 lowercase hex characters. Hash of the previous receipt, or the genesis value for the first receipt. | Writer always sets it. Verifier requires `prev_hash`, or `prev_receipt_hash` when `prev_hash` is missing or empty, to equal the previous receipt hash. |

### Outside the signature

The writer adds these after signing. They are inside the receipt hash. They are not inside the Ed25519 message, so editing one of them does not by itself make `sig` fail. It does make the stored `hash` fail unless that hash is recomputed, and a later receipt's signed `prev_hash` then no longer matches.

| Field | Type | Meaning | Required |
| --- | --- | --- | --- |
| `sig` | string | Standard Base64 (not URL-safe) of the 64-byte Ed25519 signature. No whitespace. | Present on a signed receipt. Absent on an unsigned deny. If present, the verifier checks it. If absent, the line is accepted only when `signing_error` is true and `decision` is `deny`. |
| `pubkey_id` | string | 64 lowercase hex characters: SHA-256 of the raw 32-byte Ed25519 public key (not of the PEM text). | Writer sets it on a signed receipt. The verifier does not compare it to the key it uses. |
| `seq` | integer | 1-based count of receipt lines only. Checkpoints do not consume a number. The writer sets `seq` to the count of existing receipt lines plus one. | Writer always sets it. If omitted, the verifier uses the count of receipt lines seen so far. Checkpoint ranges look receipts up by this number. |
| `tool_name` | string | Copy of `tool`. | Writer always sets it. Verifier uses it only as a display fallback when `tool` is missing. |
| `blast_radius_score` | integer | Copy of `blast_radius`. | Writer always sets it. Display fallback when `blast_radius` is absent. |
| `triggered_rules` | array of strings | Copy of `rule_ids`. | Writer always sets it. Not read by the verifier. |
| `prev_receipt_hash` | string | Copy of `prev_hash`. | Writer always sets it. Verifier reads it only when `prev_hash` is missing. |
| `hash` | string | 64 lowercase hex characters. SHA-256 of the canonical JSON of the receipt after the fields above and any extra fields are added, and before `hash` and `receipt_sha256` are inserted. | Writer always sets it. If `hash` or `receipt_sha256` is present, it must equal the recomputed digest. The verifier prefers `hash` and falls back to `receipt_sha256`. Both names are removed before recomputing. |
| `receipt_sha256` | string | Copy of `hash`. | Writer always sets it. See `hash`. |

### Extra fields

`extra_fields` are copied onto the receipt when the name is not already set. They are inside the receipt hash and outside the signature.

The PreToolUse hook adds:

| Field | Type | Meaning |
| --- | --- | --- |
| `latency_ms` | number | `round((perf_counter elapsed) * 1000, 2)` from process start to the ledger write. The deadline path stores the deadline in milliseconds instead. |
| `tool_input` | any JSON value | The `tool_input` object from stdin (or `{}` when it was missing). |

The Stop hook adds `event_type` (`"STOP_GATE"`), `test_command` (string), `test_exit_code` (integer), `retries` (integer), `stop_hook_active` (boolean), and `latency_ms` (number). A failed or gave-up stop also adds `test_output_sha256` (64 hex characters), the SHA-256 of the diagnostic text.

### Unsigned deny receipt

When signing cannot be done, or the hook deadline fires, the writer appends a receipt with `signing_error: true` (boolean), `decision` `"deny"`, no `sig`, and no `pubkey_id`. The reason is `receiptd: signing unavailable` or `receiptd: hook deadline exceeded ({ms}ms)`. The deadline path sets `rule_ids` to `["HOOK_DEADLINE_EXCEEDED"]` and `blast_radius` to `100`. The receipt is still hashed and linked by `prev_hash`. `receiptd verify` accepts that shape and counts it. Any other receipt without `sig` is a failure.

## Signing

The algorithm is Ed25519, as implemented by the `cryptography` library (`Ed25519PrivateKey.sign`). The signed message is the canonical JSON bytes of the eleven fields above. The code does not hash those bytes before signing; Ed25519 is computed over the bytes themselves. The same construction, with the four checkpoint fields below, signs a checkpoint.

Keys live in `$RECEIPTD_KEY_DIR`, or `~/.receiptd` when that variable is unset. The directory mode is `0700`.

| File | Format | Mode |
| --- | --- | --- |
| `receiptd_ed25519.pem` | Unencrypted PKCS#8 PEM, Ed25519 private key | `0600` |
| `receiptd_ed25519.pub.pem` | SubjectPublicKeyInfo PEM, Ed25519 public key | `0644` |

`RECEIPTD_SIGNING_KEY`, or else `BIRKIN_SIGNING_KEY`, replaces the files for that process. If the value contains `BEGIN`, it is PEM. Otherwise the writer tries standard Base64 of the 32-byte seed, and if that fails it uses the UTF-8 bytes of the string as the seed.

`receiptd verify` checks signatures with, in order: the `--pubkey` option, then `RECEIPTD_PUBLIC_KEY`, then the public PEM from the key directory. The option and the environment variable are key material, not a filesystem path: PEM when the string contains `BEGIN`, otherwise standard Base64 of the raw 32-byte public key. The CLI help text calls `--pubkey` a path; the verifier does not open one. If `receiptd_ed25519.pub.pem` is missing, `receiptd verify` loads the private key, creating one when the directory has none, and uses that public key. `tools/verify_standalone.py` reads the public PEM file only and does not create a key.

## Hash chaining

Digests are SHA-256, written as 64 lowercase hex characters with no prefix.

The genesis value, for both the receipt chain and the checkpoint chain, is 64 `0` characters:

```text
0000000000000000000000000000000000000000000000000000000000000000
```

Receipt `prev_hash` links receipt to receipt in file order. Checkpoint lines are not links in that chain. The first receipt's `prev_hash` is the genesis value. Each later receipt's `prev_hash` is the previous receipt's `hash`.

The receipt hash is SHA-256 over the canonical JSON of the object with `hash` and `receipt_sha256` removed. On the writer's path those two fields are added only after the digest is computed, so the preimage includes `sig`, `pubkey_id`, `seq`, the alias fields, and any extra fields.

## Merkle checkpoints

The PreToolUse hook appends a checkpoint when the number of receipt hashes since the previous checkpoint, including the receipt just written, is at least the interval. The interval is `100` unless `--checkpoint-interval` sets it. If `RECEIPTD_CHECKPOINT_INTERVAL` is set to an integer, that value replaces the flag. A non-integer is ignored.

The Stop hook does not use that interval. It appends a checkpoint after a passing run and after a `gave_up` receipt, covering whatever receipts are not yet in a checkpoint. A failing stop that exits `2` does not append one.

`from_seq` is the previous checkpoint's `to_seq` plus one (or `1` when there has been no checkpoint). `to_seq` is the new receipt's `seq`. The leaves are the receipt `hash` values for the inclusive seq range, in increasing `seq` order. The reference writer's seq numbers follow append order, so that list is the uncheckpointed receipt hashes in file order.

`merkle_root` (`receiptd.crypto.merkle_root`):

1. Decode each leaf from hex to its raw 32-byte digest.
2. While more than one node remains, pair them left to right. The parent is SHA-256 of the raw left digest concatenated with the raw right digest (the bytes, not the hex text).
3. If a level has an odd node, that node is carried up unchanged. It is not duplicated and it is not hashed with itself.
4. The root is the final 32 bytes, written as lowercase hex.
5. An empty leaf list hashes to SHA-256 of the empty byte string, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. A single leaf's root is that leaf. The worked example is the single-leaf case: `merkle_root` equals the receipt `hash`.

The checkpoint signature covers only this canonical JSON object:

```text
{"from_seq":<int>,"merkle_root":"<hex>","prev_checkpoint_hash":"<hex>","to_seq":<int>}
```

`prev_checkpoint_hash` is the previous checkpoint record's `hash`, or the genesis value for the first checkpoint. That chain is separate from receipt `prev_hash`.

| Field | Type | Meaning | Required |
| --- | --- | --- | --- |
| `type` | string | Always `checkpoint`. This is what makes the line a checkpoint. | Writer always sets it. Verifier branches on it. |
| `from_seq` | integer | First receipt `seq` in the leaf range. | Writer always sets it. Signed. Defaulted to `0` if missing, which then fails the range check. |
| `to_seq` | integer | Last receipt `seq` in the leaf range. | Writer always sets it. Signed. |
| `merkle_root` | string | 64 lowercase hex characters. | Writer always sets it. Signed. Verifier recomputes the tree and compares. |
| `prev_checkpoint_hash` | string | 64 lowercase hex characters. | Writer always sets it. Signed. Must equal the running checkpoint-chain value. |
| `sig` | string | Base64 Ed25519 signature over the four signed fields. | Writer always sets it. The current verifier checks it only when `sig` is non-empty and a public key is available. An empty `sig` does not by itself fail the checkpoint. |
| `pubkey_id` | string | Same construction as on a receipt. | Writer always sets it. Not compared to the verification key. |
| `hash` | string | SHA-256 of the canonical JSON of the checkpoint object with `hash` and `checkpoint_hash` removed (so `type`, `sig`, and `pubkey_id` are inside this digest). | Writer always sets it. Checked when present, same preference rule as a receipt. |
| `checkpoint_hash` | string | Copy of `hash`. | Writer always sets it. |

## Offline verification

`receiptd verify --ledger PATH` runs the steps below in `receiptd.cli._verify_ledger_file`. It needs no network. It does not re-evaluate policy rules.

1. Read the file as UTF-8. Reject a missing file. Parse every non-blank line as JSON. Reject a bad line.
2. An empty file is success, unless `--allow-unanchored` is unset and an anchor for this path has `last_seq` greater than `0`. That early check looks only at `ledgers[<absolute path>]` or at the top-level object when its `ledger_path` matches. It does not check the anchor signature. A hit with `last_seq` greater than `0` is a failure.
3. Resolve the public key as described under Signing. A missing key fails a receipt that has `sig`. A checkpoint signature is checked only when both `sig` and a public key are present.
4. Walk the lines in order. Start the receipt chain and the checkpoint chain at the genesis value.
5. For a checkpoint:
   - `prev_checkpoint_hash` must equal the checkpoint chain value.
   - If `sig` is non-empty and a public key is available, the signature must verify over the four signed fields.
   - Every integer `seq` from `from_seq` through `to_seq` must already have been seen as a receipt. The Merkle root over those receipt hashes, in that order, must equal `merkle_root`.
   - If `hash` or `checkpoint_hash` is present, it must equal the recomputed record digest.
   - Advance the checkpoint chain to that digest.
6. For a receipt:
   - `prev_hash` (or `prev_receipt_hash` when `prev_hash` is missing or empty) must equal the receipt chain value.
   - If `hash` or `receipt_sha256` is present, it must equal the recomputed digest. Otherwise the recomputed digest is used as the link.
   - If `sig` is present, a public key must be available and the signature must verify over whichever of the eleven signed names are present.
   - If `sig` is absent, `signing_error` must be true and `decision` must be `deny`.
   - Advance the receipt chain to the digest. Remember the digest under `seq`.
7. Unless `--allow-unanchored` is set, load `$RECEIPTD_KEY_DIR/ledger_state.json`, or `state.json` in that directory if the first file is absent. The anchor object is chosen in this order: `ledgers[<absolute path>]` when that value is an object; the top-level value at the absolute path when it is an object; the top-level object when its `ledger_path` equals the absolute path; the top-level object when it has `last_seq` and no `ledger_path`. Its `sig` must verify over the canonical JSON of exactly these three fields: `last_hash` (string), `last_seq` (integer), and `ledger_path` (the absolute path). The receipt count must not be lower than `last_seq`. When `last_seq` is one of the receipt seqs, that receipt's hash must equal `last_hash`. A ledger with receipts and no anchor for its path fails this step. The anchor is local state. It is not a ledger line. A copy of the JSONL on another machine will not satisfy it, because the signed path is absolute; portable checks pass `--allow-unanchored` and supply the public key.
8. If the highest checkpoint `to_seq` is below the receipt count, print a warning that the tail is uncheckpointed. The warning does not change the result. Those receipts were still hash-checked and signature-checked. They are not inside a signed Merkle root. The text is: `Warning: Uncheckpointed tail: receipts {start} to {count} have not been sealed in a Merkle checkpoint. Missing receipts after the last checkpoint cannot be proven.`
9. On success with at least one line, the process prints `VERDICT: AUTHENTIC` with the receipt count, the checkpoint count, and `Unsigned deny receipts accepted: N`, and exits `0`. An empty file that passes step 2 prints `Ledger is empty. No execution frames recorded.` and exits `0` without the `AUTHENTIC` line. `--format json` only suppresses the table. The verdict is still those text lines.

The hook writes the anchor in the key directory on each appended receipt (`last_seq` and `last_hash` of that receipt, signed as in step 7). Default verify therefore expects that file when it runs on the same machine against the same path.

### Exit codes

For `receiptd verify --ledger` (and for the default ledger `.receiptd/receipts.jsonl`, or `.birkin/receipts.jsonl` when that is the file which exists and `--ledger` was omitted):

| Exit | When |
| --- | --- |
| `0` | Every check above passed, including an empty ledger that no anchor contradicts, and a ledger whose only issue is an uncheckpointed tail. |
| `2` | The file is missing, a line is not JSON, or any check above failed (chain, hash, signature, Merkle root, anchor). A failed chain, hash, signature, Merkle, or anchor check prints `TAMPER DETECTED` and the receipt sequence, checkpoint number, or seq range involved. A missing file or a non-JSON line prints that error instead. |

`receiptd verify <package.json>` is the other command. Exit `0` means `AUTHENTIC`. Exit `1` means the verdict was `TAMPERED` or `INVALID`. Exit `2` means the package path does not exist, or neither a package nor a ledger was given and neither default ledger file exists. A ledger tamper exits `2`. A run-package verdict other than `AUTHENTIC` exits `1`.

`tools/verify_standalone.py` runs the ledger steps above and does not import the receiptd package. It uses the same exit codes for a ledger: `0` on success, `2` on tamper, a missing file, or a non-JSON line. It also prints each receipt's `policy_sha256`. When that value is the fixed label hash in [Limitations](#limitations), the line says so. Every such line says the policy text was not checked. `receiptd verify` does not print `policy_sha256`.

## Limitations

Receipts are written only for tool calls that enter the hook and reach the append. A call the host never sends to the hook produces no line. Empty stdin, a non-object payload, and an exception before the append exit `2` from the hook process and leave no receipt. The hook process is fail-closed on those paths: it exits `2` and, when it still can, writes a deny receipt. This format does not claim that a host which skips the hook, ignores the exit status, or continues after its own hook timeout is prevented from running the tool.

A receipt does not identify a model. Nothing in the signed fields, the hash, or the checkpoint is a model name, model version, or provider. The ledger does not prove which model produced a call.

`policy_sha256` on the PreToolUse path is not a digest of the rules that decided the call. The default value is SHA-256 of the UTF-8 label `DEFAULT_RULES:POL-01,POL-02,POL-03`, which is `4c396e2e2f56376e576fb1363d0d6bdb497df548219f0a573bb81fea458af278`. The regexes in `DEFAULT_RULES` are not inputs to that hash. `--policy PATH` replaces it with SHA-256 of the raw file bytes when the file exists, and the decision function still uses the hardcoded regexes rather than the file. **Known defect, being fixed.** The Stop hook stores SHA-256 of the test-command string in the same field, which is also not a policy document.

## Worked example

The two lines below were produced by running `python3 -m receiptd.hooks.claude_code_gate` with stdin `{"tool_name":"Bash","tool_input":{"command":"printf spec"},"session_id":"spec-example"}`, a throwaway key directory, and `RECEIPTD_CHECKPOINT_INTERVAL=1`. The interval is `1` only so this short ledger contains a checkpoint; the default interval is `100`. The private key was discarded and is not in this repository. The public key below is the matching verification key.

`policy_sha256` in the receipt is the constant label hash from [Limitations](#limitations). `merkle_root` equals the receipt `hash` because the tree has one leaf.

The Ed25519 message for the receipt, as `canonical_json_subset` emitted it, is:

```json
{"args_sha256":"80dd78243694b33266384529ee7ce515a379da66b07941fa4ab3af8ad5faea6d","blast_radius":10,"decision":"allow","policy_sha256":"4c396e2e2f56376e576fb1363d0d6bdb497df548219f0a573bb81fea458af278","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","reason":"allowed","rule_ids":[],"session_id":"spec-example","tool":"Bash","ts":"2026-11-12T09:08:43.095523+00:00","v":1}
```

The checkpoint message is:

```json
{"from_seq":1,"merkle_root":"ff244d7d8b771bab912bdb5f62c796bfedcdbb4a42da5b9046c5f7a5e3ab3582","prev_checkpoint_hash":"0000000000000000000000000000000000000000000000000000000000000000","to_seq":1}
```

Ledger (`receipts.jsonl`), one object per line:

```jsonl
{"args_sha256":"80dd78243694b33266384529ee7ce515a379da66b07941fa4ab3af8ad5faea6d","blast_radius":10,"blast_radius_score":10,"decision":"allow","hash":"ff244d7d8b771bab912bdb5f62c796bfedcdbb4a42da5b9046c5f7a5e3ab3582","latency_ms":3.7,"policy_sha256":"4c396e2e2f56376e576fb1363d0d6bdb497df548219f0a573bb81fea458af278","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","prev_receipt_hash":"0000000000000000000000000000000000000000000000000000000000000000","pubkey_id":"4e6d02a445dcf3ab22de71f9a72098c2abeb92406b26fc2a481d89d20d766e61","reason":"allowed","receipt_sha256":"ff244d7d8b771bab912bdb5f62c796bfedcdbb4a42da5b9046c5f7a5e3ab3582","rule_ids":[],"seq":1,"session_id":"spec-example","sig":"DoB/k+uEBsDvUaw1gdCMFM9nRQfOLZby/AfEliFlvH0PdfsUoOAYnI3gy3vNA53LjGV25X5+/x2S1QMpB6xSAg==","tool":"Bash","tool_input":{"command":"printf spec"},"tool_name":"Bash","triggered_rules":[],"ts":"2026-11-12T09:08:43.095523+00:00","v":1}
{"checkpoint_hash":"692ff9015bc04617999caf8dbb34dfc2ac610f0222543e8ad27297f05872d812","from_seq":1,"hash":"692ff9015bc04617999caf8dbb34dfc2ac610f0222543e8ad27297f05872d812","merkle_root":"ff244d7d8b771bab912bdb5f62c796bfedcdbb4a42da5b9046c5f7a5e3ab3582","prev_checkpoint_hash":"0000000000000000000000000000000000000000000000000000000000000000","pubkey_id":"4e6d02a445dcf3ab22de71f9a72098c2abeb92406b26fc2a481d89d20d766e61","sig":"OsY/Ch9oohCHlzb9siPJQMpXEfIhl+xhtr7keXFF/aL+yyUyBGJNlJlrqYOLA8ws7nVc6Pb+KT03PYZMaV7+DQ==","to_seq":1,"type":"checkpoint"}
```

Public key (`receipts.pub.pem`):

```pem
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFUf1ZMuyg5iorRddaQKaJG7/CVZ+QE+0/wHWeMg3ZCg=
-----END PUBLIC KEY-----
```

```bash
receiptd verify --ledger receipts.jsonl --pubkey "$(cat receipts.pub.pem)" --allow-unanchored
```

That command exits `0`. Changing one byte of the receipt payload and leaving `hash` as written exits `2` and names sequence `#1`.
