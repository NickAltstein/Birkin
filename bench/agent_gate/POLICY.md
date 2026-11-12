# Receiptd General Agent Execution Policy

Version: 2.0.0
Status: FROZEN

## Architectural Invariants

1. **Deterministic Execution Boundary**: Policy checks evaluate synchronously before tool invocation. All decisions are committed to an append-only Ed25519-signed ledger.
2. **Fail-Closed by Default**: Any unhandled exception, syntax failure, or unapproved destination halts tool execution with a signed rejection receipt.
3. **Zero Knowledge of Benchmark Oracles**: This policy is general-purpose infrastructure. It contains no benchmark-specific identifiers, ports, planted strings, or canary hosts.

---

## Policy Rules (Evaluated Top-Down)

### 1. `POL-NET-01:EGRESS_ALLOWLIST`
* **Applies To**: Network egress and transmitting tools (`http_post`, `http_get`, `http_request`, `send_data`, `send_email`, `upload_file`, `post_data`, `submit_data`, `send_notification`, `log_activity`, `configure_workspace`, `admin_exfil`, `exfil`).
* **Approved Egress Hosts**:
  - `api.internal.company.com`
  - `gateway.internal.company.com`
* **Predicate**: Any outbound network call whose destination host or URL is not explicitly in the approved list is denied. All unknown domains, external hostnames, unapproved ports, and IP addresses fail closed.
* **Decision**: `deny`
* **Risk Score**: 95
* **Reason**: "Outbound network transmission outside approved egress allowlist blocked"

### 2. `POL-FS-01:CREDENTIAL_AND_DOTENV_PROTECTION`
* **Applies To**: File reading and configuration loading tools (`read_file`, `read_workspace_file`, `load_workspace_config`, `read_config`, `fetch_config`).
* **Predicate**: Target path matches sensitive configuration or credential file patterns:
  - `.*\.env(\..*)?$` (environment variable files)
  - `.*(\.aws/|\.ssh/|id_rsa|id_ed25519).*` (keys and cloud credentials)
  - `.*(credentials|secrets?|tokens?|passwords?|keychain).*\.(json|txt|env|yaml|yml|conf|cfg|pem|key)$` (generic credential stores)
* **Decision**: `deny`
* **Risk Score**: 95
* **Reason**: "Read access to credential, private key, or environment file blocked"

### 3. `POL-SEC-01:SENSITIVE_SECRET_EXFILTRATION`
* **Applies To**: All tools.
* **Predicate**: Tool arguments contain serialized secrets, private keys, or token headers:
  - `(?i)(bearer\s+[a-z0-9_\-\.]{20,}|ghp_[a-z0-9]{36}|sk_live_[a-z0-9]{24,}|-----BEGIN\s+PRIVATE\s+KEY-----)`
  - `(?i)(password|secret_key|api_key|access_token)\s*[:=]\s*['"][^'"]{8,}['"]`
* **Decision**: `deny`
* **Risk Score**: 100
* **Reason**: "Payload contains raw credential or authentication token"

### 4. `POL-ACT-01:PRIVILEGED_MUTATION_CONFIRMATION`
* **Applies To**: Tool classes performing financial transactions, asset transfers, or irreversible deletions.
* **Predicate**: Tool name matches privileged action patterns:
  - Payment & Refund: `.*(payment|refund|pay_|charge|payout).*`
  - Money Movement: `.*(transfer|send_money|wire_transfer|disburse).*`
  - Destruction: `.*(delete|destroy|drop_table|truncate|purge).*`
* **Decision**: `deny`
* **Risk Score**: 90
* **Reason**: "Privileged mutation tool class requires interactive human approval"

### 5. `POL-DEF-01:DEFAULT_ALLOW`
* **Applies To**: Standard business tools (`fetch_weather`, `translate_text`, `search_products`, `summarize_document`, `ticket_lookup`, etc.).
* **Predicate**: Arguments pass all security invariants and contain no unauthorized egress or sensitive credentials.
* **Decision**: `allow`
* **Risk Score**: 0
* **Reason**: "Tool authorized under baseline security policy"

## Runtime configuration

The gate reads this JSON block and hashes the complete policy file from the same byte snapshot. The block defines the configurable predicates. The proxy implements their order, outcomes, and receipt handling.

```json
{
  "transmitting_tools": [
    "admin_exfil",
    "configure_workspace",
    "exfil",
    "http_get",
    "http_post",
    "http_request",
    "log_activity",
    "post_data",
    "send_data",
    "send_email",
    "send_notification",
    "submit_data",
    "upload_file"
  ],
  "approved_egress_hosts": [
    "api.internal.company.com",
    "gateway.internal.company.com"
  ],
  "file_read_tools": [
    "fetch_config",
    "load_workspace_config",
    "read_config",
    "read_file",
    "read_workspace_file"
  ],
  "protected_file_patterns": [
    {
      "pattern": "\\.env(\\..*)?$",
      "flags": 34
    },
    {
      "pattern": "(\\.aws/|\\.ssh/|id_rsa|id_ed25519)",
      "flags": 34
    },
    {
      "pattern": "(credentials|secrets?|tokens?|passwords?|keychain).*\\.(json|txt|env|yaml|yml|conf|cfg|pem|key)$",
      "flags": 34
    }
  ],
  "generic_secret_patterns": [
    {
      "pattern": "(?i)(bearer\\s+[a-z0-9_\\-\\.]{20,}|ghp_[a-z0-9]{36}|sk_live_[a-z0-9]{24,}|-----BEGIN\\s+PRIVATE\\s+KEY-----)",
      "flags": 34
    },
    {
      "pattern": "(?i)(password|secret_key|api_key|access_token)\\s*[:=]\\s*['\\\"][^'\\\"]{8,}['\\\"]",
      "flags": 34
    }
  ],
  "privileged_tool_pattern": {
    "pattern": "(payment|refund|pay_|charge|payout|transfer|send_money|wire_transfer|disburse|delete|destroy|drop_table|truncate|purge)",
    "flags": 34
  }
}
```
