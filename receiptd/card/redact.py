"""Path redaction for --redact-paths.

Evidence targets that are path components (filenames like `.env`,
`id_rsa`) are replaced with a deterministic keyed hash prefix: same input ->
same short token, so cards stay comparable without revealing file names.
Hosts and program tokens are NOT paths and are left as-is.
"""

from __future__ import annotations

import hashlib
import hmac

from receiptd.card.models import Hit

REDACT_SALT = "receiptd-redact-v1"
HASH_LEN = 8


def redact_target(target: str) -> str:
    digest = hmac.new(REDACT_SALT.encode(), target.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:HASH_LEN]


def redact_hits(hits) -> list:
    """Copy of the hit list with path-component targets hashed."""
    return [
        Hit(
            h.category,
            h.index,
            h.tool,
            redact_target(h.target) if h.is_path else h.target,
            h.timestamp,
            h.rule,
            h.is_path,
        )
        for h in hits
    ]
