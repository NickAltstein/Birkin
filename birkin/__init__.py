"""
birkin compatibility shim
=========================

Backward-compatibility shim re-exporting `receiptd` and mapping its
submodules (e.g. `birkin.crypto`, `birkin.verify`, `birkin.adapters`) via `sys.modules`.
"""

import importlib
import sys

import receiptd
from receiptd import *  # noqa: F401, F403

__all__ = getattr(receiptd, "__all__", [k for k in dir(receiptd) if not k.startswith("_")])
__version__ = getattr(receiptd, "__version__", "1.0.0")

_this_module = sys.modules[__name__]

# Submodule aliases mapped into sys.modules so legacy imports work.
_SUBMODULES = [
    "adapter",
    "adapters",
    "adapters.grok_bot",
    "adapters.hermes",
    "adapters.infini_gateway",
    "adapters.null_agent",
    "audit",
    "card",
    "card.classifier",
    "card.models",
    "card.parser",
    "card.pipeline",
    "card.redact",
    "card.render_card",
    "card.render_terminal",
    "card.signing",
    "card.verdict",
    "crypto",
    "engine",
    "ledger",
    "models",
    "policy",
    "trifecta",
    "verify",
]

for _sub in _SUBMODULES:
    _target = importlib.import_module(f"receiptd.{_sub}")
    sys.modules[f"birkin.{_sub}"] = _target
    _parts = _sub.split(".")
    _curr = _this_module
    for _part in _parts[:-1]:
        _curr = getattr(_curr, _part, None)
        if _curr is None:
            break
    if _curr is not None:
        setattr(_curr, _parts[-1], _target)


def __getattr__(name: str):
    """Fallback attribute lookup delegating to receiptd."""
    if hasattr(receiptd, name):
        val = getattr(receiptd, name)
        setattr(_this_module, name, val)
        return val
    try:
        mod = importlib.import_module(f"receiptd.{name}")
        sys.modules[f"birkin.{name}"] = mod
        setattr(_this_module, name, mod)
        return mod
    except ModuleNotFoundError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
