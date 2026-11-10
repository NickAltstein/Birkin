"""
birkin compatibility shim
=========================

Backward-compatibility shim re-exporting `receiptd` and mapping its
submodules (e.g. `birkin.crypto`, `birkin.verify`, `birkin.adapters`) via `sys.modules`.
"""

import importlib
import pkgutil
import sys

import receiptd
from receiptd import *  # noqa: F401, F403

__all__ = getattr(receiptd, "__all__", [k for k in dir(receiptd) if not k.startswith("_")])
__version__ = getattr(receiptd, "__version__", "1.0.0")

_this_module = sys.modules[__name__]


def _map_submodules() -> None:
    prefix = receiptd.__name__ + "."
    for mod_info in pkgutil.walk_packages(receiptd.__path__, prefix):
        sub_name = mod_info.name[len(prefix):]
        try:
            target_mod = importlib.import_module(mod_info.name)
        except Exception:
            continue

        birkin_mod_name = f"birkin.{sub_name}"
        sys.modules[birkin_mod_name] = target_mod

        # Attach to parent package in the birkin module tree
        parts = sub_name.split(".")
        current = _this_module
        for part in parts[:-1]:
            current = getattr(current, part, None)
            if current is None:
                break
        if current is not None:
            setattr(current, parts[-1], target_mod)


_map_submodules()


class _BirkinShimFinder:
    """MetaPathFinder fallback to dynamically map any birkin.* import to receiptd.*"""

    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        if fullname.startswith("birkin."):
            sub = fullname[len("birkin."):]
            target_name = f"receiptd.{sub}"
            try:
                mod = importlib.import_module(target_name)
                sys.modules[fullname] = mod
                return mod.__spec__
            except ModuleNotFoundError:
                return None
        return None


if _BirkinShimFinder not in sys.meta_path:
    sys.meta_path.insert(0, _BirkinShimFinder)


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
