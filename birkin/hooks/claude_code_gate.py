"""Thin shim for receiptd.hooks.claude_code_gate."""

import sys
from receiptd.hooks.claude_code_gate import *  # noqa: F401, F403
from receiptd.hooks.claude_code_gate import main

if __name__ == "__main__":
    sys.exit(main())
