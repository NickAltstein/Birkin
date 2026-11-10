"""Thin shim for receiptd.cli."""

import sys
from receiptd.cli import *  # noqa: F401, F403
from receiptd.cli import app, cli, main

if __name__ == "__main__":
    main()
