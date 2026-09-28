#!/usr/bin/env python3
"""Hound launcher.

Examples::

    python run.py                      # API + dashboard (accepts events from a capture daemon)
    python run.py --demo               # API + dashboard + synthetic traffic (no privileges needed)
    python run.py capture -i eth0      # privileged capture daemon that forwards to the server
    python run.py --interface eth0     # all-in-one (whole process needs capture privileges)
    python run.py interfaces           # list capture interfaces

See README.md for details.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # noqa: UP036  # guard for old interpreters
    sys.stderr.write("Hound requires Python 3.11 or newer.\n")
    raise SystemExit(1)

from app.cli import main  # noqa: E402  (import after the version guard on purpose)

if __name__ == "__main__":
    raise SystemExit(main())
