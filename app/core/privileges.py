"""Privilege detection shared by the CLI and the environment diagnostic."""

from __future__ import annotations

import os
import sys


def is_privileged() -> bool:
    """``True`` when running as root (POSIX) or as an elevated Administrator (Windows)."""
    if sys.platform == "win32":
        import ctypes

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0
