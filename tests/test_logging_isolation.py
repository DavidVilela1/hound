"""Tests must not leak process-wide logging setup into later tests.

``configure_logging()`` (called by ``cli.main``) replaces the root handlers with one bound
to the *current* ``sys.stderr`` — inside a test that is pytest's capture stream for that
test only. Left in place, later log records (e.g. from a server thread shutting down) are
written to a closed stream: "--- Logging error --- ValueError: I/O operation on closed file"
(seen on the owner's Windows run). The autouse fixture in conftest restores the setup.
The two tests below run in file order.
"""

from __future__ import annotations

import logging

from app.core.logging_config import KeyValueFormatter, configure_logging


def test_a_configures_logging_like_the_cli_does() -> None:
    configure_logging("INFO", "text")
    assert any(isinstance(h.formatter, KeyValueFormatter) for h in logging.getLogger().handlers)


def test_b_sees_no_handler_left_behind_by_the_previous_test() -> None:
    leaked = [h for h in logging.getLogger().handlers if isinstance(h.formatter, KeyValueFormatter)]
    assert leaked == [], "a test left Hound's stderr handler on the root logger"
