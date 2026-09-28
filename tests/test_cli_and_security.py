"""CLI parsing and ingest-token handling."""

from __future__ import annotations

import os
import stat
import sys

import pytest
from pydantic import SecretStr

from app.cli import build_parser, main, normalize_argv
from app.core.config import Settings
from app.core.security import load_or_create_ingest_token, read_ingest_token, tokens_match


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], ["serve"]),
        (["--demo"], ["serve", "--demo"]),
        (["--interface", "eth0"], ["serve", "--interface", "eth0"]),
        (["capture", "-i", "eth0"], ["capture", "-i", "eth0"]),
        (["interfaces"], ["interfaces"]),
        (["--help"], ["--help"]),
    ],
)
def test_default_command(argv: list[str], expected: list[str]) -> None:
    assert normalize_argv(argv) == expected


def test_demo_and_interface_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["serve", "--demo", "--interface", "eth0"])


def test_serve_arguments() -> None:
    args = build_parser().parse_args(normalize_argv(["--demo", "--port", "9001", "--no-dashboard"]))
    assert args.command == "serve" and args.demo and args.port == 9001 and args.no_dashboard


def test_invalid_config_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--port", "70000"]) == 2
    assert "Invalid configuration" in capsys.readouterr().err


def test_ingest_token_created_with_private_permissions(settings: Settings) -> None:
    token = load_or_create_ingest_token(settings)
    assert len(token) >= 32
    path = settings.resolve_path(settings.ingest_token_path)
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert read_ingest_token(settings) == token
    assert load_or_create_ingest_token(settings) == token  # stable across restarts


def test_env_token_takes_precedence(settings: Settings) -> None:
    load_or_create_ingest_token(settings)  # a token file exists...
    configured = settings.model_copy(update={"ingest_token": SecretStr("e" * 40)})
    assert read_ingest_token(configured) == "e" * 40  # ...but the configured token wins
    assert read_ingest_token(Settings(_env_file=None, ingest_token="short")) is None  # type: ignore[call-arg]


def test_tokens_match() -> None:
    assert tokens_match("abc", "abc")
    assert not tokens_match("abc", "abd")
    assert not tokens_match(None, "abc")
    assert not tokens_match("abc", None)


def test_privilege_detection_matches_platform() -> None:
    from app.cli import _is_privileged

    result = _is_privileged()
    assert isinstance(result, bool)
    if sys.platform != "win32":
        assert result == (os.geteuid() == 0)
