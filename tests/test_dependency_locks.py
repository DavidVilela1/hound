"""The lock files must stay consistent with the requirement ranges they were generated from.

``requirements*.txt`` declare what Hound supports (ranges); ``requirements*.lock`` pin the
exact, hash-checked set CI installs (ADR-019). These tests catch a range edited without
re-locking, a hand-edited lock, or runtime pins that differ between the two lock files.
They read files only - no network, no installs.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
LOCK_COMMAND = "uv pip compile {src} --universal --python-version {py} --generate-hashes"
PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;\\]+)")
PAIRS = [("requirements.txt", "requirements.lock"), ("requirements-dev.txt", "requirements-dev.lock")]


def direct_requirements(path: Path) -> list[Requirement]:
    """Requirements declared in ``path``, following ``-r`` includes."""
    found: list[Requirement] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r "):
            found += direct_requirements(path.parent / line[3:].strip())
            continue
        found.append(Requirement(line))
    return found


def locked(path: Path) -> dict[str, tuple[str, int]]:
    """``{canonical name: (version, number of hashes)}`` from a hash-locked requirements file."""
    pins: dict[str, tuple[str, int]] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PIN.match(line)
        if match:
            current = canonicalize_name(match["name"])
            pins[current] = (match["version"], 0)
        elif current and line.strip().startswith("--hash=sha256:"):
            version, hashes = pins[current]
            pins[current] = (version, hashes + 1)
        elif line.strip() and not line.startswith((" ", "#")):
            current = None
    return pins


def minimum_python() -> str:
    spec = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["requires-python"]
    match = re.fullmatch(r">=\s*(\d+\.\d+)", spec)
    assert match, f"unexpected requires-python: {spec!r}"
    return match.group(1)


@pytest.mark.parametrize(("source", "lock"), PAIRS)
def test_every_declared_requirement_is_locked_within_its_range(source: str, lock: str) -> None:
    pins = locked(ROOT / lock)
    for requirement in direct_requirements(ROOT / source):
        name = canonicalize_name(requirement.name)
        assert name in pins, f"{requirement.name} is in {source} but not in {lock}; re-lock (README: Dependencies)"
        version = pins[name][0]
        assert requirement.specifier.contains(version, prereleases=True), (
            f"{lock} pins {requirement.name}=={version}, outside {source}'s range {requirement.specifier}; re-lock"
        )


@pytest.mark.parametrize("lock", [lock for _, lock in PAIRS])
def test_every_pin_is_hash_checked(lock: str) -> None:
    pins = locked(ROOT / lock)
    assert len(pins) > 10
    unhashed = sorted(name for name, (_, hashes) in pins.items() if hashes == 0)
    assert not unhashed, f"{lock}: pins without hashes (pip would refuse the file): {unhashed}"


def test_runtime_pins_are_identical_in_the_dev_lock() -> None:
    runtime, dev = locked(ROOT / "requirements.lock"), locked(ROOT / "requirements-dev.lock")
    differing = {name: (version, dev.get(name, (None,))[0]) for name, (version, _) in runtime.items()}
    differing = {name: pair for name, pair in differing.items() if pair[0] != pair[1]}
    assert not differing, f"runtime pins differ between the lock files (runtime, dev): {differing}"


@pytest.mark.parametrize(("source", "lock"), PAIRS)
def test_lock_records_how_it_was_generated(source: str, lock: str) -> None:
    header = (ROOT / lock).read_text(encoding="utf-8").split("\n", 3)[:2]
    expected = LOCK_COMMAND.format(src=source, py=minimum_python())
    assert expected in header[1], f"{lock} was not generated with the documented command ({expected} ...)"
