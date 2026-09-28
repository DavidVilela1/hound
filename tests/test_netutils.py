"""IP validation and domain normalisation."""

from __future__ import annotations

import pytest

from app.core.netutils import (
    domain_suffixes,
    is_local_address,
    is_public_address,
    is_valid_ip,
    normalize_domain,
    normalize_ip,
    shannon_entropy,
)


@pytest.mark.parametrize(
    "value,expected",
    [("192.168.1.1", "192.168.1.1"), (" 8.8.8.8 ", "8.8.8.8"), ("2001:DB8::0:1", "2001:db8::1")],
)
def test_normalize_ip(value: str, expected: str) -> None:
    assert normalize_ip(value) == expected


@pytest.mark.parametrize("value", ["", "256.1.1.1", "1.2.3", "example.com", "1.2.3.4; rm -rf /", None, 42])
def test_invalid_ips(value: object) -> None:
    assert not is_valid_ip(value)


def test_local_and_public_classification() -> None:
    assert is_local_address("192.168.1.5")
    assert is_local_address("10.0.0.1")
    assert is_local_address("fe80::1")
    assert is_local_address("224.0.0.251")
    assert not is_local_address("8.8.8.8")
    assert is_public_address("8.8.8.8")
    assert not is_public_address("192.168.1.5")
    assert not is_public_address("garbage")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("www.example.com.", "www.example.com"),
        ("  Sub.Example.com  ", "sub.example.com"),
        ("https://www.example.com/path?q=1", "www.example.com"),
        ("http://user@example.com:8080/", "example.com"),
        ("_dmarc.example.org", "_dmarc.example.org"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        ".",
        "-bad.example",
        "bad-.example",
        "a..b",
        "exa mple.com",
        "a" * 64 + ".com",
        ("a" * 60 + ".") * 5,
        None,
    ],
)
def test_invalid_domains(raw: str | None) -> None:
    assert normalize_domain(raw) is None


def test_domain_suffixes() -> None:
    assert domain_suffixes("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com", "com"]


def test_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("x7k2qp9zv4m1bw") > shannon_entropy("googleusercontent")
