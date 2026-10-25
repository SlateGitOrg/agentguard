"""Unit tests for argument constraints (paths, URLs, amounts, e-mail, enums)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from agentguard.constraints import (
    ArgumentConstraints,
    build_constraint,
    compile_glob,
    glob_match,
    normalize_path,
    to_decimal,
)
from agentguard.errors import PolicyError


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a/b", "a/b"),
        ("./a//b/", "a/b"),
        ("a/../b", "b"),
        (".", "."),
        ("a/..", "."),
        ("../a", None),
        ("a/../../b", None),
        ("/etc/passwd", None),
        ("~/x", None),
        ("a\\b", None),
        ("a\x00b", None),
        ("", None),
    ],
)
def test_normalize_path(raw: str, expected: str | None) -> None:
    assert normalize_path(raw) == expected


@pytest.mark.parametrize(
    ("pattern", "path", "ok"),
    [
        ("notes/*.md", "notes/a.md", True),
        ("notes/*.md", "notes/sub/a.md", False),
        ("notes/**", "notes", True),
        ("notes/**", "notes/a/b/c.txt", True),
        ("notes/**", "notesx/a", False),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("a/**/b", "a/x/y/c", False),
        ("**/.env", ".env", True),
        ("**/.env", "x/y/.env", True),
        ("**", "anything/at/all", True),
        ("file?.txt", "file1.txt", True),
        ("file?.txt", "file/.txt", False),
        ("[ab].txt", "a.txt", False),  # brackets are literal
        ("[ab].txt", "[ab].txt", True),
        ("notes/*.md", "notes/../secrets/a.md", False),
        ("notes/**", "notes/../../etc/passwd", False),
    ],
)
def test_glob_match(pattern: str, path: str, ok: bool) -> None:
    assert glob_match(pattern, path) is ok


@pytest.mark.parametrize("bad", ["", "/abs", "a//b", "a/../b", "./a", "a\\b"])
def test_invalid_globs(bad: str) -> None:
    with pytest.raises(PolicyError):
        compile_glob(bad)


def test_glob_and_deny_glob_constraints() -> None:
    allow = build_constraint("glob", ["notes/**", "docs/*.md"], "t")
    deny = build_constraint("deny_glob", "**/.env", "t")
    assert allow.check("notes/x/y.txt") is None
    assert "matches none of" in str(allow.check("secrets/k"))
    assert "not a valid sandbox-relative path" in str(allow.check("../x"))
    assert allow.check(5) == "path must be a string"
    assert deny.check("notes/a.md") is None
    assert "denied glob" in str(deny.check("notes/.env"))
    assert deny.check(None) == "path must be a string"
    assert "not a valid" in str(deny.check("/etc"))
    assert allow.kind == "glob"
    assert "notes/**" in allow.describe()
    assert "deny_glob" in deny.describe()


URL = build_constraint(
    "url",
    {"hosts": ["docs.python.org", "*.wikipedia.org"], "path_prefixes": ["/3/", "/wiki"]},
    "t",
)


@pytest.mark.parametrize(
    ("url", "fragment"),
    [
        ("https://docs.python.org/3/library/json.html", None),
        ("https://en.wikipedia.org/wiki/Capability", None),
        ("https://DOCS.python.org./3/x", None),
        ("http://docs.python.org/3/", "scheme 'http'"),
        ("https://wikipedia.org/wiki/x", "not in allow-list"),
        ("https://docs.python.org.evil.test/3/", "not in allow-list"),
        ("https://evil.test/?u=https://docs.python.org/3/", "not in allow-list"),
        ("https://docs.python.org@evil.test/3/", "userinfo"),
        ("https://user:pw@docs.python.org/3/", "userinfo"),
        ("https://docs.python.org:8443/3/", "explicit port 8443"),
        ("https://docs.python.org:99999/3/", "unparseable"),
        ("https://127.0.0.1/3/", "IP literal"),
        ("https://docs.python.org/2/", "not under"),
        ("https://docs.python.org/3/../2/", "dot segments"),
        ("https://docs.python.org/3/%2e%2e/2/", "dot segments"),
        ("https://docs.python.org/3/ x", "whitespace"),
        ("https://docs.python.org\\@evil.test/", "backslashes"),
        ("https:///3/", "no host"),
        ("https://dóc.python.org/3/", "punycode"),
        (42, "must be a string"),
    ],
)
def test_url_constraint(url: Any, fragment: str | None) -> None:
    reason = URL.check(url)
    if fragment is None:
        assert reason is None
    else:
        assert reason is not None
        assert fragment in reason


def test_url_with_allowed_port_and_ip() -> None:
    c = build_constraint("url", {"hosts": ["10.0.0.5"], "schemes": ["http"], "ports": [8080]}, "t")
    assert c.check("http://10.0.0.5:8080/anything") is None
    assert "hosts=" in c.describe()


@pytest.mark.parametrize(
    ("spec", "fragment"),
    [
        ("x", "must be a mapping"),
        ({"hosts": ["a.com"], "nope": 1}, "unknown url keys"),
        ({"hosts": ["*a.com"]}, "bad host pattern"),
        ({"hosts": ["a.*.com"]}, "bad host pattern"),
        ({"hosts": ["a.com"], "ports": ["80"]}, "ports must be a list"),
        ({}, "non-empty string"),
    ],
)
def test_url_constraint_spec_errors(spec: Any, fragment: str) -> None:
    with pytest.raises(PolicyError, match=fragment):
        build_constraint("url", spec, "t")


def test_bounds_are_exact_decimals() -> None:
    cap = build_constraint("max", 100, "t")
    floor = build_constraint("min", "0.01", "t")
    assert cap.check(100) is None
    assert cap.check("100.00") is None
    assert "exceeds max" in str(cap.check(100.000001))
    assert "exceeds max" in str(cap.check("1e3"))
    assert "not a finite number" in str(cap.check(float("inf")))
    assert "not a finite number" in str(cap.check("NaN"))
    assert "not a finite number" in str(cap.check(True))
    assert "not a finite number" in str(cap.check(None))
    assert "below min" in str(floor.check(0))
    assert floor.describe() == "min 0.01"
    with pytest.raises(PolicyError, match="finite number"):
        build_constraint("max", "lots", "t")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (3, Decimal(3)),
        (0.1, Decimal("0.1")),
        (" 2.50 ", Decimal("2.50")),
        ("abc", None),
        (float("nan"), None),
        (False, None),
        ([1], None),
    ],
)
def test_to_decimal(value: Any, expected: Decimal | None) -> None:
    assert to_decimal(value) == expected


def test_one_of_is_type_strict() -> None:
    c = build_constraint("one_of", [1, "USD"], "t")
    assert c.check(1) is None
    assert c.check("USD") is None
    assert c.check(True) is not None
    assert c.check("1") is not None
    assert c.check(1.0) is not None
    assert "one_of" in c.describe()
    with pytest.raises(PolicyError):
        build_constraint("one_of", [], "t")


def test_regex_and_max_length() -> None:
    r = build_constraint("regex", "[A-Z]{3}", "t")
    assert r.check("USD") is None
    assert r.check("USDX") is not None
    assert r.check(3) == "value must be a string"
    assert "regex" in r.describe()
    m = build_constraint("max_length", 3, "t")
    assert m.check("abc") is None
    assert "exceeds 3" in str(m.check("abcd"))
    assert m.check(1) == "value must be a string"
    assert m.describe() == "max_length 3"
    with pytest.raises(PolicyError, match="invalid regex"):
        build_constraint("regex", "(", "t")
    with pytest.raises(PolicyError, match="regex must be a string"):
        build_constraint("regex", 1, "t")
    with pytest.raises(PolicyError, match="non-negative"):
        build_constraint("max_length", -1, "t")


def test_email_constraint() -> None:
    c = build_constraint(
        "email",
        {"domains": ["example.com", "*.example.org"], "addresses": ["Ops@Partner.test"]},
        "t",
    )
    assert c.check("alice@example.com") is None
    assert c.check(" Bob@Example.COM ") is None
    assert c.check("x@eu.example.org") is None
    assert c.check("ops@partner.test") is None
    assert "not in allowed" in str(c.check("x@example.org"))
    assert "not in allowed" in str(c.check("a@example.com.evil.test"))
    assert "not a plain" in str(c.check("Alice <alice@example.com>"))
    assert "not a plain" in str(c.check("a@example.com,b@evil.test"))
    assert c.check(1) == "address must be a string"
    assert "domains=" in c.describe()
    only_addr = build_constraint("email", {"addresses": ["a@b.co"]}, "t")
    assert only_addr.check("c@b.co") is not None
    for bad in ({}, {"nope": 1}, "x"):
        with pytest.raises(PolicyError):
            build_constraint("email", bad, "t")


def test_unknown_kind_and_bad_lists() -> None:
    with pytest.raises(PolicyError, match="unknown constraint kind"):
        build_constraint("prefix", "x", "t")
    with pytest.raises(PolicyError, match="non-empty string or list"):
        build_constraint("glob", [], "t")
    with pytest.raises(PolicyError, match="non-empty string or list"):
        build_constraint("glob", [1], "t")


def test_argument_constraints_apply_elementwise_and_skip_absent() -> None:
    ac = ArgumentConstraints("to", (build_constraint("email", {"domains": ["a.com"]}, "t"),))
    assert ac.check({}) == []
    assert ac.check({"to": "x@a.com"}) == []
    assert ac.check({"to": ["x@a.com", "y@a.com"]}) == []
    failures = ac.check({"to": ["x@a.com", "y@b.com"]})
    assert len(failures) == 1
    assert failures[0].startswith("to: ")
