"""Argument constraints attached to capability grants.

Each constraint checks one argument value and returns ``None`` when it is satisfied or a
human-readable reason when it is not. Constraints are *fail-closed*: anything that cannot be
parsed unambiguously (``..`` escaping the sandbox root, URLs with userinfo, non-ASCII host
names, NaN amounts, booleans posing as numbers) is rejected rather than interpreted.

Supported kinds (as written in policy YAML under ``constraints: {<arg>: {<kind>: ...}}``):

=================  ==========================================================================
``glob``           path must match at least one glob (``*``, ``?``, ``**``; segment-aware)
``deny_glob``      path must match none of these globs
``url``            scheme/host/port/path-prefix allow-list for URLs
``max`` / ``min``  numeric bounds, compared as exact decimals
``one_of``         value must equal one of the listed values
``regex``          string must fully match
``max_length``     string length bound
``email``          address or domain allow-list for e-mail recipients
=================  ==========================================================================
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

from agentguard.errors import PolicyError

# --------------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------------


def normalize_path(raw: str) -> str | None:
    """Normalize a sandbox-relative POSIX path, or return ``None`` if it is not acceptable.

    Rejected: empty strings, NUL bytes, backslashes, absolute paths, ``~`` expansion and any
    ``..`` that would climb above the sandbox root. The root itself normalizes to ``"."``.
    """
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith(("/", "~")):
        return None
    parts: list[str] = []
    for seg in raw.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts) if parts else "."


def _segment_regex(segment: str) -> str:
    out = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "*":
            while i + 1 < len(segment) and segment[i + 1] == "*":
                i += 1
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


@lru_cache(maxsize=1024)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a segment-aware glob into an anchored regex over the *rooted* path ``"/" + p``.

    Unlike :mod:`fnmatch`, ``*`` and ``?`` never cross a ``/``. ``**`` as a whole segment
    matches zero or more segments, so ``a/**/b`` matches ``a/b`` and ``a/x/y/b``, and a
    trailing ``/**`` also matches the directory itself (``reports/**`` grants ``reports`` and
    everything below it). Brackets and every other character are literal. Use
    :func:`match_glob` rather than matching the regex directly.

    Every path segment is compiled to ``/<segment>`` and every ``**`` to ``(?:/[^/]+)*``, which
    keeps the composition of consecutive and leading/trailing ``**`` trivially correct (this
    is property-tested against a recursive reference matcher).
    """
    if not pattern or pattern.startswith("/") or "\\" in pattern:
        raise PolicyError(f"invalid glob {pattern!r}: must be a non-empty relative path")
    segments = pattern.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise PolicyError(f"invalid glob {pattern!r}: empty, '.' or '..' segment")
    parts: list[str] = []
    for seg in segments:
        if seg == "**":
            if not parts or parts[-1] != _ANY_SEGMENTS:  # '**/**' is the same as '**'
                parts.append(_ANY_SEGMENTS)
        else:
            parts.append("/" + _segment_regex(seg))
    return re.compile("".join(parts))


_ANY_SEGMENTS = "(?:/[^/]+)*"


def match_glob(pattern: str, normalized: str) -> bool:
    """True if an already-:func:`normalize_path`-ed path matches ``pattern``."""
    return compile_glob(pattern).fullmatch("/" + normalized) is not None


def glob_match(pattern: str, path: str) -> bool:
    """True if ``path`` normalizes to a sandbox path that matches ``pattern``."""
    normalized = normalize_path(path)
    if normalized is None:
        return False
    return match_glob(pattern, normalized)


# --------------------------------------------------------------------------------------------
# Constraint protocol and implementations
# --------------------------------------------------------------------------------------------


class Constraint(Protocol):
    """Structural type of every argument constraint."""

    @property
    def kind(self) -> str: ...

    def check(self, value: Any) -> str | None:
        """Return ``None`` if ``value`` satisfies the constraint, else the reason it does not."""

    def describe(self) -> str: ...


@dataclass(frozen=True)
class GlobConstraint:
    patterns: tuple[str, ...]
    kind: str = "glob"

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "path must be a string"
        normalized = normalize_path(value)
        if normalized is None:
            return f"path {value!r} is not a valid sandbox-relative path"
        for pattern in self.patterns:
            if match_glob(pattern, normalized):
                return None
        return f"path {normalized!r} matches none of {list(self.patterns)}"

    def describe(self) -> str:
        return f"glob {list(self.patterns)}"


@dataclass(frozen=True)
class DenyGlobConstraint:
    patterns: tuple[str, ...]
    kind: str = "deny_glob"

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "path must be a string"
        normalized = normalize_path(value)
        if normalized is None:
            return f"path {value!r} is not a valid sandbox-relative path"
        for pattern in self.patterns:
            if match_glob(pattern, normalized):
                return f"path {normalized!r} matches denied glob {pattern!r}"
        return None

    def describe(self) -> str:
        return f"deny_glob {list(self.patterns)}"


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class UrlConstraint:
    hosts: tuple[str, ...]
    schemes: tuple[str, ...] = ("https",)
    ports: tuple[int, ...] = ()
    path_prefixes: tuple[str, ...] = ()
    kind: str = "url"

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "url must be a string"
        if any(ch.isspace() or ord(ch) < 0x20 for ch in value) or "\\" in value:
            return "url contains whitespace, control characters or backslashes"
        try:
            parts = urlsplit(value)
            port = parts.port
        except ValueError as exc:
            return f"unparseable url: {exc}"
        scheme = parts.scheme.lower()
        if scheme not in self.schemes:
            return f"scheme {scheme!r} not in {list(self.schemes)}"
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            return "urls with userinfo are not allowed"
        host = (parts.hostname or "").rstrip(".")
        if not host:
            return "url has no host"
        if not host.isascii():
            return "non-ASCII host names must be given in punycode"
        if port is not None and port not in self.ports:
            return f"explicit port {port} not allowed"
        if _is_ip(host) and host not in self.hosts:
            return f"IP literal host {host!r} not allowed"
        if not any(_host_matches(p, host) for p in self.hosts):
            return f"host {host!r} not in allow-list {list(self.hosts)}"
        if self.path_prefixes:
            path = unquote(parts.path) or "/"
            if any(seg in ("..", ".") for seg in path.split("/")):
                return "url path contains dot segments"
            if not any(_path_prefix_ok(prefix, path) for prefix in self.path_prefixes):
                return f"path {path!r} not under {list(self.path_prefixes)}"
        return None

    def describe(self) -> str:
        return f"url hosts={list(self.hosts)} schemes={list(self.schemes)}"


def _path_prefix_ok(prefix: str, path: str) -> bool:
    prefix = "/" + prefix.strip("/")
    return prefix in ("/", path) or path.startswith(prefix + "/")


def to_decimal(value: Any) -> Decimal | None:
    """Exact decimal for an int/float/numeric-string amount; ``None`` if not a finite number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        dec = Decimal(repr(value))
    elif isinstance(value, str):
        try:
            dec = Decimal(value.strip())
        except InvalidOperation:
            return None
    else:
        return None
    return dec if dec.is_finite() else None


@dataclass(frozen=True)
class BoundConstraint:
    bound: Decimal
    upper: bool
    kind: str = "max"

    def check(self, value: Any) -> str | None:
        dec = to_decimal(value)
        if dec is None:
            return f"{value!r} is not a finite number"
        if self.upper and dec > self.bound:
            return f"{dec} exceeds max {self.bound}"
        if not self.upper and dec < self.bound:
            return f"{dec} below min {self.bound}"
        return None

    def describe(self) -> str:
        return f"{'max' if self.upper else 'min'} {self.bound}"


@dataclass(frozen=True)
class OneOfConstraint:
    values: tuple[Any, ...]
    kind: str = "one_of"

    def check(self, value: Any) -> str | None:
        # Compare type-strictly so True never equals 1 and "1" never equals 1.
        for allowed in self.values:
            if type(allowed) is type(value) and allowed == value:
                return None
        return f"{value!r} not one of {list(self.values)}"

    def describe(self) -> str:
        return f"one_of {list(self.values)}"


@dataclass(frozen=True)
class RegexConstraint:
    pattern: str
    kind: str = "regex"

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "value must be a string"
        if re.fullmatch(self.pattern, value) is None:
            return f"{value!r} does not match {self.pattern!r}"
        return None

    def describe(self) -> str:
        return f"regex {self.pattern!r}"


@dataclass(frozen=True)
class MaxLengthConstraint:
    limit: int
    kind: str = "max_length"

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "value must be a string"
        if len(value) > self.limit:
            return f"length {len(value)} exceeds {self.limit}"
        return None

    def describe(self) -> str:
        return f"max_length {self.limit}"


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")


@dataclass(frozen=True)
class EmailConstraint:
    domains: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    kind: str = "email"

    def check(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "address must be a string"
        match = _EMAIL_RE.match(value.strip())
        if match is None:
            return f"{value!r} is not a plain e-mail address"
        address = value.strip().lower()
        domain = match.group(1).lower()
        if address in self.addresses:
            return None
        if any(_host_matches(d, domain) for d in self.domains):
            return None
        return f"recipient {address!r} not in allowed domains/addresses"

    def describe(self) -> str:
        return f"email domains={list(self.domains)} addresses={list(self.addresses)}"


# --------------------------------------------------------------------------------------------
# Construction from policy YAML
# --------------------------------------------------------------------------------------------


def _str_list(spec: Any, where: str) -> tuple[str, ...]:
    if isinstance(spec, str):
        spec = [spec]
    if not isinstance(spec, list) or not spec or not all(isinstance(s, str) for s in spec):
        raise PolicyError("expected a non-empty string or list of strings", where=where)
    return tuple(spec)


def _number(spec: Any, where: str) -> Decimal:
    dec = to_decimal(spec)
    if dec is None:
        raise PolicyError(f"expected a finite number, got {spec!r}", where=where)
    return dec


def build_constraint(kind: str, spec: Any, where: str) -> Constraint:
    """Build one constraint from its YAML form, raising :class:`PolicyError` on bad input."""
    where = f"{where}.{kind}"
    if kind == "glob":
        patterns = _str_list(spec, where)
        for p in patterns:
            compile_glob(p)
        return GlobConstraint(patterns)
    if kind == "deny_glob":
        patterns = _str_list(spec, where)
        for p in patterns:
            compile_glob(p)
        return DenyGlobConstraint(patterns)
    if kind == "url":
        if not isinstance(spec, Mapping):
            raise PolicyError("url constraint must be a mapping", where=where)
        unknown = set(spec) - {"hosts", "schemes", "ports", "path_prefixes"}
        if unknown:
            raise PolicyError(f"unknown url keys {sorted(unknown)}", where=where)
        hosts = tuple(h.lower().rstrip(".") for h in _str_list(spec.get("hosts"), where))
        for h in hosts:
            if (h.startswith("*") and not h.startswith("*.")) or "*" in h[1:]:
                raise PolicyError(f"bad host pattern {h!r} (use '*.example.com')", where=where)
        schemes = tuple(s.lower() for s in _str_list(spec.get("schemes", ["https"]), where))
        ports = spec.get("ports", [])
        if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
            raise PolicyError("ports must be a list of integers", where=where)
        prefixes = _str_list(spec["path_prefixes"], where) if "path_prefixes" in spec else ()
        return UrlConstraint(hosts, schemes, tuple(ports), prefixes)
    if kind in ("max", "min"):
        return BoundConstraint(_number(spec, where), upper=kind == "max", kind=kind)
    if kind == "one_of":
        if not isinstance(spec, list) or not spec:
            raise PolicyError("one_of needs a non-empty list", where=where)
        return OneOfConstraint(tuple(spec))
    if kind == "regex":
        if not isinstance(spec, str):
            raise PolicyError("regex must be a string", where=where)
        try:
            re.compile(spec)
        except re.error as exc:
            raise PolicyError(f"invalid regex: {exc}", where=where) from exc
        return RegexConstraint(spec)
    if kind == "max_length":
        if not isinstance(spec, int) or isinstance(spec, bool) or spec < 0:
            raise PolicyError("max_length must be a non-negative integer", where=where)
        return MaxLengthConstraint(spec)
    if kind == "email":
        if not isinstance(spec, Mapping) or not (set(spec) <= {"domains", "addresses"}):
            raise PolicyError("email constraint takes 'domains' and/or 'addresses'", where=where)
        if not spec:
            raise PolicyError("email constraint must list domains or addresses", where=where)
        domains = tuple(d.lower() for d in _str_list(spec.get("domains", ["-"]), where))
        addresses = tuple(a.lower() for a in _str_list(spec.get("addresses", ["-"]), where))
        return EmailConstraint(
            tuple(d for d in domains if d != "-"), tuple(a for a in addresses if a != "-")
        )
    raise PolicyError(f"unknown constraint kind {kind!r}", where=where)


@dataclass(frozen=True)
class ArgumentConstraints:
    """All constraints on one argument. For grants (``check``), lists are checked
    element-wise and every element must pass; an absent optional argument has nothing to
    constrain and passes. For deny rules (``satisfied_by_some``), one element that passes
    every constraint is enough, so benign elements cannot dilute a forbidden one."""

    arg: str
    constraints: tuple[Constraint, ...]

    def check(self, args: Mapping[str, Any]) -> list[str]:
        if self.arg not in args:
            return []
        value = args[self.arg]
        values: Sequence[Any] = value if isinstance(value, list) else [value]
        failures: list[str] = []
        for item in values:
            for constraint in self.constraints:
                reason = constraint.check(item)
                if reason is not None:
                    failures.append(f"{self.arg}: {reason}")
        return failures

    def satisfied_by_some(self, args: Mapping[str, Any]) -> bool:
        """Existential match used by deny rules: the argument is present and at least one of
        its values (the scalar itself, or any list element) satisfies every constraint. An
        absent argument or an empty list has no such value."""
        if self.arg not in args:
            return False
        value = args[self.arg]
        values: Sequence[Any] = value if isinstance(value, list) else [value]
        return any(all(c.check(item) is None for c in self.constraints) for item in values)
