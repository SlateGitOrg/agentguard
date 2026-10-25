"""Property tests: the glob compiler agrees with a reference matcher, path normalisation
never escapes the sandbox, and URL / amount checks fail closed."""

from __future__ import annotations

from decimal import Decimal

from hypothesis import assume, given
from hypothesis import strategies as st

from agentguard.constraints import (
    build_constraint,
    glob_match,
    match_glob,
    normalize_path,
)

SEG_CHARS = st.sampled_from(["a", "b", "c", "."])
segment = st.text(SEG_CHARS, min_size=1, max_size=3).filter(lambda s: s not in (".", ".."))
pattern_segment = st.one_of(
    segment,
    st.just("*"),
    st.just("**"),
    st.just("a*"),
    st.just("?"),
    st.just("*b"),
)


def ref_segment(pat: str, seg: str) -> bool:
    """Reference single-segment matcher for '*', '?' and literals (recursive, obviously right)."""
    if not pat:
        return not seg
    if pat[0] == "*":
        return any(ref_segment(pat[1:], seg[i:]) for i in range(len(seg) + 1))
    if not seg:
        return False
    if pat[0] == "?" or pat[0] == seg[0]:
        return ref_segment(pat[1:], seg[1:])
    return False


def ref_match(pats: list[str], segs: list[str]) -> bool:
    if not pats:
        return not segs
    head = pats[0]
    if head == "**":
        if len(pats) == 1:
            return True  # trailing ** also matches the directory itself (zero segments)
        return any(ref_match(pats[1:], segs[i:]) for i in range(len(segs) + 1))
    return bool(segs) and ref_segment(head, segs[0]) and ref_match(pats[1:], segs[1:])


@given(st.lists(pattern_segment, min_size=1, max_size=4), st.lists(segment, min_size=1, max_size=5))
def test_glob_agrees_with_reference(pats: list[str], segs: list[str]) -> None:
    pattern = "/".join(pats)
    path = "/".join(segs)
    expected = ref_match(pats, segs)
    if pats == ["**"]:
        expected = True
    assert match_glob(pattern, path) == expected


@given(st.lists(st.one_of(segment, st.just(".."), st.just("."), st.just("")), max_size=8))
def test_normalized_paths_never_escape(parts: list[str]) -> None:
    raw = "/".join(parts)
    norm = normalize_path(raw)
    if norm is None:
        return
    assert not norm.startswith("/")
    assert ".." not in norm.split("/")
    assert normalize_path(norm) == norm  # idempotent
    # escaping: the running depth must never go negative for accepted paths
    depth = 0
    for p in parts:
        if p == "..":
            depth -= 1
        elif p not in ("", "."):
            depth += 1
        assert depth >= 0


@given(st.lists(segment, min_size=1, max_size=4), st.integers(min_value=1, max_value=4))
def test_dotdot_escape_never_matches_any_glob(segs: list[str], ups: int) -> None:
    # "notes/x/../../.." climbs out of the root -> must never match even '**'
    path = "/".join(segs + [".."] * (len(segs) + ups))
    assert not glob_match("**", path)


hosts = st.from_regex(r"[a-z]{1,8}(\.[a-z]{1,8}){1,2}", fullmatch=True)


@given(hosts, hosts)
def test_url_host_must_be_listed(allowed: str, other: str) -> None:
    assume(other != allowed)
    c = build_constraint("url", {"hosts": [allowed]}, "t")
    assert c.check(f"https://{allowed}/x") is None
    assert c.check(f"https://{other}/x") is not None
    assert c.check(f"https://{allowed}.{other}/x") is not None
    assert c.check(f"https://{allowed}@{other}/x") is not None
    assert c.check(f"https://{other}@{allowed}/x") is not None


@given(st.decimals(allow_nan=False, allow_infinity=False, places=2), st.integers(0, 10_000))
def test_max_matches_exact_arithmetic(amount: Decimal, limit: int) -> None:
    c = build_constraint("max", limit, "t")
    assert (c.check(str(amount)) is None) == (amount <= limit)


@given(st.from_regex(r"[a-z]{1,6}", fullmatch=True), hosts, hosts)
def test_email_domain_allow_list(user: str, allowed: str, other: str) -> None:
    assume(other != allowed and not other.endswith("." + allowed))
    c = build_constraint("email", {"domains": [allowed]}, "t")
    assert c.check(f"{user}@{allowed}") is None
    assert c.check(f"{user}@{other}") is not None
    assert c.check(f"{user}@{allowed}.{other}") is not None
