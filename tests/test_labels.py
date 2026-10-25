"""Unit and property tests for the label lattice and monotone context labels."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentguard.labels import (
    BOTTOM,
    UNTRUSTED,
    ContextLabel,
    Integrity,
    Label,
    Secrecy,
    join_all,
)

labels = st.builds(Label, st.sampled_from(Integrity), st.sampled_from(Secrecy))


def test_parse_and_describe_round_trip() -> None:
    assert Label.parse("untrusted/secret") == Label(Integrity.UNTRUSTED, Secrecy.SECRET)
    assert Label.parse("internal") == Label(Integrity.TRUSTED, Secrecy.INTERNAL)
    assert Label.parse("") == BOTTOM
    for label in (BOTTOM, UNTRUSTED, Label(Integrity.UNTRUSTED, Secrecy.INTERNAL)):
        assert Label.parse(label.describe()) == label


def test_parse_rejects_unknown_component() -> None:
    with pytest.raises(ValueError, match="unknown label component 'classified'"):
        Label.parse("trusted/classified")


def test_tainted_flag() -> None:
    assert UNTRUSTED.tainted
    assert not Label(Integrity.TRUSTED, Secrecy.SECRET).tainted


def test_join_all_of_nothing_is_bottom() -> None:
    assert join_all([]) == BOTTOM


@given(labels, labels)
def test_join_is_commutative_and_an_upper_bound(a: Label, b: Label) -> None:
    j = a.join(b)
    assert j == b.join(a)
    assert a.flows_to(j)
    assert b.flows_to(j)


@given(labels, labels, labels)
def test_join_is_associative_and_least(a: Label, b: Label, c: Label) -> None:
    assert a.join(b).join(c) == a.join(b.join(c))
    if a.flows_to(c) and b.flows_to(c):
        assert a.join(b).flows_to(c)


@given(labels)
def test_join_is_idempotent_with_bottom_identity(a: Label) -> None:
    assert a.join(a) == a
    assert a.join(BOTTOM) == a


@given(st.lists(st.tuples(labels, st.text(max_size=5)), max_size=30))
def test_context_label_never_decreases(events: list[tuple[Label, str]]) -> None:
    ctx = ContextLabel()
    history = [ctx.current]
    for step, (label, origin) in enumerate(events):
        raised = ctx.absorb(label, step=step, origin=origin)
        assert history[-1].flows_to(ctx.current)
        assert raised == (ctx.current != history[-1])
        history.append(ctx.current)
    # the final label is exactly the join of everything absorbed
    assert ctx.current == join_all(label for label, _ in events)
    # once tainted, always tainted
    first = next((i for i, h in enumerate(history) if h.tainted), None)
    if first is not None:
        assert all(h.tainted for h in history[first:])


def test_context_explain_names_the_source() -> None:
    ctx = ContextLabel()
    assert ctx.explain() == "context is trusted/public"
    assert ctx.absorb(UNTRUSTED, step=3, origin="fetch_url")
    assert not ctx.absorb(BOTTOM, step=4, origin="read_file")
    assert ctx.tainted
    assert ctx.explain() == "step 3: fetch_url -> untrusted/public"
