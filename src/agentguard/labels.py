"""Data-flow labels and taint propagation.

A :class:`Label` has two independent dimensions that together form a product lattice:

* **integrity** -- ``TRUSTED`` < ``UNTRUSTED``. Content that came from somewhere an attacker can
  write (the web, an inbound email, a file dropped into a downloads folder) is UNTRUSTED.
* **secrecy** -- ``PUBLIC`` < ``INTERNAL`` < ``SECRET``. Content read from sensitive stores
  raises the secrecy of everything derived from it.

Labels only ever move *up* the lattice: the label of a conversation context is the join of
every label that has entered it, so once a context has seen untrusted text it stays tainted for
the rest of the session. This is deliberately coarse (context-level, not value-level) -- the
model can copy any token from any message into any later tool argument, so value-level tracking
inside an LLM is not sound. See ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum


class Integrity(IntEnum):
    """Integrity level: higher means *less* trustworthy (taint)."""

    TRUSTED = 0
    UNTRUSTED = 1


class Secrecy(IntEnum):
    """Confidentiality level: higher means more sensitive."""

    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


@dataclass(frozen=True, order=True)
class Label:
    """An element of the integrity x secrecy product lattice."""

    integrity: Integrity = Integrity.TRUSTED
    secrecy: Secrecy = Secrecy.PUBLIC

    def join(self, other: Label) -> Label:
        """Least upper bound: the most tainted integrity and the highest secrecy."""
        return Label(max(self.integrity, other.integrity), max(self.secrecy, other.secrecy))

    def flows_to(self, other: Label) -> bool:
        """True if ``self`` is below or equal to ``other`` in the lattice."""
        return self.integrity <= other.integrity and self.secrecy <= other.secrecy

    @property
    def tainted(self) -> bool:
        return self.integrity is Integrity.UNTRUSTED

    def describe(self) -> str:
        return f"{self.integrity.name.lower()}/{self.secrecy.name.lower()}"

    @classmethod
    def parse(cls, text: str) -> Label:
        """Parse ``"untrusted/secret"`` style labels (either part may be omitted)."""
        integrity = Integrity.TRUSTED
        secrecy = Secrecy.PUBLIC
        for part in (p.strip().upper() for p in text.split("/") if p.strip()):
            if part in Integrity.__members__:
                integrity = Integrity[part]
            elif part in Secrecy.__members__:
                secrecy = Secrecy[part]
            else:
                raise ValueError(f"unknown label component {part.lower()!r}")
        return cls(integrity, secrecy)


BOTTOM = Label()
UNTRUSTED = Label(Integrity.UNTRUSTED, Secrecy.PUBLIC)


def join_all(labels: Iterable[Label]) -> Label:
    """Join an iterable of labels; the join of nothing is the bottom element."""
    result = BOTTOM
    for label in labels:
        result = result.join(label)
    return result


@dataclass
class TaintSource:
    """Why the context carries a given label: which step introduced it."""

    step: int
    origin: str
    label: Label


@dataclass
class ContextLabel:
    """Mutable, monotone label of one agent conversation.

    ``absorb`` is the only mutator and it can only raise the label, which makes the
    "taint never decreases" invariant hold by construction (it is also property-tested).
    """

    current: Label = BOTTOM
    sources: list[TaintSource] = field(default_factory=list)

    def absorb(self, label: Label, *, step: int, origin: str) -> bool:
        """Join ``label`` into the context. Returns True if the label went up."""
        joined = self.current.join(label)
        if joined == self.current:
            return False
        self.current = joined
        self.sources.append(TaintSource(step=step, origin=origin, label=label))
        return True

    @property
    def tainted(self) -> bool:
        return self.current.tainted

    def explain(self) -> str:
        if not self.sources:
            return "context is trusted/public"
        parts = [f"step {s.step}: {s.origin} -> {s.label.describe()}" for s in self.sources]
        return "; ".join(parts)
