"""Tamper-evident, hash-chained audit log (JSON Lines).

Every record carries ``seq``, ``prev`` (the previous record's hash) and ``hash``, where::

    hash = H(canonical_json(record without "hash"))

and ``H`` is SHA-256, or HMAC-SHA256 when a key is configured. Verification recomputes every
hash and link, so editing, deleting, inserting or reordering any record breaks the chain at
that point. Two attacks a plain chain cannot catch on its own are addressed explicitly:

* **truncation** (dropping the tail) -- :meth:`AuditLog.head` returns ``(seq, hash)`` which the
  embedding application stores somewhere the agent cannot write (the CLI writes it to a
  ``.head`` anchor file); :func:`verify_log` compares against it.
* **wholesale rewrite** by someone who can recompute SHA-256 -- use an HMAC key that lives
  outside the agent's reach (``AGENTGUARD_AUDIT_KEY``). Without the key a forged chain cannot
  be produced.

Argument values marked ``sensitive`` in a tool schema are replaced by an unsalted SHA-256
digest prefix before they are written, so the log can prove *what* was sent without storing it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from agentguard.errors import AuditError

log = logging.getLogger(__name__)

GENESIS = "0" * 64


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, non-ASCII escaped, str() fallback."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def digest_value(value: Any) -> str:
    """Short, stable fingerprint of a value used in place of sensitive data."""
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()[:16]


def redact(args: Mapping[str, Any], sensitive: frozenset[str]) -> dict[str, Any]:
    return {k: (digest_value(v) if k in sensitive else v) for k, v in args.items()}


class _Hasher:
    def __init__(self, key: bytes | None) -> None:
        self._key = key

    @property
    def keyed(self) -> bool:
        return self._key is not None

    def __call__(self, payload: str) -> str:
        if self._key is None:
            return hashlib.sha256(payload.encode()).hexdigest()
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()


def key_from_env(var: str = "AGENTGUARD_AUDIT_KEY") -> bytes | None:
    value = os.environ.get(var)
    return value.encode() if value else None


class AuditLog:
    """Append-only, hash-chained event log; in memory, optionally mirrored to a file.

    Appending to an existing file first verifies it and continues its chain, so a log that was
    tampered with between runs is refused rather than silently extended.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        key: bytes | None = None,
        clock: Any = time.time,
    ) -> None:
        self._hasher = _Hasher(key)
        self._clock = clock
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._path = Path(path) if path is not None else None
        self._fh: IO[str] | None = None
        if self._path is not None:
            if self._path.exists() and self._path.stat().st_size > 0:
                report = verify_log(self._path, key=key)
                if not report.ok:
                    raise AuditError(f"refusing to append to broken log: {report.describe()}")
                self._records = list(read_records(self._path))
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self._path.open("a", encoding="utf-8")

    @property
    def keyed(self) -> bool:
        return self._hasher.keyed

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def head(self) -> tuple[int, str]:
        """``(seq, hash)`` of the last record, or ``(-1, GENESIS)`` for an empty log."""
        if not self._records:
            return -1, GENESIS
        last = self._records[-1]
        return int(last["seq"]), str(last["hash"])

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one event and return the stored record (including its hash)."""
        if "hash" in fields or "prev" in fields or "seq" in fields:
            raise AuditError("event fields may not override chain fields")
        with self._lock:
            last_seq, prev = self.head()
            seq = last_seq + 1
            record: dict[str, Any] = {
                "seq": seq,
                "ts": round(float(self._clock()), 6),
                "event": event,
                "prev": prev,
                **json.loads(canonical_json(fields)),
            }
            record["hash"] = self._hasher(canonical_json(record))
            self._records.append(record)
            if self._fh is not None:
                try:
                    self._fh.write(canonical_json(record) + "\n")
                    self._fh.flush()
                except OSError as exc:
                    raise AuditError(f"cannot write audit log: {exc}") from exc
        log.debug("audit %s seq=%d", event, seq)
        return record

    def write_anchor(self, path: str | Path) -> None:
        """Persist the current head so later truncation can be detected."""
        seq, digest = self.head()
        Path(path).write_text(json.dumps({"seq": seq, "hash": digest}) + "\n", encoding="utf-8")

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    try:
        with Path(path).open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditError(f"line {lineno}: not JSON ({exc.msg})") from exc
                if not isinstance(record, dict):
                    raise AuditError(f"line {lineno}: record is not an object")
                yield record
    except OSError as exc:
        raise AuditError(f"cannot read audit log: {exc}") from exc


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    records: int
    bad_seq: int | None = None
    reason: str = ""
    head: tuple[int, str] = (-1, GENESIS)

    def describe(self) -> str:
        if self.ok:
            return f"OK: {self.records} records, head seq={self.head[0]} hash={self.head[1][:16]}"
        return f"BROKEN at record {self.bad_seq}: {self.reason}"


def verify_records(
    records: list[dict[str, Any]],
    *,
    key: bytes | None = None,
    anchor: tuple[int, str] | None = None,
) -> VerifyReport:
    """Check sequence numbers, links and hashes; optionally that the head equals ``anchor``."""
    hasher = _Hasher(key)
    prev = GENESIS
    for index, record in enumerate(records):

        def broken(reason: str, index: int = index) -> VerifyReport:
            return VerifyReport(False, len(records), index, reason)

        if record.get("seq") != index:
            return broken(f"expected seq {index}, found {record.get('seq')!r}")
        if record.get("prev") != prev:
            return broken("prev-hash link does not match the preceding record")
        claimed = record.get("hash")
        body = {k: v for k, v in record.items() if k != "hash"}
        if not isinstance(claimed, str) or not hmac.compare_digest(
            claimed, hasher(canonical_json(body))
        ):
            return broken("record hash mismatch (content modified or wrong key)")
        prev = claimed
    head = (len(records) - 1, prev)
    if anchor is not None and (anchor[0], anchor[1]) != head:
        return VerifyReport(
            False,
            len(records),
            min(anchor[0], len(records)),
            f"head {head[0]} does not match anchor {anchor[0]} (truncated or extended)",
            head,
        )
    return VerifyReport(True, len(records), head=head)


def read_anchor(path: str | Path) -> tuple[int, str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return int(data["seq"]), str(data["hash"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise AuditError(f"cannot read anchor {path}: {exc}") from exc


def verify_log(
    path: str | Path, *, key: bytes | None = None, anchor: tuple[int, str] | None = None
) -> VerifyReport:
    try:
        records = list(read_records(path))
    except AuditError as exc:
        return VerifyReport(False, 0, None, str(exc))
    return verify_records(records, key=key, anchor=anchor)
