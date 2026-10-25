"""Hash-chained audit log: tamper detection, truncation anchors, HMAC keys, redaction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentguard.audit import (
    GENESIS,
    AuditLog,
    digest_value,
    key_from_env,
    read_anchor,
    read_records,
    redact,
    verify_log,
    verify_records,
)
from agentguard.errors import AuditError


def _log(n: int = 5, key: bytes | None = None, path: Path | None = None) -> AuditLog:
    log = AuditLog(path, key=key, clock=lambda: 1.5)
    for i in range(n):
        log.append("decision", step=i, tool="pay", args={"amount": i})
    return log


def test_chain_links_and_head() -> None:
    log = _log(3)
    recs = log.records
    assert [r["seq"] for r in recs] == [0, 1, 2]
    assert recs[0]["prev"] == GENESIS
    assert recs[1]["prev"] == recs[0]["hash"]
    assert log.head() == (2, recs[2]["hash"])
    assert AuditLog().head() == (-1, GENESIS)
    report = verify_records(recs)
    assert report.ok
    assert report.describe().startswith("OK: 3 records")


def test_reserved_fields_cannot_be_overridden() -> None:
    with pytest.raises(AuditError, match="chain fields"):
        AuditLog().append("x", hash="forged")


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    [
        (lambda r: r[2].__setitem__("args", {"amount": 999}), "hash mismatch"),
        (lambda r: r.pop(2), "expected seq 2"),
        (lambda r: r.insert(1, dict(r[1])), "expected seq 2"),
        (lambda r: r.__setitem__(slice(1, 3), [r[2], r[1]]), "expected seq 1"),
        (lambda r: r[3].__setitem__("prev", "f" * 64), "prev-hash link"),
        (lambda r: r[0].__setitem__("hash", None), "hash mismatch"),
    ],
)
def test_tampering_is_detected(mutation: Any, fragment: str) -> None:
    records = _log(5).records
    mutation(records)
    report = verify_records(records)
    assert not report.ok
    assert fragment in report.reason
    assert report.describe().startswith("BROKEN at record")


def test_truncation_needs_an_anchor() -> None:
    log = _log(5)
    truncated = log.records[:3]
    assert verify_records(truncated).ok  # a bare chain cannot see a dropped tail...
    report = verify_records(truncated, anchor=log.head())
    assert not report.ok  # ...but the anchor can
    assert "does not match anchor" in report.reason


def test_rewrite_is_detected_with_hmac_key() -> None:
    keyed = _log(3, key=b"k1")
    assert keyed.keyed
    assert verify_records(keyed.records, key=b"k1").ok
    assert not verify_records(keyed.records, key=b"k2").ok
    assert not verify_records(keyed.records).ok
    # An attacker without the key recomputes an unkeyed chain: it fails keyed verification.
    forged = _log(3)
    assert verify_records(forged.records).ok
    assert not verify_records(forged.records, key=b"k1").ok


@given(st.integers(0, 9), st.sampled_from(["event", "tool", "step", "ts"]), st.text(max_size=5))
def test_any_single_field_edit_breaks_verification(index: int, key: str, value: str) -> None:
    records = _log(10).records
    if records[index].get(key) == value:
        return
    records[index][key] = value
    assert not verify_records(records).ok


def test_file_persistence_reopen_and_anchor(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    with _log(3, path=path) as log:
        log.write_anchor(tmp_path / "audit.head")
    assert verify_log(path).ok
    with AuditLog(path) as again:  # continues the chain
        again.append("decision", step=99)
    records = list(read_records(path))
    assert len(records) == 4
    assert verify_log(path).ok
    anchor = read_anchor(tmp_path / "audit.head")
    assert anchor[0] == 2
    report = verify_log(path, anchor=anchor)
    assert not report.ok  # extended beyond the anchor


def test_refuses_to_extend_a_tampered_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _log(3, path=path).close()
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["args"] = {"amount": 1_000_000}
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError, match="refusing to append"):
        AuditLog(path)


def test_read_errors(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json}\n")
    assert "not JSON" in verify_log(bad).reason
    bad.write_text("[1, 2]\n\n")
    assert "not an object" in verify_log(bad).reason
    assert "cannot read" in verify_log(tmp_path / "missing.jsonl").reason
    with pytest.raises(AuditError, match="cannot read anchor"):
        read_anchor(tmp_path / "missing.head")


def test_write_failure_is_an_audit_error(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    assert log._fh is not None
    log._fh.close()  # simulate the disk going away

    class Broken:
        def write(self, _s: str) -> int:
            raise OSError("disk full")

        def flush(self) -> None:  # pragma: no cover - never reached
            return None

        def close(self) -> None:
            return None

    log._fh = Broken()  # type: ignore[assignment]
    with pytest.raises(AuditError, match="disk full"):
        log.append("x")
    log.close()


def test_redaction_and_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    args = {"to": "a@example.com", "body": "secret text"}
    out = redact(args, frozenset({"body"}))
    assert out["to"] == "a@example.com"
    assert out["body"] == digest_value("secret text")
    assert out["body"].startswith("sha256:")
    assert "secret" not in json.dumps(out)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "abc")
    assert key_from_env() == b"abc"
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEY")
    assert key_from_env() is None
