"""The sandbox world: an in-memory stand-in for a file system, a mailbox, the web and a bank.

Nothing here touches the real machine or network. A world is loaded from a YAML fixture and
records every effect (files written/deleted, mail sent, URLs fetched, payments made) so
scenarios can check outcomes -- "was the summary saved?", "did money reach the attacker?" --
from state rather than from what the model *said* it did.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml

from agentguard.constraints import compile_glob, match_glob, normalize_path, to_decimal
from agentguard.errors import ScenarioError
from agentguard.labels import BOTTOM, Label


@dataclass
class FileEntry:
    content: str
    label: Label = BOTTOM


@dataclass(frozen=True)
class Email:
    id: str
    sender: str
    to: str
    subject: str
    body: str
    verified: bool = False  # sender authenticated as an internal, trusted colleague


@dataclass(frozen=True)
class Payee:
    id: str
    name: str
    account: str


@dataclass(frozen=True)
class Transfer:
    payee: str
    amount: Decimal
    currency: str
    memo: str


@dataclass(frozen=True)
class LabelRule:
    glob: str
    label: Label


@dataclass
class World:
    files: dict[str, FileEntry] = field(default_factory=dict)
    label_rules: list[LabelRule] = field(default_factory=list)
    default_file_label: Label = BOTTOM
    inbox: list[Email] = field(default_factory=list)
    outbox: list[Email] = field(default_factory=list)
    pages: dict[str, str] = field(default_factory=dict)
    fetched: list[str] = field(default_factory=list)
    balances: dict[str, Decimal] = field(default_factory=dict)
    payees: dict[str, Payee] = field(default_factory=dict)
    transfers: list[Transfer] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    owner: str = "user@example.com"

    def path_label(self, path: str) -> Label:
        """Static label of a path from the world's label rules (first matching rule wins)."""
        for rule in self.label_rules:
            if match_glob(rule.glob, path):
                return rule.label
        return self.default_file_label

    def file_label(self, path: str) -> Label:
        entry = self.files.get(path)
        static = self.path_label(path)
        return static.join(entry.label) if entry is not None else static

    def clone(self) -> World:
        return copy.deepcopy(self)

    def summary(self) -> dict[str, Any]:
        return {
            "files": sorted(self.files),
            "deleted": list(self.deleted),
            "sent": [{"to": m.to, "subject": m.subject} for m in self.outbox],
            "fetched": list(self.fetched),
            "transfers": [
                {"payee": t.payee, "amount": str(t.amount), "currency": t.currency}
                for t in self.transfers
            ],
            "balances": {k: str(v) for k, v in self.balances.items()},
        }


def _req(data: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in data:
        raise ScenarioError(f"{where}: missing {key!r}")
    return data[key]


def world_from_dict(data: Mapping[str, Any]) -> World:
    """Build a world from its fixture form (see ``scenarios/worlds/*.yaml``)."""
    world = World(owner=str(data.get("owner", "user@example.com")))
    try:
        world.default_file_label = Label.parse(str(data.get("default_file_label", "trusted")))
        for rule in data.get("labels", []):
            compile_glob(str(_req(rule, "glob", "labels")))
            world.label_rules.append(
                LabelRule(str(rule["glob"]), Label.parse(str(_req(rule, "label", "labels"))))
            )
    except ValueError as exc:
        raise ScenarioError(f"bad label: {exc}") from exc
    for raw_path, content in (data.get("files") or {}).items():
        path = normalize_path(str(raw_path))
        if path is None or path == ".":
            raise ScenarioError(f"bad fixture path {raw_path!r}")
        if isinstance(content, Mapping):
            # {content: ..., written_label: untrusted} models a file written earlier by a
            # session whose context carried that label (cross-session taint).
            try:
                written = Label.parse(str(content.get("written_label", "trusted")))
            except ValueError as exc:
                raise ScenarioError(f"bad written_label for {path}: {exc}") from exc
            world.files[path] = FileEntry(str(_req(content, "content", path)), written)
        else:
            world.files[path] = FileEntry(str(content))
    for i, mail in enumerate(data.get("inbox", [])):
        where = f"inbox[{i}]"
        world.inbox.append(
            Email(
                id=str(mail.get("id", f"m{i + 1}")),
                sender=str(_req(mail, "from", where)),
                to=world.owner,
                subject=str(mail.get("subject", "")),
                body=str(_req(mail, "body", where)),
                verified=bool(mail.get("verified", False)),
            )
        )
    world.pages = {str(k): str(v) for k, v in (data.get("pages") or {}).items()}
    for currency, amount in (data.get("balances") or {}).items():
        value = to_decimal(amount)
        if value is None:
            raise ScenarioError(f"bad balance for {currency}")
        world.balances[str(currency).upper()] = value
    for payee in data.get("payees", []):
        pid = str(_req(payee, "id", "payees"))
        world.payees[pid] = Payee(pid, str(payee.get("name", pid)), str(payee.get("account", "")))
    return world


def load_world(path: str | Path) -> World:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScenarioError(f"cannot load world {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ScenarioError(f"world {path} is not a mapping")
    return world_from_dict(data)
