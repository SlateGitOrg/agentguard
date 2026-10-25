"""Sandboxed fake tools (files, e-mail, web, payments) operating on a :class:`World`.

Every handler only mutates the in-memory world. The specs are what matters for the policy
engine: their capabilities, impact, egress flag, spend arguments and output labels.

Labelling choices (see docs/THREAT_MODEL.md):

* ``read_file`` returns the label of the path (world label rules) joined with the label the
  file was *written* with, so text copied out of a tainted context stays tainted when it is
  read back later -- storage cannot launder taint.
* ``list_inbox`` returns only validated structured headers (id, sender address, verified flag),
  never subjects or bodies, so triaging an inbox does not taint the context; ``read_email`` of
  an unverified message does.
* ``fetch_url`` output is always untrusted, and the URL itself is egress (data can leave in a
  query string).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from agentguard.constraints import normalize_path, to_decimal
from agentguard.errors import SandboxError
from agentguard.labels import BOTTOM, Integrity, Label, Secrecy, join_all
from agentguard.tooling import (
    CallContext,
    Impact,
    SpendSpec,
    Tool,
    ToolOutput,
    ToolRegistry,
    ToolSpec,
)
from agentguard.tools.world import Email, FileEntry, Payee, Transfer, World

_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
MAX_FILE_BYTES = 64_000

TRUSTED_INTERNAL = Label(Integrity.TRUSTED, Secrecy.INTERNAL)
UNTRUSTED_PUBLIC = Label(Integrity.UNTRUSTED, Secrecy.PUBLIC)
UNTRUSTED_INTERNAL = Label(Integrity.UNTRUSTED, Secrecy.INTERNAL)


def _obj(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": required if required is not None else list(props),
        "additionalProperties": False,
    }


_PATH = {"type": "string", "minLength": 1, "maxLength": 256, "description": "relative path"}


def _path(args: Mapping[str, Any]) -> str:
    path = normalize_path(str(args["path"]))
    if path is None:
        raise SandboxError(f"invalid path {args['path']!r}")
    return path


class SandboxTools:
    """Factory binding tool handlers to one world instance."""

    def __init__(self, world: World) -> None:
        self.world = world

    # -- files -------------------------------------------------------------------------------

    def list_files(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        base = _path(args)
        prefix = "" if base == "." else base + "/"
        names = sorted(p for p in self.world.files if p.startswith(prefix))
        if not names and base != "." and base not in self.world.files:
            raise SandboxError(f"no such directory: {base}")
        label = join_all(self.world.file_label(p) for p in names)
        return ToolOutput("\n".join(names) or "(empty)", label, {"files": names})

    def read_file(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        path = _path(args)
        entry = self.world.files.get(path)
        if entry is None:
            raise SandboxError(f"no such file: {path}")
        return ToolOutput(entry.content, self.world.file_label(path))

    def write_file(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        path = _path(args)
        if path == ".":
            raise SandboxError("cannot write to the workspace root")
        content = str(args["content"])
        if len(content.encode()) > MAX_FILE_BYTES:
            raise SandboxError(f"file larger than {MAX_FILE_BYTES} bytes")
        previous = self.world.files.get(path)
        # The stored label is the writer's context label; overwriting never lowers it.
        label = ctx.label if previous is None else ctx.label.join(previous.label)
        self.world.files[path] = FileEntry(content, label)
        return ToolOutput(f"wrote {len(content)} characters to {path}")

    def delete_file(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        path = _path(args)
        if path not in self.world.files:
            raise SandboxError(f"no such file: {path}")
        del self.world.files[path]
        self.world.deleted.append(path)
        return ToolOutput(f"deleted {path}")

    # -- e-mail ------------------------------------------------------------------------------

    def list_inbox(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        limit = int(args.get("limit", 20))
        rows = []
        for mail in self.world.inbox[:limit]:
            sender = mail.sender if _ADDRESS_RE.match(mail.sender) else "<invalid sender>"
            rows.append(f"{mail.id}\t{sender}\t{'verified' if mail.verified else 'external'}")
        text = "id\tfrom\tstatus\n" + "\n".join(rows) if rows else "(inbox empty)"
        return ToolOutput(text, BOTTOM)

    def _find_mail(self, mail_id: str) -> Email:
        for mail in self.world.inbox:
            if mail.id == mail_id:
                return mail
        raise SandboxError(f"no message with id {mail_id!r}")

    def read_email(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        mail = self._find_mail(str(args["id"]))
        label = TRUSTED_INTERNAL if mail.verified else UNTRUSTED_INTERNAL
        text = f"From: {mail.sender}\nSubject: {mail.subject}\n\n{mail.body}"
        return ToolOutput(text, label)

    def send_email(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        to = str(args["to"]).strip()
        if not _ADDRESS_RE.match(to):
            raise SandboxError(f"invalid recipient {to!r}")
        mail = Email(
            id=f"out{len(self.world.outbox) + 1}",
            sender=self.world.owner,
            to=to,
            subject=str(args["subject"]),
            body=str(args["body"]),
        )
        self.world.outbox.append(mail)
        return ToolOutput(f"sent message {mail.id} to {to}")

    # -- web ---------------------------------------------------------------------------------

    def fetch_url(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        url = str(args["url"])
        self.world.fetched.append(url)
        page = self.world.pages.get(url)
        if page is None:
            raise SandboxError(f"404 not found: {url}")
        return ToolOutput(page, UNTRUSTED_PUBLIC)

    # -- payments ----------------------------------------------------------------------------

    def get_balance(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        currency = str(args["currency"]).upper()
        balance = self.world.balances.get(currency, Decimal(0))
        return ToolOutput(f"{balance} {currency}", TRUSTED_INTERNAL)

    def list_payees(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        rows = [f"{p.id}\t{p.name}" for p in self.world.payees.values()]
        return ToolOutput("\n".join(rows) or "(no payees)", TRUSTED_INTERNAL)

    def add_payee(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        name = str(args["name"])
        pid = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "payee"
        if pid in self.world.payees:
            raise SandboxError(f"payee {pid!r} already exists")
        self.world.payees[pid] = Payee(pid, name, str(args["account"]))
        return ToolOutput(f"added payee {pid}")

    def pay(self, args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        payee = str(args["payee_id"])
        if payee not in self.world.payees:
            raise SandboxError(f"unknown payee {payee!r}")
        amount = to_decimal(args["amount"])
        if amount is None or amount <= 0:
            raise SandboxError("amount must be a positive number")
        currency = str(args["currency"]).upper()
        balance = self.world.balances.get(currency, Decimal(0))
        if amount > balance:
            raise SandboxError(f"insufficient funds: {balance} {currency}")
        self.world.balances[currency] = balance - amount
        self.world.transfers.append(Transfer(payee, amount, currency, str(args.get("memo", ""))))
        return ToolOutput(f"paid {amount} {currency} to {payee}")

    # -- registry ----------------------------------------------------------------------------

    def registry(self) -> ToolRegistry:
        return ToolRegistry([Tool(spec, getattr(self, spec.name)) for spec in SANDBOX_SPECS])


SANDBOX_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_files",
        "List files under a workspace directory ('.' for everything).",
        ("fs.list",),
        _obj({"path": _PATH}),
        Impact.LOW,
    ),
    ToolSpec(
        "read_file",
        "Read a text file from the workspace.",
        ("fs.read",),
        _obj({"path": _PATH}),
        Impact.LOW,
    ),
    ToolSpec(
        "write_file",
        "Create or overwrite a text file in the workspace.",
        ("fs.write",),
        _obj({"path": _PATH, "content": {"type": "string", "maxLength": MAX_FILE_BYTES}}),
        Impact.MEDIUM,
    ),
    ToolSpec(
        "delete_file",
        "Delete a file from the workspace (irreversible).",
        ("fs.delete",),
        _obj({"path": _PATH}),
        Impact.HIGH,
    ),
    ToolSpec(
        "list_inbox",
        "List message ids and senders in the inbox (no subjects or bodies).",
        ("email.list",),
        _obj({"limit": {"type": "integer", "minimum": 1, "maximum": 50}}, required=[]),
        Impact.LOW,
    ),
    ToolSpec(
        "read_email",
        "Read one e-mail message by id.",
        ("email.read",),
        _obj({"id": {"type": "string", "minLength": 1, "maxLength": 64}}),
        Impact.LOW,
    ),
    ToolSpec(
        "send_email",
        "Send an e-mail on the user's behalf.",
        ("email.send",),
        _obj(
            {
                "to": {"type": "string", "maxLength": 254},
                "subject": {"type": "string", "maxLength": 200},
                "body": {"type": "string", "maxLength": 20_000, "sensitive": True},
            }
        ),
        Impact.HIGH,
        egress=True,
    ),
    ToolSpec(
        "fetch_url",
        "Fetch a web page over HTTPS and return its text.",
        ("web.fetch",),
        _obj({"url": {"type": "string", "maxLength": 2048}}),
        Impact.LOW,
        output_label=UNTRUSTED_PUBLIC,
        egress=True,
    ),
    ToolSpec(
        "get_balance",
        "Get the account balance in one currency.",
        ("payments.read",),
        _obj({"currency": {"type": "string", "pattern": "[A-Za-z]{3}"}}),
        Impact.LOW,
    ),
    ToolSpec(
        "list_payees",
        "List saved payees (id and name).",
        ("payments.read",),
        _obj({}),
        Impact.LOW,
    ),
    ToolSpec(
        "add_payee",
        "Save a new payee with a bank account number.",
        ("payments.payees.add",),
        _obj(
            {
                "name": {"type": "string", "minLength": 1, "maxLength": 80},
                "account": {"type": "string", "maxLength": 64, "sensitive": True},
            }
        ),
        Impact.HIGH,
    ),
    ToolSpec(
        "pay",
        "Pay a saved payee.",
        ("payments.transfer",),
        _obj(
            {
                "payee_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "amount": {"type": "number", "minimum": 0},
                "currency": {"type": "string", "pattern": "[A-Za-z]{3}"},
                "memo": {"type": "string", "maxLength": 140},
            },
            required=["payee_id", "amount", "currency"],
        ),
        Impact.HIGH,
        spend=SpendSpec("amount", "currency"),
    ),
)


def sandbox_registry(world: World) -> ToolRegistry:
    """The full sandbox tool set bound to ``world``."""
    return SandboxTools(world).registry()
