"""Exception hierarchy for agentguard.

Every error raised by the library derives from :class:`AgentGuardError` so callers can
catch library failures without catching unrelated bugs.
"""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base class for all agentguard errors."""


class PolicyError(AgentGuardError):
    """A policy document is malformed or inconsistent with the tool registry."""

    def __init__(self, message: str, *, where: str = "") -> None:
        self.where = where
        super().__init__(f"{where}: {message}" if where else message)


class SchemaError(AgentGuardError):
    """A tool argument schema is itself invalid (not a validation failure of arguments)."""


class RegistryError(AgentGuardError):
    """A tool was registered twice, or an unknown tool was requested from the registry."""


class AuditError(AgentGuardError):
    """The audit log could not be written or read."""


class ProviderError(AgentGuardError):
    """The model provider failed (transport error, malformed response, script exhausted)."""


class SandboxError(AgentGuardError):
    """A sandboxed fake tool rejected an operation (missing file, insufficient funds...)."""


class ScenarioError(AgentGuardError):
    """A scenario file is malformed."""
