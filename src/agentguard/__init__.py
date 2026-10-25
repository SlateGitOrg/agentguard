"""agentguard: capability-based permissions, taint tracking and tamper-evident audit for
LLM agent tool calls.

Typical embedding::

    registry = ToolRegistry([...])                 # your tools, each with a ToolSpec
    policy = load_policy("policy.yaml", registry)  # strict, fail-closed parsing + binding
    engine = PolicyEngine(policy, registry, task="inbox-assistant")
    session = GuardedSession(engine, audit=AuditLog("audit.jsonl"), approver=my_hook)
    result = session.call(ToolCall("send_email", {...}))   # the only way a tool runs
"""

from agentguard.agent import AgentRun, run_agent
from agentguard.approval import (
    ApprovalRequest,
    ApprovalResponse,
    Approver,
    approve_all,
    deny_all,
)
from agentguard.audit import AuditLog, verify_log, verify_records
from agentguard.engine import Decision, PolicyEngine, ToolCall, Verdict
from agentguard.errors import (
    AgentGuardError,
    AuditError,
    PolicyError,
    ProviderError,
    RegistryError,
    SandboxError,
    ScenarioError,
    SchemaError,
)
from agentguard.labels import Integrity, Label, Secrecy
from agentguard.policy import Policy, load_policy, parse_policy
from agentguard.session import CallResult, GuardedSession, Mode, Status, check_taint_invariant
from agentguard.tooling import Impact, SpendSpec, Tool, ToolOutput, ToolRegistry, ToolSpec

__version__ = "0.1.0"

__all__ = [
    "AgentGuardError",
    "AgentRun",
    "ApprovalRequest",
    "ApprovalResponse",
    "Approver",
    "AuditError",
    "AuditLog",
    "CallResult",
    "Decision",
    "GuardedSession",
    "Impact",
    "Integrity",
    "Label",
    "Mode",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "ProviderError",
    "RegistryError",
    "SandboxError",
    "ScenarioError",
    "SchemaError",
    "Secrecy",
    "SpendSpec",
    "Status",
    "Tool",
    "ToolCall",
    "ToolOutput",
    "ToolRegistry",
    "ToolSpec",
    "Verdict",
    "__version__",
    "approve_all",
    "check_taint_invariant",
    "deny_all",
    "load_policy",
    "parse_policy",
    "run_agent",
    "verify_log",
    "verify_records",
]
