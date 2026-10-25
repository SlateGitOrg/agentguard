"""Command-line interface: ``agentguard <command>``.

Commands
--------
``tools``    list the sandbox tools with their capabilities, impact and flags
``check``    parse a policy and bind it to the sandbox tools (non-zero exit on any problem)
``explain``  dry-run one tool call through the engine and print the decision
``run``      run the agent loop on a sandbox world (scripted model or Ollama)
``eval``     run the scenario suite under every guard configuration
``verify``   verify an audit log's hash chain (and optional anchor) and the taint invariant
``demo``     offline end-to-end demo against the bundled fixtures
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

import yaml

from agentguard.agent import args_preview, run_agent
from agentguard.approval import Approver, ConsoleApprover, approve_all, deny_all
from agentguard.audit import AuditLog, key_from_env, read_anchor, read_records, verify_log
from agentguard.engine import PolicyEngine, SessionState, ToolCall
from agentguard.errors import AgentGuardError
from agentguard.evaluation import CONFIG_NAMES, build_configs, run_suite, write_outputs
from agentguard.labels import Label
from agentguard.policy import Policy, load_policy
from agentguard.providers import OpenAICompatProvider, PrefixedProvider, ScriptedProvider
from agentguard.providers.base import ChatProvider
from agentguard.scenarios import Scenario, load_scenarios
from agentguard.session import GuardedSession, Mode, check_taint_invariant
from agentguard.tools import SANDBOX_SPECS, World, load_world, sandbox_registry

log = logging.getLogger("agentguard")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

DEFAULT_POLICY = "policies/assistant.yaml"
DEFAULT_SCENARIOS = "scenarios"
DEFAULT_WORLDS = "scenarios/worlds"


def _bound_policy(path: str) -> Policy:
    return load_policy(path, sandbox_registry(World()))


def _out(stream: TextIO, text: str = "") -> None:
    stream.write(text + "\n")
    stream.flush()


# ------------------------------------------------------------------------------------------
# commands
# ------------------------------------------------------------------------------------------


def cmd_tools(args: argparse.Namespace, out: TextIO) -> int:
    _out(out, f"{'tool':<12} {'impact':<7} {'egress':<6} capabilities / output label")
    for spec in SANDBOX_SPECS:
        _out(
            out,
            f"{spec.name:<12} {spec.impact.name.lower():<7} {'yes' if spec.egress else '-':<6} "
            f"{', '.join(spec.capabilities)}  [{spec.output_label.describe()}]",
        )
    return EXIT_OK


def cmd_check(args: argparse.Namespace, out: TextIO) -> int:
    policy = _bound_policy(args.policy)
    _out(out, f"policy {policy.name!r} OK (sha256 {policy.digest[:16]}...)")
    rules = policy.taint
    _out(out, f"  taint: low={rules.low} medium={rules.medium} high={rules.high}")
    _out(out, f"  egress: internal={policy.egress.internal} secret={policy.egress.secret}")
    for task in policy.tasks.values():
        cap = task.max_tool_calls if task.max_tool_calls is not None else "none"
        _out(out, f"  task {task.name} (max_tool_calls={cap})")
        for grant in task.grants:
            extras = [
                ac.arg + ": " + ", ".join(c.describe() for c in ac.constraints)
                for ac in grant.constraints
            ]
            if grant.approval.value != "never":
                extras.append(f"approval={grant.approval}")
            if grant.approve_above:
                extras.append(
                    "approve_above " + ", ".join(f"{k}>{v}" for k, v in grant.approve_above.items())
                )
            if grant.rate:
                extras.append(f"rate {grant.rate.calls}/{grant.rate.per_seconds:g}s")
            detail = f"  [{'; '.join(extras)}]" if extras else ""
            _out(out, f"    grant {grant.id}: {grant.capability}{detail}")
        for rule in task.denies:
            _out(out, f"    deny {rule.capability}: {rule.reason}")
        for budget in task.budgets:
            _out(out, f"    budget {budget.id}: {budget.limit} {budget.currency}")
    return EXIT_OK


def cmd_explain(args: argparse.Namespace, out: TextIO) -> int:
    policy = _bound_policy(args.policy)
    engine = PolicyEngine(policy, sandbox_registry(World()), args.task)
    try:
        call_args = json.loads(args.args)
    except json.JSONDecodeError as exc:
        _out(out, f"--args is not JSON: {exc}")
        return EXIT_USAGE
    context = Label.parse(args.context)
    decision = engine.decide(ToolCall(args.tool, call_args), context, SessionState())
    _out(out, f"context: {context.describe()}")
    _out(out, decision.explain())
    return EXIT_OK if decision.allowed else EXIT_FAIL


def _approver(name: str, stdin: TextIO, stdout: TextIO) -> Approver:
    if name == "approve":
        return approve_all
    if name == "console":
        return ConsoleApprover(stdin, stdout)
    return deny_all


def _provider(args: argparse.Namespace) -> ChatProvider:
    if args.script:
        data = yaml.safe_load(Path(args.script).read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise AgentGuardError("script file must contain a list of steps")
        return ScriptedProvider.from_script(data)
    return OpenAICompatProvider(model=args.model) if args.model else OpenAICompatProvider()


def cmd_run(args: argparse.Namespace, out: TextIO) -> int:
    world = load_world(args.world)
    registry = sandbox_registry(world)
    policy = load_policy(args.policy, registry)
    engine = PolicyEngine(policy, registry, args.task)
    audit = AuditLog(args.audit, key=key_from_env()) if args.audit else AuditLog()
    session = GuardedSession(
        engine,
        audit=audit,
        approver=_approver(args.approver, sys.stdin, out),
        mode=Mode(args.mode),
    )
    run = run_agent(
        _provider(args),
        session,
        args.prompt,
        max_turns=args.max_turns,
        max_calls_per_turn=None if args.script else 1,
    )
    audit.close()
    for index, call in enumerate(run.calls, 1):
        _out(out, f"{index:>2}. {call.tool}({args_preview(call.args)})")
        _out(out, f"    -> {call.status.value} [context {call.context}]")
        for reason in call.reasons:
            _out(out, f"       {reason}")
    _out(out, f"stop: {run.stop_reason}")
    if run.final:
        _out(out, f"final: {run.final}")
    _out(out, "world: " + json.dumps(world.summary(), sort_keys=True))
    if args.audit:
        audit.write_anchor(str(args.audit) + ".head")
        _out(out, f"audit: {args.audit} ({len(audit.records)} records, anchor written)")
    return EXIT_OK


def _scenario_provider(model: str, prefix_steps: int) -> Any:
    def factory(scenario: Scenario) -> ChatProvider:
        real = OpenAICompatProvider(model=model)
        if prefix_steps <= 0:
            return real
        scripted = ScriptedProvider.from_script(scenario.script[:prefix_steps])
        return PrefixedProvider(scripted, real, prefix_steps)

    return factory


def cmd_eval(args: argparse.Namespace, out: TextIO) -> int:
    policy = _bound_policy(args.policy)
    scenarios = load_scenarios(args.scenarios)
    if args.only:
        wanted = set(args.only.split(","))
        scenarios = [s for s in scenarios if s.id in wanted]
    configs = build_configs(policy, args.configs.split(","))

    def progress(line: str) -> None:
        if args.verbose:
            _out(sys.stderr, line)

    if args.provider == "ollama":
        suite = run_suite(
            scenarios,
            configs,
            args.worlds,
            split=args.split,
            provider_factory=_scenario_provider(args.model, args.prefix_steps),
            provider_name=f"ollama:{args.model} (first {args.prefix_steps} step(s) scripted)",
            max_turns=args.max_turns,
            max_calls_per_turn=args.calls_per_turn,
            progress=progress,
        )
    else:
        suite = run_suite(
            scenarios,
            configs,
            args.worlds,
            split=args.split,
            max_turns=args.max_turns,
            progress=progress,
        )
    table = suite.markdown().split("\n<details>")[0]
    _out(out, f"provider: {suite.provider}  scenarios: {len(scenarios)}  split: {args.split}")
    _out(out, table)
    if args.out:
        json_path, md_path = write_outputs(suite, args.out, args.stem)
        _out(out, f"wrote {json_path} and {md_path}")
    enforced = [s for s in suite.summaries if s.config in ("guard-unattended",)]
    failed = any(s.invariant_violations or s.audit_failures for s in enforced)
    return EXIT_FAIL if failed else EXIT_OK


def cmd_verify(args: argparse.Namespace, out: TextIO) -> int:
    anchor = read_anchor(args.anchor) if args.anchor else None
    report = verify_log(args.log, key=key_from_env(), anchor=anchor)
    _out(out, f"chain: {report.describe()}")
    if not report.ok:
        return EXIT_FAIL
    violations = check_taint_invariant(list(read_records(args.log)))
    for v in violations:
        _out(out, f"invariant: {v.session} step {v.step}: {v.tool} executed {v.detail}")
    _out(out, f"taint invariant: {'OK' if not violations else f'{len(violations)} violation(s)'}")
    return EXIT_FAIL if violations else EXIT_OK


# ------------------------------------------------------------------------------------------
# demo
# ------------------------------------------------------------------------------------------

DEMO_SCENARIOS = ("bookkeeper-pay-acme", "attack-bookkeeper-bec", "attack-research-exfil-email")


def cmd_demo(args: argparse.Namespace, out: TextIO) -> int:
    root = Path(args.root)
    registry_world = World()
    policy = load_policy(root / DEFAULT_POLICY, sandbox_registry(registry_world))
    scenarios = {s.id: s for s in load_scenarios(root / DEFAULT_SCENARIOS)}
    worlds = root / DEFAULT_WORLDS
    _out(out, f"== agentguard demo: policy {policy.name!r}, scripted (hijackable) model ==")
    with tempfile.TemporaryDirectory(prefix="agentguard-demo-") as tmp:
        audit_path = Path(tmp) / "audit.jsonl"
        from agentguard.scenarios import run_scenario  # local: keeps CLI import light

        for config in build_configs(policy, ["unguarded", "guard-unattended"]):
            for sid in DEMO_SCENARIOS:
                scenario = scenarios[sid]
                result, _run, world = run_scenario(
                    scenario,
                    config,
                    worlds,
                    audit_path=audit_path if config.name == "guard-unattended" else None,
                )
                if scenario.kind == "attack":
                    verdict = "ATTACK SUCCEEDED" if result.attack_success else "attack blocked"
                else:
                    verdict = "task done" if result.success else "task not done"
                _out(out, f"\n[{config.name}] {sid} ({scenario.kind}): {verdict}")
                for line in result.trace:
                    _out(out, f"   {line}")
                transfers = world.summary()["transfers"]
                _out(out, f"   transfers: {transfers}")
        _out(out, "\n== audit log of the guarded runs ==")
        report = verify_log(audit_path)
        records = list(read_records(audit_path))
        _out(out, f"{audit_path.name}: {report.describe()}")
        _out(out, f"taint invariant violations: {len(check_taint_invariant(records))}")
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        victim = next(i for i, line in enumerate(lines) if '"verdict":"deny"' in line)
        record = json.loads(lines[victim])
        record["verdict"] = "allow"
        lines[victim] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        tampered = Path(tmp) / "tampered.jsonl"
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _out(
            out,
            f"after flipping record {victim} from deny to allow: "
            f"{verify_log(tampered).describe()}",
        )
    return EXIT_OK


# ------------------------------------------------------------------------------------------
# entry point
# ------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Capability-based permission engine for LLM agent tool calls.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("tools", help="list sandbox tools")

    p = sub.add_parser("check", help="validate a policy against the sandbox tools")
    p.add_argument("policy", nargs="?", default=DEFAULT_POLICY)

    p = sub.add_parser("explain", help="dry-run one tool call")
    p.add_argument("--policy", default=DEFAULT_POLICY)
    p.add_argument("--task", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--args", default="{}", help="JSON object of tool arguments")
    p.add_argument("--context", default="trusted/public", help="e.g. untrusted/internal")

    p = sub.add_parser("run", help="run the agent on a sandbox world")
    p.add_argument("--policy", default=DEFAULT_POLICY)
    p.add_argument("--task", required=True)
    p.add_argument("--world", default=f"{DEFAULT_WORLDS}/office.yaml")
    p.add_argument("--prompt", required=True)
    p.add_argument("--script", help="YAML list of scripted model steps (default: Ollama)")
    p.add_argument("--model", help="model name for the OpenAI-compatible endpoint")
    p.add_argument("--approver", choices=["deny", "approve", "console"], default="deny")
    p.add_argument("--mode", choices=[m.value for m in Mode], default="enforce")
    p.add_argument("--audit", help="append the audit log to this JSONL file")
    p.add_argument("--max-turns", type=int, default=10)

    p = sub.add_parser("eval", help="run the scenario suite")
    p.add_argument("--policy", default=DEFAULT_POLICY)
    p.add_argument("--scenarios", default=DEFAULT_SCENARIOS)
    p.add_argument("--worlds", default=DEFAULT_WORLDS)
    p.add_argument("--split", choices=["dev", "heldout", "all"], default="all")
    p.add_argument("--configs", default=",".join(CONFIG_NAMES))
    p.add_argument("--only", help="comma-separated scenario ids")
    p.add_argument("--provider", choices=["scripted", "ollama"], default="scripted")
    p.add_argument("--model", default="llama3.1:8b")
    p.add_argument("--max-turns", type=int, default=10)
    p.add_argument(
        "--calls-per-turn",
        type=int,
        default=1,
        help="ollama only: execute at most N tool calls per model turn (default 1)",
    )
    p.add_argument(
        "--prefix-steps",
        type=int,
        default=1,
        help="ollama only: force the first N scripted steps (the content-ingesting step)",
    )
    p.add_argument("--out", help="directory for <stem>.json and <stem>.md")
    p.add_argument("--stem", default="scenarios-scripted")

    p = sub.add_parser("verify", help="verify an audit log")
    p.add_argument("log")
    p.add_argument("--anchor", help="head anchor file written by 'run --audit'")

    p = sub.add_parser("demo", help="offline end-to-end demo")
    p.add_argument("--root", default=".", help="repository root holding policies/ and scenarios/")
    return parser


COMMANDS = {
    "tools": cmd_tools,
    "check": cmd_check,
    "explain": cmd_explain,
    "run": cmd_run,
    "eval": cmd_eval,
    "verify": cmd_verify,
    "demo": cmd_demo,
}


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    stream = out if out is not None else sys.stdout
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return COMMANDS[args.command](args, stream)
    except (AgentGuardError, ValueError, OSError) as exc:
        _out(stream, f"error: {exc}")
        return EXIT_USAGE
