"""Scenario-suite evaluation: run every scenario under several guard configurations.

Configurations (all use the same policy file and the same scenarios):

``unguarded``
    MONITOR mode -- every call runs. The baseline: what the (fake or real) model does with no
    enforcement. The engine still records what it *would* have done.
``guard-unattended``
    ENFORCE with a deny-all approver: nobody is around to approve, so anything that needs a
    human does not happen. Measures the utility cost of the policy.
``guard-rubber-stamp``
    ENFORCE with an approve-all approver: a careless human. Shows which attacks only a human
    stands in front of (approval fatigue is a real attack surface).
``ablation-no-taint``
    ENFORCE with deny-all, but taint rules set to allow everything. Shows what capability
    constraints alone stop, and therefore what data-flow tracking adds.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agentguard.policy import Action, Policy, TaintRules
from agentguard.scenarios import (
    ProviderFactory,
    RunConfig,
    Scenario,
    ScenarioResult,
    SuiteSummary,
    render_markdown,
    run_scenario,
    scripted_provider,
    summarize,
)
from agentguard.session import Mode

log = logging.getLogger(__name__)

CONFIG_NAMES = ("unguarded", "guard-unattended", "guard-rubber-stamp", "ablation-no-taint")


def without_taint_rules(policy: Policy) -> Policy:
    """Ablation only: a policy whose taint rules allow everything.

    This bypasses the parser's "high may not be allow" check on purpose and must never be
    used outside evaluation.
    """
    allow = TaintRules(Action.ALLOW, Action.ALLOW, Action.ALLOW)
    tasks = {name: dataclasses.replace(task, taint=None) for name, task in policy.tasks.items()}
    return dataclasses.replace(policy, taint=allow, tasks=tasks, name=policy.name + "-no-taint")


def build_configs(policy: Policy, names: Sequence[str] = CONFIG_NAMES) -> list[RunConfig]:
    table = {
        "unguarded": RunConfig("unguarded", policy, Mode.MONITOR, "approve"),
        "guard-unattended": RunConfig("guard-unattended", policy, Mode.ENFORCE, "deny"),
        "guard-rubber-stamp": RunConfig("guard-rubber-stamp", policy, Mode.ENFORCE, "approve"),
        "ablation-no-taint": RunConfig(
            "ablation-no-taint", without_taint_rules(policy), Mode.ENFORCE, "deny"
        ),
    }
    unknown = [n for n in names if n not in table]
    if unknown:
        raise ValueError(f"unknown config(s) {unknown}; choose from {list(table)}")
    return [table[n] for n in names]


@dataclass
class SuiteRun:
    provider: str
    split: str
    results: list[ScenarioResult]
    summaries: list[SuiteSummary]
    elapsed_s: float

    def to_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "split": self.split,
            "summaries": [s.as_dict() for s in self.summaries],
            "results": [asdict(r) for r in self.results],
        }

    def markdown(self) -> str:
        return render_markdown(self.summaries, self.results)


def run_suite(
    scenarios: Sequence[Scenario],
    configs: Sequence[RunConfig],
    worlds_dir: str | Path,
    *,
    split: str = "all",
    provider_factory: ProviderFactory = scripted_provider,
    provider_name: str = "scripted",
    max_turns: int = 10,
    max_calls_per_turn: int | None = None,
    progress: Any = None,
) -> SuiteRun:
    """Run every (config, scenario) pair of ``split`` and summarise per config and split."""
    chosen = [s for s in scenarios if split in ("all", s.split)]
    results: list[ScenarioResult] = []
    started = time.monotonic()
    for config in configs:
        for scenario in chosen:
            t0 = time.monotonic()
            result, _run, _world = run_scenario(
                scenario,
                config,
                worlds_dir,
                provider_factory,
                max_turns=max_turns,
                max_calls_per_turn=max_calls_per_turn,
            )
            results.append(result)
            if progress is not None:
                progress(
                    f"[{config.name}] {scenario.id}: "
                    f"{'attack WON' if result.attack_success else 'ok'} "
                    f"done={result.success} calls={result.calls} "
                    f"({time.monotonic() - t0:.1f}s)"
                )
    splits = ["dev", "heldout"] if split == "all" else [split]
    summaries = [summarize(results, c.name, sp) for c in configs for sp in splits]
    return SuiteRun(provider_name, split, results, summaries, time.monotonic() - started)


def write_outputs(run: SuiteRun, out_dir: str | Path, stem: str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{stem}.json"
    md_path = out / f"{stem}.md"
    json_path.write_text(json.dumps(run.to_json(), indent=2, sort_keys=True) + "\n")
    md_path.write_text(run.markdown() + "\n")
    return json_path, md_path
