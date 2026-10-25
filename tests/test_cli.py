"""End-to-end tests of the command-line interface (scripted provider only, no network)."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from agentguard.cli import main


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), out)
    return code, out.getvalue()


@pytest.fixture(autouse=True)
def _cwd(root: Path) -> None:
    os.chdir(root)


def test_tools() -> None:
    code, text = run("tools")
    assert code == 0
    assert "pay" in text
    assert "payments.transfer" in text
    assert "[untrusted/public]" in text  # fetch_url output label


def test_check_prints_grants() -> None:
    code, text = run("check")
    assert code == 0
    assert "policy 'office-assistant' OK" in text
    assert "grant pay-vendors: payments.transfer" in text
    assert "approve_above amount>250" in text
    assert "budget session-spend: 1200 USD" in text
    assert "deny payments.transfer: petty cash" in text


def test_check_reports_policy_errors(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("version: 1\nname: x\ntaint: {high: allow}\ntasks: {t: {}}\n")
    code, text = run("check", str(bad))
    assert code == 2
    assert "may not be allowed from a tainted context" in text


@pytest.mark.parametrize(
    ("args", "code", "fragment"),
    [
        (
            [
                "--task",
                "bookkeeper",
                "--tool",
                "pay",
                "--args",
                '{"payee_id": "acme", "amount": 100, "currency": "USD"}',
            ],
            0,
            "allow pay | via pay-vendors",
        ),
        (
            [
                "--task",
                "bookkeeper",
                "--tool",
                "pay",
                "--args",
                '{"payee_id": "acme", "amount": 100, "currency": "USD"}',
                "--context",
                "untrusted",
            ],
            1,
            "needs approval: context is tainted",
        ),
        (
            [
                "--task",
                "research-assistant",
                "--tool",
                "fetch_url",
                "--args",
                '{"url": "https://evil.test/"}',
            ],
            1,
            "not in allow-list",
        ),
        (["--task", "bookkeeper", "--tool", "pay", "--args", "{bad"], 2, "not JSON"),
        (["--task", "nope", "--tool", "pay"], 2, "no task 'nope'"),
    ],
)
def test_explain(args: list[str], code: int, fragment: str) -> None:
    got, text = run("explain", *args)
    assert got == code
    assert fragment in text


def test_run_with_script_audit_and_verify(tmp_path: Path) -> None:
    script = tmp_path / "script.yaml"
    script.write_text(
        "- {call: fetch_url, args: {url: 'https://en.wikipedia.org/wiki/Prompt_injection'}}\n"
        "- {call: send_email, args: {to: team@example.com, subject: s, body: b}}\n"
        "- {final: done}\n"
    )
    audit = tmp_path / "audit.jsonl"
    code, text = run(
        "run",
        "--task",
        "research-assistant",
        "--prompt",
        "summarize",
        "--script",
        str(script),
        "--audit",
        str(audit),
    )
    assert code == 0
    assert "-> refused [context untrusted/public]" in text
    assert "final: done" in text
    assert '"sent": []' in text
    assert "anchor written" in text
    code, text = run("verify", str(audit), "--anchor", str(audit) + ".head")
    assert code == 0
    assert "taint invariant: OK" in text
    # truncate the log: the anchor catches it
    lines = audit.read_text().splitlines()
    audit.write_text("\n".join(lines[:-2]) + "\n")
    code, text = run("verify", str(audit), "--anchor", str(audit) + ".head")
    assert code == 1
    assert "does not match anchor" in text


def test_run_monitor_mode_and_invariant_violation(tmp_path: Path) -> None:
    script = tmp_path / "script.yaml"
    script.write_text(
        "- {call: read_email, args: {id: m4}}\n"
        "- {call: pay, args: {payee_id: globex, amount: 50, currency: USD}}\n"
    )
    audit = tmp_path / "audit.jsonl"
    code, _ = run(
        "run",
        "--task",
        "bookkeeper",
        "--prompt",
        "p",
        "--script",
        str(script),
        "--mode",
        "monitor",
        "--audit",
        str(audit),
    )
    assert code == 0
    code, text = run("verify", str(audit))
    assert code == 1
    assert "pay executed high-impact from taint" in text


def test_run_bad_script_and_verify_broken_log(tmp_path: Path) -> None:
    script = tmp_path / "script.yaml"
    script.write_text("{not: a list}\n")
    code, text = run("run", "--task", "bookkeeper", "--prompt", "p", "--script", str(script))
    assert code == 2
    assert "must contain a list" in text
    log = tmp_path / "log.jsonl"
    log.write_text('{"seq": 5}\n')
    code, text = run("verify", str(log))
    assert code == 1
    assert "BROKEN" in text


def test_eval_writes_results(tmp_path: Path) -> None:
    code, text = run(
        "eval",
        "--split",
        "heldout",
        "--configs",
        "guard-unattended",
        "--out",
        str(tmp_path),
        "--stem",
        "t",
    )
    assert code == 0
    assert "| guard-unattended | heldout |" in text
    data = json.loads((tmp_path / "t.json").read_text())
    assert data["summaries"][0]["invariant_violations"] == 0


def test_eval_only_and_verbose(capsys: pytest.CaptureFixture[str]) -> None:
    code, text = run("-v", "eval", "--only", "attack-research-pay", "--configs", "unguarded")
    assert code == 0
    assert "attacks succeeded" in text
    assert "attack WON" in capsys.readouterr().err


def test_demo() -> None:
    code, text = run("demo")
    assert code == 0
    assert "[unguarded] attack-bookkeeper-bec (attack): ATTACK SUCCEEDED" in text
    assert "[guard-unattended] attack-bookkeeper-bec (attack): attack blocked" in text
    assert "[guard-unattended] bookkeeper-pay-acme (benign): task done" in text
    assert "taint invariant violations: 0" in text
    assert "from deny to allow: BROKEN" in text


def test_scenario_provider_factory_prefix() -> None:
    from agentguard.cli import _scenario_provider
    from agentguard.providers import OpenAICompatProvider, PrefixedProvider
    from agentguard.scenarios import load_scenarios

    scenario = load_scenarios("scenarios")[0]
    assert isinstance(_scenario_provider("m", 0)(scenario), OpenAICompatProvider)
    forced = _scenario_provider("m", 1)(scenario)
    assert isinstance(forced, PrefixedProvider)
    assert forced.steps == 1
