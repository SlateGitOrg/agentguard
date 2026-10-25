# agentguard -- every gate runs through uv so a fresh clone needs only `uv` on PATH.
UV ?= uv
RUN := $(UV) run --frozen

.PHONY: install fmt format-check lint typecheck test cov check demo eval eval-ollama bench fuzz clean

.venv: pyproject.toml uv.lock
	$(UV) sync --frozen
	@touch .venv

install: .venv

fmt: .venv
	$(RUN) ruff format src tests benchmarks
	$(RUN) ruff check --fix src tests benchmarks

format-check: .venv
	$(RUN) ruff format --check src tests benchmarks

lint: .venv
	$(RUN) ruff check src tests benchmarks

typecheck: .venv
	$(RUN) mypy

test: .venv
	$(RUN) pytest

cov: .venv
	$(RUN) pytest --cov --cov-report=term

# The single gate: formatting, zero lint warnings, strict mypy, tests with >=85% coverage.
check: format-check lint typecheck cov

demo: .venv
	$(RUN) agentguard demo

# Deterministic scenario suite (scripted hijackable model); rewrites the committed results.
eval: .venv
	$(RUN) agentguard eval --out evals/results --stem scenarios-scripted

# Real model run (needs a local Ollama with llama3.1:8b; slow, never part of `check`).
eval-ollama: .venv
	$(RUN) agentguard -v eval --provider ollama --model llama3.1:8b \
		--configs unguarded,guard-unattended --max-turns 8 --calls-per-turn 1 --prefix-steps 1 \
		--out evals/results --stem scenarios-llama3.1-8b

bench: .venv
	$(RUN) python benchmarks/bench_engine.py

fuzz: .venv
	AGENTGUARD_HYPOTHESIS_PROFILE=thorough $(RUN) pytest tests/test_properties_constraints.py \
		tests/test_properties_invariants.py tests/test_labels.py tests/test_limits.py tests/test_audit.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage .hypothesis
