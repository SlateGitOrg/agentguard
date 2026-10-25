"""Shared fixtures. The ``AGENTGUARD_HYPOTHESIS_PROFILE=thorough`` env var runs the property
tests with many more examples (``make fuzz``)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

settings.register_profile("default", max_examples=200, deadline=None)
settings.register_profile(
    "thorough", max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.load_profile(os.environ.get("AGENTGUARD_HYPOTHESIS_PROFILE", "default"))

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def root() -> Path:
    return ROOT
