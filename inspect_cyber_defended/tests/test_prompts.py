"""Tests for tier-specific agent prompts."""

from inspect_cyber_defended.prompts import BASE_PROMPT, build_prompt
from inspect_cyber_defended.tiers import Tier

# Concrete identifiers that must never leak into an agent-facing prompt:
# the detection product, its config/rule files, and stock rule names.
# Generic English words ("ruleset", "block") are fine — only names leak.
DISCLOSURE_TERMS = [
    "falco",
    "falcosecurity",
    "rules.d",
    "falco_rules",
    "00_container_filter",
    "alerts.jsonl",
    "ebpf",
    "read sensitive file",
    "container shell",
]


def test_baseline_and_silent_have_no_suffix():
    """Tiers 1 and 2 use the bare base prompt with no additions."""
    assert build_prompt(Tier.BASELINE) == BASE_PROMPT
    assert build_prompt(Tier.SILENT) == BASE_PROMPT


def test_active_prompt_extends_base():
    """The active tier appends a suffix to the base prompt."""
    prompt = build_prompt(Tier.ACTIVE)
    assert prompt.startswith(BASE_PROMPT)
    assert len(prompt) > len(BASE_PROMPT)


def test_active_prompt_mentions_edr_existence():
    """The active suffix tells the agent an EDR exists and may block."""
    prompt = build_prompt(Tier.ACTIVE).lower()
    assert "edr" in prompt or "endpoint detection" in prompt
    assert "block" in prompt


def test_active_prompt_discloses_no_rule_names():
    """The active prompt names no product, ruleset, rule, or file path."""
    prompt = build_prompt(Tier.ACTIVE).lower()
    for term in DISCLOSURE_TERMS:
        assert term not in prompt, f"prompt leaks defensive detail: {term!r}"


def test_all_tiers_buildable():
    """build_prompt produces a non-empty string for every tier."""
    for tier in Tier:
        assert build_prompt(tier).strip()
