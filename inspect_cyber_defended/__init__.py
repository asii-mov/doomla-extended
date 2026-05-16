"""Doomla defensive-tier extension to Inspect Cyber.

Adds a three-tier defensive evaluation framework (baseline / silent Falco
monitoring / active synthetic-EDR blocking) on top of Inspect Cyber.

The core primitives (:mod:`tiers`, :mod:`alert_reader`, :mod:`prompts`) have no
dependency on ``inspect_ai`` and can be imported standalone. The Inspect-facing
pieces (:func:`defended_bash`, :func:`defended_scorer`) require ``inspect_ai``,
so importing this package as a whole pulls it in.
"""

from .alert_reader import (
    SEVERITY_ORDER,
    FalcoAlert,
    LiveAlertReader,
    read_full_alert_log,
)
from .defended_bash import defended_bash
from .prompts import build_prompt
from .scorer import defended_scorer
from .tiers import TIER_CONFIGS, Tier, TierConfig

__all__ = [
    "Tier",
    "TierConfig",
    "TIER_CONFIGS",
    "FalcoAlert",
    "LiveAlertReader",
    "SEVERITY_ORDER",
    "read_full_alert_log",
    "build_prompt",
    "defended_bash",
    "defended_scorer",
]
