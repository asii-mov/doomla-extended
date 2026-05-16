"""Tests for the tier-aware ``defended_bash`` tool wrapper.

The Inspect runtime dependencies (``sandbox``, ``store``) and the live alert
reader are faked so the block-decision logic can be exercised in isolation.
Async ``execute`` calls are driven with ``asyncio.run`` to avoid needing a
pytest async plugin.
"""

import asyncio
import sys

from inspect_cyber_defended.alert_reader import FalcoAlert
from inspect_cyber_defended.defended_bash import BLOCK_MESSAGE, defended_bash
from inspect_cyber_defended.tiers import TIER_CONFIGS, Tier

# The package __init__ binds the name ``defended_bash`` to the function, which
# shadows the submodule attribute — reach the module object via sys.modules.
defended_bash_mod = sys.modules["inspect_cyber_defended.defended_bash"]


class FakeExecResult:
    """Stand-in for an Inspect ``ExecResult``."""

    def __init__(self, stdout="", stderr="", returncode=0):
        """Store the preset stdout, stderr, and return code."""
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FakeSandbox:
    """Sandbox whose ``exec`` always returns a preset result."""

    def __init__(self, result):
        """Store the result that ``exec`` will return."""
        self._result = result

    async def exec(self, cmd, timeout):
        """Return the preset result regardless of the command."""
        return self._result


class FakeStore:
    """Minimal dict-backed stand-in for an Inspect ``Store``."""

    def __init__(self):
        """Initialise an empty store."""
        self._d = {}

    def get(self, key, default=None):
        """Return the stored value or ``default``."""
        return self._d.get(key, default)

    def set(self, key, value):
        """Store ``value`` under ``key``."""
        self._d[key] = value


class FakeReader:
    """Returns queued alert batches in order; empty once exhausted."""

    def __init__(self, batches):
        """Queue the alert batches to return on successive calls."""
        self._batches = list(batches)

    def get_new_alerts(self, min_severity="warning"):
        """Pop and return the next queued batch, or an empty list."""
        if self._batches:
            return self._batches.pop(0)
        return []


async def _noop_sleep(_seconds):
    """Replacement for ``asyncio.sleep`` that returns immediately."""
    return None


def _alert(rule, priority):
    """Build a minimal :class:`FalcoAlert` with the given rule and priority."""
    return FalcoAlert(time="2026-05-14T12:00:00Z", priority=priority,
                      rule=rule, output="")


def _patch(monkeypatch, *, exec_result, store, reader=None):
    """Patch the module's sandbox, store, and (optionally) reader factories."""
    monkeypatch.setattr(defended_bash_mod, "sandbox",
                        lambda: FakeSandbox(exec_result))
    monkeypatch.setattr(defended_bash_mod, "store", lambda: store)
    if reader is not None:
        monkeypatch.setattr(defended_bash_mod, "LiveAlertReader",
                            lambda *a, **kw: reader)
    else:
        def _boom(*a, **kw):
            raise AssertionError("LiveAlertReader must not be constructed")

        monkeypatch.setattr(defended_bash_mod, "LiveAlertReader", _boom)
    # Keep Tier 3's grace-period sleep instant.
    monkeypatch.setattr(defended_bash_mod.asyncio, "sleep", _noop_sleep)


def test_tier3_blocks_on_threshold_alert(monkeypatch):
    """A warning-or-above alert yields the generic block string."""
    store = FakeStore()
    reader = FakeReader([[], [_alert("Suspicious Rule", "Warning")]])
    _patch(monkeypatch, exec_result=FakeExecResult(stdout="ran"),
           store=store, reader=reader)

    tool = defended_bash(TIER_CONFIGS[Tier.ACTIVE])
    out = asyncio.run(tool(cmd="whoami", timeout=60))

    assert out == BLOCK_MESSAGE


def test_block_record_contains_rule_names(monkeypatch):
    """The internal ``store()`` block record carries rule names for audit."""
    store = FakeStore()
    reader = FakeReader([[], [_alert("Suspicious Rule", "Warning")]])
    _patch(monkeypatch, exec_result=FakeExecResult(stdout="ran"),
           store=store, reader=reader)

    tool = defended_bash(TIER_CONFIGS[Tier.ACTIVE])
    asyncio.run(tool(cmd="whoami", timeout=60))

    blocks = store.get("falco_blocks_internal")
    assert blocks == [{
        "cmd": "whoami",
        "rules": ["Suspicious Rule"],
        "priorities": ["Warning"],
    }]


def test_tier3_below_threshold_does_not_block(monkeypatch):
    """An alert below ``min_severity_to_block`` returns normal output."""
    store = FakeStore()
    # ACTIVE blocks at >= warning (rank 3); "notice" is rank 2.
    reader = FakeReader([[], [_alert("Low Rule", "Notice")]])
    _patch(monkeypatch, exec_result=FakeExecResult(stdout="ran"),
           store=store, reader=reader)

    tool = defended_bash(TIER_CONFIGS[Tier.ACTIVE])
    out = asyncio.run(tool(cmd="ls", timeout=60))

    assert out == "ran"
    assert store.get("falco_blocks_internal") is None


def test_tier3_no_alerts_returns_output(monkeypatch):
    """Tier 3 with no post-command alerts returns command output."""
    store = FakeStore()
    reader = FakeReader([[], []])
    _patch(monkeypatch, exec_result=FakeExecResult(stdout="ran"),
           store=store, reader=reader)

    tool = defended_bash(TIER_CONFIGS[Tier.ACTIVE])
    out = asyncio.run(tool(cmd="ls", timeout=60))

    assert out == "ran"
    assert store.get("falco_blocks_internal") is None


def test_tier1_returns_output_unchanged(monkeypatch):
    """Tier 1 never blocks, never reads alerts, never writes the store."""
    store = FakeStore()
    _patch(monkeypatch, exec_result=FakeExecResult(stdout="hello"),
           store=store)

    tool = defended_bash(TIER_CONFIGS[Tier.BASELINE])
    out = asyncio.run(tool(cmd="echo hello", timeout=60))

    assert out == "hello"
    assert store.get("falco_blocks_internal") is None


def test_tier2_returns_output_unchanged(monkeypatch):
    """Tier 2 (silent) never blocks, never reads alerts, never writes."""
    store = FakeStore()
    _patch(monkeypatch, exec_result=FakeExecResult(stdout="hello"),
           store=store)

    tool = defended_bash(TIER_CONFIGS[Tier.SILENT])
    out = asyncio.run(tool(cmd="echo hello", timeout=60))

    assert out == "hello"
    assert store.get("falco_blocks_internal") is None


def test_output_includes_stderr_and_exit_code(monkeypatch):
    """Non-zero exits and stderr are annotated onto the returned output."""
    store = FakeStore()
    _patch(monkeypatch,
           exec_result=FakeExecResult(stdout="out", stderr="err",
                                      returncode=2),
           store=store)

    tool = defended_bash(TIER_CONFIGS[Tier.BASELINE])
    out = asyncio.run(tool(cmd="false", timeout=60))

    assert out == "out\n[stderr]\nerr\n[exit code: 2]"
