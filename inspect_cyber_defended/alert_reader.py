"""Parsing and reading of Falco alerts emitted as JSON lines.

Two responsibilities, deliberately separated:

1. :class:`LiveAlertReader` — best-effort byte-offset tailing of the alert
   file, used for in-loop Tier 3 block decisions. May miss late-arriving
   alerts; never used for scoring.
2. :func:`read_full_alert_log` — a complete read of the alert file at scoring
   time. This is the source of truth for all detection metrics.

The alert file path is the contract established by the Falco sidecar
(phase 1): ``/var/log/falco/alerts.jsonl``.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

SEVERITY_ORDER = [
    "debug",
    "informational",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
]

DEFAULT_ALERT_PATH = Path("/var/log/falco/alerts.jsonl")


@dataclass
class FalcoAlert:
    """A single Falco alert parsed from one JSON line of the alert log."""

    time: str  # ISO-8601 from Falco
    priority: str
    rule: str
    output: str
    tags: list[str] = field(default_factory=list)
    fields: dict = field(default_factory=dict)

    def severity_rank(self) -> int:
        """Return the alert's severity as an index into ``SEVERITY_ORDER``.

        Unknown priorities rank as ``0`` (lowest) so they never trigger a
        block on their own.
        """
        try:
            return SEVERITY_ORDER.index(self.priority.lower())
        except ValueError:
            return 0

    @property
    def datetime(self) -> datetime | None:
        """Parse the ISO-8601 ``time`` field, tolerating a trailing ``Z``.

        Returns ``None`` if the timestamp cannot be parsed.
        """
        try:
            return datetime.fromisoformat(self.time.replace("Z", "+00:00"))
        except ValueError:
            return None


def _parse_line(line: str) -> FalcoAlert | None:
    """Parse one line of the alert log into a :class:`FalcoAlert`.

    Never raises: blank lines and non-JSON lines return ``None``.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return FalcoAlert(
        time=obj.get("time", ""),
        priority=obj.get("priority", "informational"),
        rule=obj.get("rule", ""),
        output=obj.get("output", ""),
        tags=obj.get("tags", []),
        fields=obj.get("output_fields", {}),
    )


class LiveAlertReader:
    """Tail-based reader for in-loop block decisions (Tier 3 only).

    Best-effort: late-arriving alerts (after the grace period) are missed
    here and only surface in the post-run scorer. This is acceptable for
    blocking — blocking has to be a real-time decision — but it is NOT
    used for any scoring metric.
    """

    def __init__(self, path: Path = DEFAULT_ALERT_PATH):
        """Open the reader, polling up to ~2s for the alert file to appear.

        Falco may create the file lazily, so the constructor waits briefly.
        Once the file exists, the read offset starts at end-of-file so only
        alerts produced after construction are returned.

        Args:
            path: Path to the Falco JSON-lines alert file.
        """
        self.path = path
        self.offset = 0
        for _ in range(20):
            if self.path.exists():
                self.offset = self.path.stat().st_size
                return
            time.sleep(0.1)

    def get_new_alerts(self, min_severity: str = "warning") -> list[FalcoAlert]:
        """Return alerts appended since the last call, at or above a severity.

        Advances the internal byte offset to end-of-file so subsequent calls
        only see newer alerts.

        Args:
            min_severity: Lowest severity to include, by ``SEVERITY_ORDER``.

        Returns:
            New alerts in file order; empty if the file does not yet exist.
        """
        if not self.path.exists():
            return []
        min_rank = SEVERITY_ORDER.index(min_severity.lower())
        out = []
        with self.path.open("r") as f:
            f.seek(self.offset)
            for line in f:
                alert = _parse_line(line)
                if alert and alert.severity_rank() >= min_rank:
                    out.append(alert)
            self.offset = f.tell()
        return out


def read_full_alert_log(path: Path = DEFAULT_ALERT_PATH) -> list[FalcoAlert]:
    """Read the complete alert log for post-run scoring.

    Source of truth for detection metrics. Includes alerts that arrived
    after the agent finished, after a tool call returned, etc.

    Args:
        path: Path to the Falco JSON-lines alert file.

    Returns:
        All parsable alerts in file order; empty if the file does not exist.
    """
    if not path.exists():
        return []
    alerts = []
    with path.open("r") as f:
        for line in f:
            alert = _parse_line(line)
            if alert:
                alerts.append(alert)
    return alerts
