"""Tests for Falco alert parsing and reading."""

import json
from datetime import datetime, timezone

from inspect_cyber_defended.alert_reader import (
    SEVERITY_ORDER,
    FalcoAlert,
    LiveAlertReader,
    _parse_line,
    read_full_alert_log,
)


def _alert_json(priority: str = "warning", rule: str = "Test Rule") -> str:
    """Build one valid Falco JSON-line alert string."""
    return json.dumps(
        {
            "time": "2026-05-14T12:00:00.000000000Z",
            "priority": priority,
            "rule": rule,
            "output": f"{rule} fired",
            "tags": ["container"],
            "output_fields": {"proc.name": "nmap"},
        }
    )


def test_parse_valid_line():
    """A well-formed JSON line parses into a populated FalcoAlert."""
    alert = _parse_line(_alert_json(priority="error", rule="Read Sensitive File"))
    assert isinstance(alert, FalcoAlert)
    assert alert.priority == "error"
    assert alert.rule == "Read Sensitive File"
    assert alert.tags == ["container"]
    assert alert.fields == {"proc.name": "nmap"}


def test_parse_blank_line_returns_none():
    """Blank and whitespace-only lines parse to None without raising."""
    assert _parse_line("") is None
    assert _parse_line("   \n") is None


def test_parse_malformed_json_returns_none():
    """Non-JSON lines parse to None without raising."""
    assert _parse_line("not json at all") is None
    assert _parse_line('{"unterminated": ') is None


def test_parse_missing_fields_uses_defaults():
    """Missing optional keys fall back to documented defaults."""
    alert = _parse_line("{}")
    assert alert is not None
    assert alert.time == ""
    assert alert.priority == "informational"
    assert alert.rule == ""
    assert alert.tags == []
    assert alert.fields == {}


def test_severity_rank_ordering():
    """severity_rank follows SEVERITY_ORDER from debug (low) to emergency."""
    ranks = [FalcoAlert("", p, "", "").severity_rank() for p in SEVERITY_ORDER]
    assert ranks == list(range(len(SEVERITY_ORDER)))
    assert (
        FalcoAlert("", "debug", "", "").severity_rank()
        < FalcoAlert("", "warning", "", "").severity_rank()
        < FalcoAlert("", "critical", "", "").severity_rank()
    )


def test_severity_rank_is_case_insensitive():
    """severity_rank lowercases the priority before lookup."""
    assert FalcoAlert("", "WARNING", "", "").severity_rank() == SEVERITY_ORDER.index(
        "warning"
    )


def test_severity_rank_unknown_priority():
    """An unknown priority ranks as 0 rather than raising."""
    assert FalcoAlert("", "bogus", "", "").severity_rank() == 0


def test_datetime_parses_trailing_z():
    """The datetime property parses ISO-8601 with a trailing Z."""
    alert = FalcoAlert("2026-05-14T12:00:00+00:00", "warning", "", "")
    assert alert.datetime == datetime(2026, 5, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_datetime_invalid_returns_none():
    """The datetime property returns None for an unparsable timestamp."""
    assert FalcoAlert("not-a-time", "warning", "", "").datetime is None


def test_read_full_alert_log_skips_bad_lines(tmp_path):
    """read_full_alert_log returns only parsable alerts, in file order."""
    log = tmp_path / "alerts.jsonl"
    log.write_text(
        _alert_json(rule="First")
        + "\n\n"
        + "garbage line\n"
        + _alert_json(rule="Second")
        + "\n"
    )
    alerts = read_full_alert_log(log)
    assert [a.rule for a in alerts] == ["First", "Second"]


def test_read_full_alert_log_missing_file(tmp_path):
    """read_full_alert_log returns an empty list when the file is absent."""
    assert read_full_alert_log(tmp_path / "nope.jsonl") == []


def test_live_reader_starts_at_eof(tmp_path):
    """LiveAlertReader ignores alerts present before construction."""
    log = tmp_path / "alerts.jsonl"
    log.write_text(_alert_json(rule="Old") + "\n")
    reader = LiveAlertReader(log)
    assert reader.get_new_alerts(min_severity="debug") == []


def test_live_reader_returns_only_new_lines(tmp_path):
    """LiveAlertReader advances its offset and returns each alert once."""
    log = tmp_path / "alerts.jsonl"
    log.write_text(_alert_json(rule="Old") + "\n")
    reader = LiveAlertReader(log)

    with log.open("a") as f:
        f.write(_alert_json(rule="New1") + "\n")
    first = reader.get_new_alerts(min_severity="debug")
    assert [a.rule for a in first] == ["New1"]

    # Nothing appended since: a second call returns nothing.
    assert reader.get_new_alerts(min_severity="debug") == []

    with log.open("a") as f:
        f.write(_alert_json(rule="New2") + "\n")
    second = reader.get_new_alerts(min_severity="debug")
    assert [a.rule for a in second] == ["New2"]


def test_live_reader_filters_by_min_severity(tmp_path):
    """LiveAlertReader drops alerts below the requested severity."""
    log = tmp_path / "alerts.jsonl"
    log.write_text("")
    reader = LiveAlertReader(log)
    with log.open("a") as f:
        f.write(_alert_json(priority="notice", rule="Low") + "\n")
        f.write(_alert_json(priority="critical", rule="High") + "\n")
    alerts = reader.get_new_alerts(min_severity="warning")
    assert [a.rule for a in alerts] == ["High"]
