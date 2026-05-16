"""Aggregate the post-fix Opus 4.7 example-variant runs and emit plot 04.

Reads:
  - logs_opus_rerun/{baseline,silent,active}/*.eval (the post-fix Opus runs)
  - logs_opus_rerun/silent/silent_alerts.jsonl, logs_opus_rerun/active/active_alerts.jsonl

Writes:
  - data_out/opus_rerun.json
  - data_out/04_opus_eval_results.png  (overwrites the pre-fix all-zeros plot)
"""

import json
import subprocess
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[1]
LOG_DIRS = {
    "baseline": REPO / "logs_opus_rerun" / "baseline",
    "silent": REPO / "logs_opus_rerun" / "silent",
    "active": REPO / "logs_opus_rerun" / "active",
}
ALERT_LOGS = {
    "silent": REPO / "logs_opus_rerun" / "silent" / "silent_alerts.jsonl",
    "active": REPO / "logs_opus_rerun" / "active" / "active_alerts_uncapped.jsonl",
}
# Baseline + silent are msg-cap 50 (per the first rerun, kept). Active was
# re-run again with no message limit so the chain could actually complete; the
# `.eval` for that run is the newest in logs_opus_rerun/active/ and the alert
# log is preserved under active_alerts_uncapped.jsonl.
CAP_LABEL = {"baseline": "50-msg cap", "silent": "50-msg cap", "active": "uncapped"}


def newest_eval(d: Path) -> Path:
    files = sorted(d.glob("*.eval"))
    if not files:
        raise FileNotFoundError(f"no .eval in {d}")
    return files[-1]


def load_sample(eval_path: Path) -> dict:
    """An Inspect .eval is a zip; extract the (single) sample json."""
    with zipfile.ZipFile(eval_path) as z:
        sample_names = sorted(n for n in z.namelist() if n.startswith("samples/"))
        if not sample_names:
            raise RuntimeError(f"no sample in {eval_path}")
        return json.loads(z.read(sample_names[0]))


def wall_seconds(eval_path: Path) -> float:
    """Parse start/end timestamps from the .eval header."""
    with zipfile.ZipFile(eval_path) as z:
        for n in ("header.json", "_journal/start.json", "summary.json"):
            if n in z.namelist():
                return _wall_from_header(json.loads(z.read(n)))
        # fallback: use first sample's events
    return 0.0


def _wall_from_header(h: dict) -> float:
    stats = h.get("stats") or {}
    s = stats.get("started_at")
    e = stats.get("completed_at")
    if not (s and e):
        return 0.0
    sd = datetime.fromisoformat(s.replace("Z", "+00:00"))
    ed = datetime.fromisoformat(e.replace("Z", "+00:00"))
    return (ed - sd).total_seconds()


def alert_summary(path: Path) -> dict:
    if not path.exists():
        return {"total": 0, "by_priority": {}, "by_rule": {}}
    by_pri: Counter = Counter()
    by_rule: Counter = Counter()
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            by_pri[a.get("priority", "?")] += 1
            by_rule[a.get("rule", "?")] += 1
    return {
        "total": sum(by_pri.values()),
        "by_priority": dict(by_pri),
        "by_rule": dict(by_rule),
    }


def count_blocks(sample: dict) -> int:
    n = 0
    for m in sample.get("messages", []):
        if m.get("role") != "tool":
            continue
        content = m.get("content") or ""
        if isinstance(content, list):
            content = "".join(
                c.get("text", "") if isinstance(c, dict) else str(c) for c in content
            )
        if "blocked by endpoint security" in content.lower():
            n += 1
    return n


def summarise(tier: str) -> dict:
    eval_path = newest_eval(LOG_DIRS[tier])
    sample = load_sample(eval_path)
    msgs = sample.get("messages", []) or []
    tool_calls = sum(1 for _ in (tc for m in msgs for tc in (m.get("tool_calls") or [])))
    scores = sample.get("scores") or {}
    score_obj = scores.get("defended_scorer") or {}
    meta = score_obj.get("metadata") or {}
    alerts = alert_summary(ALERT_LOGS.get(tier, Path("/nonexistent")))
    warning_plus = sum(
        n for sev, n in alerts["by_priority"].items()
        if sev in ("Warning", "Error", "Critical", "Alert", "Emergency")
    )
    return {
        "tier": tier,
        "score": float(score_obj.get("value", 0) or 0),
        "wall_seconds": wall_seconds(eval_path),
        "messages": len(msgs),
        "tool_calls": tool_calls,
        "alert_count_all": alerts["total"],
        "alert_count_warning_plus": warning_plus,
        "by_rule": alerts["by_rule"],
        "by_priority": alerts["by_priority"],
        "blocks": count_blocks(sample),
        "scorer_metadata": meta,
    }


def plot_opus(rows: list[dict], out_png: Path) -> None:
    labels = [f"{r['tier'].capitalize()}\n({CAP_LABEL[r['tier']]})" for r in rows]
    colors = ["#4c72b0", "#dd8452", "#c44e52"]
    fig, axes = plt.subplots(1, 4, figsize=(15, 4.6))

    panels = [
        ("Completion (score)", [r["score"] for r in rows], (0, 1.15), "{:.2f}", False),
        ("Wall time (min)", [r["wall_seconds"] / 60 for r in rows], None, "{:.1f}m", False),
        # Alerts span 0 → 809; use a log scale so the silent column doesn't vanish.
        ("Falco alerts (all sev., log)", [r["alert_count_all"] for r in rows], None, "{:d}", True),
        ("Tier-3 blocks", [r["blocks"] for r in rows], None, "{:d}", False),
    ]
    for ax, (title, values, ylim, fmt, log_y) in zip(axes, panels):
        ax.bar(labels, values, color=colors)
        ax.set_title(title)
        if ylim:
            ax.set_ylim(*ylim)
        if log_y:
            # Place 0-valued bars just below the lower limit so the text still
            # sits above zero in the visual.
            ax.set_yscale("symlog", linthresh=1)
            ax.set_ylim(0, max(values) * 3 if max(values) else 1)
        for i, v in enumerate(values):
            label = fmt.format(v) if isinstance(v, (int, float)) and v == v else "—"
            offset = (max(values) or 1) * 0.02 if not log_y else 0.5
            ax.text(i, v + offset, label, ha="center", va="bottom", fontsize=10)
        ax.tick_params(axis="x", labelsize=9)

    fig.suptitle(
        "Doomla example-variant — Opus 4.7, post-fix pipeline\n"
        "(baseline + silent: 50-msg cap; active: uncapped, completed the chain)",
        fontsize=11,
    )
    fig.tight_layout()
    fig.savefig(out_png, dpi=120, bbox_inches="tight")
    print(f"wrote {out_png}")


def main() -> None:
    rows = [summarise(t) for t in ("baseline", "silent", "active")]
    out_json = REPO / "data_out" / "opus_rerun.json"
    out_json.write_text(json.dumps(rows, indent=2))
    print(f"wrote {out_json}")
    plot_opus(rows, REPO / "data_out" / "04_opus_eval_results.png")


if __name__ == "__main__":
    main()
