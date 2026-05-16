"""Aggregate the four solution-variant runs and emit JSON + two focused plots.

Reads:
  - basecase/doomla/logs/2026-05-15T16-28-48+01-00_doomla_*.eval (upstream)
  - doomla/logs_solution_compare/{baseline,silent,active}/*.eval

Writes:
  - data_out/solution_variant_comparison.json
  - data_out/06_completion_and_runtime.png   (4-arm comparison, score + wall + tool calls)
  - data_out/07_silent_vs_active_rules.png   (the framework effect: rule-by-rule alert volume)
"""

import json
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[1]
BASECASE_LOG = (
    REPO.parent.parent / "basecase" / "doomla" / "logs"
    / "2026-05-15T16-28-48+01-00_doomla_5JubM2Sqr8PaAix8xXQyaa.eval"
)
LOG_DIRS = {
    "baseline": REPO / "logs_solution_compare" / "baseline",
    "silent": REPO / "logs_solution_compare" / "silent",
    "active": REPO / "logs_solution_compare" / "active",
}
SILENT_ALERTS = REPO / "data_out" / "silent_alerts.jsonl"

# Per-rule, per-severity counts captured from the ours-active solution run on
# 2026-05-15 (`logs_solution_compare/active/…_Btkt6cWg32j7z4ssmjnSHk.eval`).
# The raw alerts.jsonl was overwritten by the silent re-run (single bind-mount
# target shared across sequential evals); these counts are preserved here so
# plot 07 is reproducible without re-running active.
ACTIVE_RULE_SEV = {
    "Drop and execute new binary in container":              {"Critical": 2},
    "Packet socket created in container":                    {"Notice": 2},
    "Redirect STDOUT/STDIN to Network Connection in Container": {"Notice": 84},
    "Run shell untrusted":                                   {"Notice": 62},
}

INPUT_PER_M, OUTPUT_PER_M, CACHE_WRITE_PER_M, CACHE_READ_PER_M = 3.0, 15.0, 3.75, 0.30


def newest_eval(d: Path) -> Path:
    files = sorted(d.glob("*.eval"))
    if not files:
        raise FileNotFoundError(f"no .eval in {d}")
    return files[-1]


def dump_log(path: Path) -> dict:
    out = subprocess.check_output(
        ["uv", "run", "--no-project", "--with", "inspect_ai",
         "inspect", "log", "dump", str(path)],
        cwd=REPO,
    )
    return json.loads(out)


def wall_seconds(stats: dict) -> float:
    s = datetime.fromisoformat(stats["started_at"].replace("Z", "+00:00"))
    e = datetime.fromisoformat(stats["completed_at"].replace("Z", "+00:00"))
    return (e - s).total_seconds()


def usage_cost(u: dict) -> float:
    return (
        u.get("input_tokens", 0) * INPUT_PER_M
        + u.get("output_tokens", 0) * OUTPUT_PER_M
        + u.get("input_tokens_cache_write", 0) * CACHE_WRITE_PER_M
        + u.get("input_tokens_cache_read", 0) * CACHE_READ_PER_M
    ) / 1_000_000


def summarise(d: dict, label: str) -> dict:
    stats = d.get("stats", {})
    samples = d.get("samples", [])
    sample0 = samples[0] if samples else {}
    msgs = sample0.get("messages", []) or []
    tool_calls = sum(1 for m in msgs for _ in (m.get("tool_calls") or []))
    scores = sample0.get("scores", {}) or {}
    score_obj = scores.get("defended_scorer") or scores.get("includes") or {}
    meta = score_obj.get("metadata") or {}
    if "defended_scorer" in scores:
        score = score_obj.get("value", 0) or 0
    else:
        m = d.get("results", {}).get("scores", [{}])[0].get("metrics", {})
        score = m.get("accuracy", {}).get("value", 0) or 0
    usage_all = stats.get("model_usage") or {}
    model_usage = next(iter(usage_all.values())) if usage_all else {}
    return {
        "label": label,
        "score": float(score),
        "wall_seconds": wall_seconds(stats),
        "total_tokens": model_usage.get("total_tokens", 0),
        "output_tokens": model_usage.get("output_tokens", 0),
        "messages": len(msgs),
        "tool_calls": tool_calls,
        "alert_count_warning_plus": meta.get("alert_count", 0) or 0,
        "alert_count_all": meta.get("alert_count_all_severities", 0) or 0,
        "distinct_rules": meta.get("distinct_rules_triggered", 0) or 0,
        "triggered_rules": meta.get("triggered_rules", []) or [],
        "blocks": meta.get("block_count", 0) or 0,
        "blocked_commands": meta.get("blocked_commands", []) or [],
        "resilience": meta.get("resilience", None),
        "cost_usd": usage_cost(model_usage),
    }


def rules_by_severity(path: Path) -> dict[str, Counter]:
    """Return {severity: Counter(rule_name -> count)} for the alert log."""
    out: dict[str, Counter] = {}
    if not path.exists():
        return out
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            sev = a.get("priority", "?")
            rule = a.get("rule", "?")
            out.setdefault(sev, Counter())[rule] += 1
    return out


def plot_completion_runtime(rows: list[dict], out_png: Path) -> None:
    """4-arm comparison: completion + runtime + tool-call volume.

    Drops the all-zero panels (blocks across 4 arms, alerts where Falco is off)
    that made the previous version unreadable.
    """
    labels = [r["label"] for r in rows]
    colors = ["#777", "#4c72b0", "#dd8452", "#c44e52"]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.5))
    panels = [
        ("Completion (score)", [r["score"] for r in rows], (0, 1.15), "{:.2f}"),
        ("Wall time (min)",
         [r["wall_seconds"] / 60 for r in rows], None, "{:.0f}m"),
        ("Tool calls",
         [r["tool_calls"] for r in rows], None, "{:.0f}"),
    ]
    for ax, (title, values, ylim, fmt) in zip(axes, panels):
        ax.bar(labels, values, color=colors)
        ax.set_title(title)
        if ylim:
            ax.set_ylim(*ylim)
        for i, v in enumerate(values):
            ax.text(i, v, fmt.format(v), ha="center", va="bottom", fontsize=10)
        ax.tick_params(axis="x", labelsize=9)
    fig.suptitle(
        "Doomla solution-variant — completion and operating envelope "
        "(Sonnet 4.5, unbounded)",
        fontsize=12,
    )
    fig.tight_layout()
    fig.savefig(out_png, dpi=120, bbox_inches="tight")
    print(f"wrote {out_png}")


def plot_silent_vs_active_rules(out_png: Path) -> None:
    """Side-by-side stacked bars: per-rule alert counts under silent vs active.

    This is the headline framework-effect plot — it shows the 58→2 drop in
    `Drop and execute new binary` once the agent gets a single block signal.
    """
    silent = rules_by_severity(SILENT_ALERTS)
    # Reconstruct Counters from the preserved active dict.
    active: dict[str, Counter] = {}
    for rule, sev_counts in ACTIVE_RULE_SEV.items():
        for sev, n in sev_counts.items():
            active.setdefault(sev, Counter())[rule] += n

    # Stable rule order from both runs; drop debug/informational/notice rules
    # that exist only as noise — focus on Notice and above to keep the chart
    # readable. (Critical and Warning are the agent-relevant ones.)
    rules = sorted(
        {r for sev in silent.values() for r in sev}
        | {r for sev in active.values() for r in sev}
    )

    severities = ["Critical", "Warning", "Notice"]
    sev_color = {"Critical": "#c44e52", "Warning": "#dd8452", "Notice": "#a3b8d4"}

    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5), sharey=True)
    for ax, (title, data) in zip(
        axes, [("Silent (no blocking)", silent), ("Active (blocking on warning+)", active)]
    ):
        bottoms = np.zeros(len(rules))
        for sev in severities:
            vals = np.array(
                [data.get(sev, Counter()).get(r, 0) for r in rules], dtype=float
            )
            ax.bar(rules, vals, bottom=bottoms, color=sev_color[sev], label=sev)
            bottoms += vals
        ax.set_title(title)
        ax.tick_params(axis="x", labelrotation=30, labelsize=8)
        for label in ax.get_xticklabels():
            label.set_ha("right")
        for i, total in enumerate(bottoms):
            if total > 0:
                ax.text(
                    i, total, f"{int(total)}", ha="center", va="bottom", fontsize=9
                )
        ax.set_ylabel("alerts")
        ax.grid(axis="y", linestyle=":", alpha=0.4)
    axes[1].legend(loc="upper right", fontsize=9)
    fig.suptitle(
        "Falco alerts by rule — silent vs active (same model, same workload)",
        fontsize=12,
    )
    fig.tight_layout()
    fig.savefig(out_png, dpi=120, bbox_inches="tight")
    print(f"wrote {out_png}")


def main() -> None:
    upstream = summarise(dump_log(BASECASE_LOG), "upstream\n(react+bash)")
    rows = [upstream]
    for tier in ("baseline", "silent", "active"):
        rows.append(
            summarise(dump_log(newest_eval(LOG_DIRS[tier])), f"ours\n{tier}")
        )

    out_json = REPO / "data_out" / "solution_variant_comparison.json"
    out_json.write_text(json.dumps(rows, indent=2))
    print(f"wrote {out_json}")

    plot_completion_runtime(
        rows, REPO / "data_out" / "06_completion_and_runtime.png"
    )
    plot_silent_vs_active_rules(
        REPO / "data_out" / "07_silent_vs_active_rules.png"
    )


if __name__ == "__main__":
    main()
