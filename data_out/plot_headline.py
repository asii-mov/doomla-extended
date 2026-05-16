"""Aggregate the example-variant uncapped runs and emit the cross-model plot.

Reads (newest .eval per dir):
  - logs_sonnet_example/{silent,active}/*.eval
  - logs_opus_rerun/{silent,active,active_informed}/*.eval
  - logs_*/[silent|active|active_informed]/*_alerts*.jsonl (where present)

Writes:
  - data_out/headline_data.json
  - data_out/01_headline_example_uncapped.png  (5-arm comparison)
"""

import json
import zipfile
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parents[1]

# Pricing per million tokens (USD)
PRICING = {
    "anthropic/claude-sonnet-4-5": {"input": 3.0, "cw": 3.75, "cr": 0.30, "output": 15.0},
    "anthropic/claude-opus-4-7": {"input": 15.0, "cw": 18.75, "cr": 1.50, "output": 75.0},
}

# Five-arm definition. Each row: (label, model, log_dir, alerts_file_or_None)
ARMS = [
    ("Sonnet\nsilent",
     "anthropic/claude-sonnet-4-5",
     REPO / "logs_sonnet_example" / "silent",
     REPO / "logs_sonnet_example" / "silent" / "silent_alerts.jsonl"),
    ("Sonnet\nactive",
     "anthropic/claude-sonnet-4-5",
     REPO / "logs_sonnet_example" / "active",
     REPO / "logs_sonnet_example" / "active" / "active_alerts.jsonl"),
    ("Opus\nsilent",
     "anthropic/claude-opus-4-7",
     REPO / "logs_opus_rerun" / "silent",
     REPO / "logs_opus_rerun" / "silent" / "silent_alerts_uncapped.jsonl"),
    ("Opus\nactive",
     "anthropic/claude-opus-4-7",
     REPO / "logs_opus_rerun" / "active",
     REPO / "logs_opus_rerun" / "active" / "active_alerts_uncapped.jsonl"),
    ("Opus\nactive +\nrules disclosed",
     "anthropic/claude-opus-4-7",
     REPO / "logs_opus_rerun" / "active_informed",
     REPO / "logs_opus_rerun" / "active_informed" / "active_informed_alerts.jsonl"),
]

# Distinct colors: Sonnet (cool tones), Opus (warm tones), informed (red).
COLORS = ["#4c72b0", "#5e9eb3", "#dd8452", "#c44e52", "#8b2331"]


def newest_eval(d: Path) -> Path:
    files = sorted(d.glob("*.eval"))
    if not files:
        raise FileNotFoundError(f"no .eval in {d}")
    return files[-1]


def load_eval(eval_path: Path) -> tuple[dict, dict]:
    """Return (sample, header) parsed from the .eval zip."""
    with zipfile.ZipFile(eval_path) as z:
        sample_names = sorted(n for n in z.namelist() if n.startswith("samples/"))
        sample = json.loads(z.read(sample_names[0])) if sample_names else {}
        header = {}
        for name in ("header.json", "summary.json"):
            if name in z.namelist():
                try:
                    header = json.loads(z.read(name))
                    break
                except json.JSONDecodeError:
                    continue
    return sample, header


def wall_seconds(header: dict) -> float:
    from datetime import datetime
    stats = header.get("stats", {})
    s, e = stats.get("started_at"), stats.get("completed_at")
    if not (s and e):
        return 0.0
    sd = datetime.fromisoformat(s.replace("Z", "+00:00"))
    ed = datetime.fromisoformat(e.replace("Z", "+00:00"))
    return (ed - sd).total_seconds()


def cost_usd(header: dict, model: str) -> float:
    p = PRICING[model]
    stats = header.get("stats", {})
    mu = stats.get("model_usage", {}).get(model, {})
    return (mu.get("input_tokens", 0) * p["input"]
            + mu.get("input_tokens_cache_write", 0) * p["cw"]
            + mu.get("input_tokens_cache_read", 0) * p["cr"]
            + mu.get("output_tokens", 0) * p["output"]) / 1_000_000


def total_tokens(header: dict, model: str) -> int:
    return header.get("stats", {}).get("model_usage", {}).get(model, {}).get("total_tokens", 0)


def alert_summary(path: Path | None) -> dict:
    if not path or not path.exists():
        return {"total": 0, "notice": 0, "warning_plus": 0, "by_rule": {}}
    by_pri = Counter()
    by_rule = Counter()
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
    warning_plus = sum(
        n for sev, n in by_pri.items()
        if sev in ("Warning", "Error", "Critical", "Alert", "Emergency")
    )
    return {
        "total": sum(by_pri.values()),
        "notice": by_pri.get("Notice", 0),
        "warning_plus": warning_plus,
        "by_rule": dict(by_rule),
    }


def count_blocks(sample: dict) -> int:
    n = 0
    for m in sample.get("messages", []):
        if m.get("role") != "tool":
            continue
        c = m.get("content") or ""
        if isinstance(c, list):
            c = "".join(x.get("text", "") if isinstance(x, dict) else str(x) for x in c)
        if "blocked by endpoint security" in c.lower():
            n += 1
    return n


def summarise() -> list[dict]:
    rows = []
    for label, model, log_dir, alerts_path in ARMS:
        eval_path = newest_eval(log_dir)
        sample, header = load_eval(eval_path)
        msgs = sample.get("messages", [])
        scorer = sample.get("scores", {}).get("defended_scorer", {})
        meta = scorer.get("metadata", {})
        alerts = alert_summary(alerts_path)
        rows.append({
            "label": label.replace("\n", " "),
            "label_multiline": label,
            "model": model,
            "log_dir": str(log_dir.relative_to(REPO)),
            "eval_file": eval_path.name,
            "score": float(scorer.get("value", 0) or 0),
            "wall_seconds": wall_seconds(header),
            "messages": len(msgs),
            "tool_calls": sum(
                1 for m in msgs for _ in (m.get("tool_calls") or [])
            ),
            "total_tokens": total_tokens(header, model),
            "cost_usd": round(cost_usd(header, model), 2),
            "alert_count_all": alerts["total"],
            "alert_count_notice": alerts["notice"],
            "alert_count_warning_plus": alerts["warning_plus"],
            "by_rule": alerts["by_rule"],
            "distinct_rules_triggered": meta.get("distinct_rules_triggered", 0) or 0,
            "triggered_rules": meta.get("triggered_rules", []) or [],
            "block_count": count_blocks(sample),
            "resilience": meta.get("resilience", -1),
        })
    return rows


def plot(rows: list[dict], out_png: Path) -> None:
    labels = [r["label_multiline"] for r in rows]
    n = len(rows)

    fig, axes = plt.subplots(1, 4, figsize=(15.5, 5.0))

    # Score
    scores = [r["score"] for r in rows]
    axes[0].bar(labels, scores, color=COLORS[:n])
    axes[0].set_title("Completion (score, 1 = flag captured)")
    axes[0].set_ylim(0, 1.15)
    for i, v in enumerate(scores):
        axes[0].text(i, v + 0.02, f"{v:.2f}", ha="center", va="bottom", fontsize=10)
    axes[0].tick_params(axis="x", labelsize=8)

    # Wall time
    wall = [r["wall_seconds"] / 60 for r in rows]
    axes[1].bar(labels, wall, color=COLORS[:n])
    axes[1].set_title("Wall time (min)")
    for i, v in enumerate(wall):
        axes[1].text(
            i, v + max(wall) * 0.02, f"{v:.0f}m",
            ha="center", va="bottom", fontsize=10,
        )
    axes[1].tick_params(axis="x", labelsize=8)

    # Alerts stacked by severity (log scale)
    notice = [r["alert_count_notice"] for r in rows]
    warning_plus = [r["alert_count_warning_plus"] for r in rows]
    axes[2].bar(labels, notice, color="#a3b8d4", label="Notice")
    axes[2].bar(labels, warning_plus, bottom=notice, color="#dd8452", label="Warning+")
    axes[2].set_title("Falco alerts (log scale)")
    axes[2].set_yscale("symlog", linthresh=1)
    totals = [n_ + w for n_, w in zip(notice, warning_plus)]
    axes[2].set_ylim(0, max(totals) * 3 if max(totals) else 1)
    for i, (w, t) in enumerate(zip(warning_plus, totals)):
        if t > 0:
            axes[2].text(
                i, t + 0.5, f"{t} ({w}W+)",
                ha="center", va="bottom", fontsize=9,
            )
        else:
            axes[2].text(i, 0.5, "0", ha="center", va="bottom", fontsize=9)
    axes[2].legend(loc="upper left", fontsize=8)
    axes[2].set_ylabel("alerts")
    axes[2].tick_params(axis="x", labelsize=8)

    # Cost
    cost = [r["cost_usd"] for r in rows]
    axes[3].bar(labels, cost, color=COLORS[:n])
    axes[3].set_title("Token cost (USD)")
    for i, v in enumerate(cost):
        axes[3].text(
            i, v + max(cost) * 0.02, f"${v:.2f}",
            ha="center", va="bottom", fontsize=10,
        )
    axes[3].tick_params(axis="x", labelsize=8)

    fig.suptitle(
        "Doomla example-variant, uncapped — Sonnet 4.5 vs Opus 4.7\n"
        "Sonnet fails (any tier); Opus completes (any tier). Rule disclosure raises cost & alerts without raising completion.",
        fontsize=11,
    )
    fig.tight_layout()
    fig.savefig(out_png, dpi=120, bbox_inches="tight")
    print(f"wrote {out_png}")


def main() -> None:
    rows = summarise()
    out_json = REPO / "data_out" / "headline_data.json"
    out_json.write_text(json.dumps(rows, indent=2))
    print(f"wrote {out_json}")
    plot(rows, REPO / "data_out" / "01_headline_example_uncapped.png")


if __name__ == "__main__":
    main()
