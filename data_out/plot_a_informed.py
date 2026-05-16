"""Per-rule alert volume: Opus active uninformed vs Opus active + rules disclosed.

The §A.3 "informed red-teamer upper bound" experiment. Hypothesis was that
disclosing the full ruleset would drive alerts toward zero. Result is the
opposite: rule disclosure shifted the warning-level alerts from one rule
(`Read sensitive file untrusted`) to a closely-related sister rule
(`Read sensitive file trusted after startup`) and slightly increased the
total warning+ count.

Reads:
  - logs_opus_rerun/active/active_alerts_uncapped.jsonl
  - logs_opus_rerun/active_informed/active_informed_alerts.jsonl

Writes:
  - data_out/02_active_vs_informed_per_rule.png
"""

import json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[1]
UNINFORMED_ALERTS = (
    REPO / "logs_opus_rerun" / "active" / "active_alerts_uncapped.jsonl"
)
INFORMED_ALERTS = (
    REPO / "logs_opus_rerun" / "active_informed" / "active_informed_alerts.jsonl"
)


def rules_by_severity(path: Path) -> dict[str, Counter]:
    out: dict[str, Counter] = {}
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


SEV_COLOR = {"Critical": "#c44e52", "Warning": "#dd8452", "Notice": "#a3b8d4"}
SEVERITIES = ["Critical", "Warning", "Notice"]


def plot(out_png: Path) -> None:
    uninf = rules_by_severity(UNINFORMED_ALERTS)
    inform = rules_by_severity(INFORMED_ALERTS)

    rules = sorted(
        {r for sev in uninf.values() for r in sev}
        | {r for sev in inform.values() for r in sev}
    )

    fig, axes = plt.subplots(1, 2, figsize=(13, 6), sharey=True)
    for ax, (title, data) in zip(
        axes,
        [
            ("Uninformed (Opus active, uncapped)", uninf),
            ("Informed (Opus active + full rules disclosed, uncapped)", inform),
        ],
    ):
        bottoms = np.zeros(len(rules))
        for sev in SEVERITIES:
            vals = np.array(
                [data.get(sev, Counter()).get(r, 0) for r in rules], dtype=float
            )
            ax.bar(rules, vals, bottom=bottoms, color=SEV_COLOR[sev], label=sev)
            bottoms += vals
        ax.set_title(title, fontsize=11)
        ax.tick_params(axis="x", labelrotation=20, labelsize=8)
        for label in ax.get_xticklabels():
            label.set_ha("right")
        for i, total in enumerate(bottoms):
            if total > 0:
                ax.text(
                    i, total, f"{int(total)}",
                    ha="center", va="bottom", fontsize=9,
                )
        ax.set_ylabel("alerts")
        ax.grid(axis="y", linestyle=":", alpha=0.4)
    axes[1].legend(loc="upper right", fontsize=9)
    fig.suptitle(
        "Falco alerts by rule — Opus active, with and without rule disclosure (same model, same workload)\n"
        "Note the warning-level shift: 'Read sensitive file untrusted' (42 → 2) collapses, but 'Read sensitive file trusted after startup' (0 → 54) replaces it.",
        fontsize=10,
    )
    fig.tight_layout()
    fig.savefig(out_png, dpi=120, bbox_inches="tight")
    print(f"wrote {out_png}")


if __name__ == "__main__":
    plot(REPO / "data_out" / "02_active_vs_informed_per_rule.png")
