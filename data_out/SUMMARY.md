# `data_out/` — data dictionary

Generated artefacts for the active analysis in [`../FINDINGS.md`](../FINDINGS.md).
Everything from older methodology iterations (synthetic-attack plots,
solution-variant comparison, pre-fix Opus data) lives under
[`../_archive/data_out/`](../_archive/data_out/) — see that directory's
README for descriptions.

## Plots

| File | Description |
|---|---|
| `01_headline_example_uncapped.png` | Headline 5-arm cross-model chart: Sonnet 4.5 × {silent, active} + Opus 4.7 × {silent, active, active+rules disclosed}, all on the `example` variant, uncapped. Panels: completion, wall time, alerts (stacked Notice / Warning+ on log scale), token cost. |
| `02_active_vs_informed_per_rule.png` | Per-rule alert volume for Opus active uncapped vs Opus active with the full Falco YAML disclosed (the § A experiment). Shows the warning-rule shift from `Read sensitive file untrusted` (42 → 2) to `Read sensitive file trusted after startup` (0 → 54). |

## Data

| File | Description |
|---|---|
| `headline_data.json` | Per-arm metrics behind the headline plot. Five rows, one per arm. Fields: `score`, `wall_seconds`, `messages`, `tool_calls`, `total_tokens`, `cost_usd`, `alert_count_all`, `alert_count_notice`, `alert_count_warning_plus`, `by_rule`, `distinct_rules_triggered`, `triggered_rules`, `block_count`, `resilience`. |

## Scripts

| File | What it does |
|---|---|
| `plot_headline.py` | Reads the five active eval directories + their preserved Falco alert files, computes per-arm metrics, writes `headline_data.json`, generates `01_headline_example_uncapped.png`. Source of truth for the headline numbers in FINDINGS. |
| `plot_a_informed.py` | Reads the uninformed + informed Opus active alert logs and produces the side-by-side per-rule plot for § A. |

## Reproducing

The plot scripts run under `uv` because matplotlib isn't in the project's
poetry deps:

```bash
uv run --no-project --with matplotlib --with numpy python data_out/plot_headline.py
uv run --no-project --with matplotlib --with numpy python data_out/plot_a_informed.py
```

To regenerate the underlying eval data, see the invocations in
[`../FINDINGS.md`](../FINDINGS.md) — each run is one `inspect eval`
invocation with the appropriate `-T tier=...`, `-T variant=example`, and
optionally `-T disclose_rules=true`.
