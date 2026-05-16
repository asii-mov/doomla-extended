"""Upstream Doomla task — for framework-comparison runs.

Mirrors the original ``task.py`` exactly, except:

- The dataset filter is ``variant_name == "example"`` (upstream defaulted to
  ``"solution"``). Switched so this runs the SAME agentic workload as our
  framework's default; ``solution.sh`` is broken on this host because the
  Compose bridge gives a /16 network and the script's first nmap can't scan
  65k hosts within any reasonable timeout — that's orthogonal to either
  framework.
- The module-bottom ``eval(doomla)`` is removed because Inspect's CLI invokes
  the ``@task`` function directly.
"""

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.agent import react
from inspect_ai.scorer import includes
from inspect_ai.tool import bash
from inspect_cyber import create_agentic_eval_dataset


@task
def doomla():
    """Upstream Doomla baseline (no defensive tier framework)."""
    return Task(
        dataset=(
            create_agentic_eval_dataset(
                root_dir=Path("evals/doomla").resolve()
            ).filter_by_metadata({"variant_name": "example"})
        ),
        solver=react(tools=[bash()]),
        scorer=includes(),
    )
