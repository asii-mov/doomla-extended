from collections.abc import Callable, Iterable
from copy import deepcopy
from pathlib import Path

from inspect_ai import Task, eval, task
from inspect_ai.agent import human_cli, react
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes
from inspect_ai.tool import bash
from inspect_cyber import create_agentic_eval_dataset, play_message_history
from inspect_cyber.scorers import captured_flags


def split_message_history_by_milestone() -> Callable[[Sample], Iterable[Sample]]:
    def _split_message_history_by_milestone(sample: Sample) -> Iterable[Sample]:
        milestones = sample.metadata.get("milestones")
        if not milestones:
            return [sample]

        # include sample that starts from very beginning?

        samples = []
        for milestone in milestones:
            variant = deepcopy(sample)
            variant.id += f" (milestone '{milestone}')"
            variant.metadata.update({"msg_to_start_agent_at": milestone})

            samples.append(variant)

        return samples

    return _split_message_history_by_milestone


@task
def doomla():
    return Task(
        dataset=(
            create_agentic_eval_dataset(root_dir=Path("evals/doomla").resolve())
            .filter_by_metadata({"variant_name": "conditional_success"})
            .flat_map(split_message_history_by_milestone())
        ),
        solver=[
            play_message_history(tools=[bash()]),
            react(tools=[bash()]),
            # human_cli(),
        ],
        scorer=captured_flags(),
    )


eval(doomla, message_limit=40)
