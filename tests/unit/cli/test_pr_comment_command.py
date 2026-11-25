"""BP-9-2: `pr-comment` turns `decide --lock` output into the pull-request comment and the one REVIEW notification; the action posts it."""

from __future__ import annotations

import io
import json
import re
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.decision.pr_comment import PrCommentCommand
from cordon_scanner.decide.decision.outcome import Decision, Explanation, PolicyRef, Reason, States
from cordon_scanner.foundation.errors import ConfigError
from support import ROOT

BASE = "https://cordon.example.com/t/acme"


class Gate:
    @staticmethod
    def document(*states: str) -> dict[str, Any]:
        decisions = []
        for i, state in enumerate(states):
            decision = Decision(
                state=state,
                reason_codes=("R604",),
                explanation=Explanation(
                    "A reviewer is needed.", (Reason("R604", "the tool description changed"),)
                ),
                obligations=(),
                inputs_digest="sha256:" + f"{i:x}" * 64,
                policy=PolicyRef("default", 1, "sha256:" + "b" * 64),
            )
            decisions.append({"subject": f"npm:p{i}@1.0.0", "decision": decision.to_json()})
        return {"state": states[0], "passes": states[0] != "BLOCK", "decisions": decisions}

    @staticmethod
    def run(
        document: dict[str, Any],
        tmp_path: Path,
        owner: str | None = "acme/reviewers",
        base: str = BASE,
    ) -> tuple[str, Path]:
        out, note = io.StringIO(), tmp_path / "note.json"
        args = Namespace(base=base, owner=owner, pr="acme/app#12", notification_out=str(note))
        assert PrCommentCommand.run(args, io.StringIO(json.dumps(document)), out) == 0
        return out.getvalue(), note


class TestTheCommand:
    def test_a_review_result_gives_the_comment_with_the_three_links_and_names_the_owner(
        self, tmp_path: Path
    ) -> None:
        body, _ = Gate.run(Gate.document(States.REVIEW), tmp_path)
        assert "## Cordon: REVIEW" in body and "the tool description changed" in body
        assert len(re.findall(r"\]\(https://cordon\.example\.com/t/acme/", body)) == 3
        assert body.rstrip().endswith("Needs review from @acme/reviewers.")

    def test_a_review_result_writes_the_one_notification(self, tmp_path: Path) -> None:
        _, note = Gate.run(Gate.document(States.REVIEW, States.REVIEW), tmp_path)
        record = json.loads(note.read_text(encoding="utf-8"))
        assert (
            record["to"] == "acme/reviewers"
            and record["pull_request"] == "acme/app#12"
            and record["subjects"] == ["npm:p0@1.0.0", "npm:p1@1.0.0"]
        )

    @pytest.mark.parametrize("state", [States.ALLOW, States.BLOCK])
    def test_any_other_result_writes_no_notification_and_names_no_owner(
        self, tmp_path: Path, state: str
    ) -> None:
        body, note = Gate.run(Gate.document(state), tmp_path)
        assert not note.exists() and "Needs review" not in body

    def test_an_owner_that_could_carry_markup_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            Gate.run(Gate.document(States.REVIEW), tmp_path, owner="x) [evil](https://evil.example")

    @pytest.mark.parametrize("base", ["http://cordon.example.com", "javascript:alert(1)"])
    def test_a_base_that_is_not_https_is_refused(self, tmp_path: Path, base: str) -> None:
        with pytest.raises(ConfigError):
            Gate.run(Gate.document(States.REVIEW), tmp_path, base=base)

    def test_input_that_is_not_gate_output_is_refused(self) -> None:
        args = Namespace(base=BASE, owner=None, pr="a/b#1", notification_out=None)
        with pytest.raises(ConfigError):
            PrCommentCommand.run(args, io.StringIO('{"state": "ALLOW"}'), io.StringIO())

    def test_it_is_a_command_of_the_cli(self) -> None:
        from cordon_scanner.cli.parser import CommandParser

        assert "pr-comment" in CommandParser.build().subcommands()


class TestTheActionPostsIt:
    text = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
    step = text.split("Comment the decisions on the pull request", 1)[1].split("\n    - name:", 1)[
        0
    ]

    def test_the_step_runs_on_a_pull_request_in_decide_mode_even_after_a_failed_gate(self) -> None:
        assert (
            "always() && inputs.mode == 'decide' && inputs.decide-comment == 'true' && github.event_name == 'pull_request'"
            in self.step
        )

    def test_it_posts_the_comment_updating_the_last_one_and_keeps_the_notification_record(
        self,
    ) -> None:
        assert "gh pr comment" in self.step and "--edit-last" in self.step
        assert "--notification-out cordon-notification.json" in self.step

    def test_chosen_text_reaches_the_shell_only_through_the_environment(self) -> None:
        script = self.step.split("run: |", 1)[1]
        assert "${{" not in script
