"""BP-9-2: the PR comment shows the explanation and the three links; a REVIEW result creates one notification to the owner."""

from __future__ import annotations

import re

import pytest

from cordon_scanner.cloud.agent.pr_comment import PrComment
from cordon_scanner.decide.decision.outcome import Decision, Explanation, PolicyRef, Reason, States

BASE = "https://cordon.example.com/t/acme"


class Kit:
    @staticmethod
    def decision(
        state: str,
        code: str = "R604",
        text: str = "the tool description changed",
        digest: str = "a" * 64,
    ) -> Decision:
        return Decision(
            state=state,
            reason_codes=(code,),
            explanation=Explanation("A reviewer is needed.", (Reason(code, text),)),
            obligations=(),
            inputs_digest="sha256:" + digest,
            policy=PolicyRef("default", 1, "sha256:" + "b" * 64),
        )


class TestTheComment:
    def test_a_review_result_shows_the_explanation_and_the_three_links(self) -> None:
        body = PrComment.render([("npm:left-pad@1.3.0", Kit.decision(States.REVIEW))], BASE)
        assert (
            "## Cordon: REVIEW" in body
            and "the tool description changed" in body
            and "R604" in body
        )
        links = re.findall(r"\]\((https://[^)]+)\)", body)
        assert [link.split("?")[0] for link in links] == [
            f"{BASE}/exceptions/new",
            f"{BASE}/false-positives/new",
            f"{BASE}/allowed-versions",
        ]
        assert all(
            "subject=npm%3Aleft-pad%401.3.0" in link and "decision=sha256%3A" in link
            for link in links
        )

    def test_an_allow_result_offers_no_actions(self) -> None:
        body = PrComment.render([("npm:ok@1.0.0", Kit.decision(States.ALLOW, "R100"))], BASE)
        assert "## Cordon: ALLOW" in body and "https://" not in body

    def test_the_strictest_result_decides_and_is_the_one_the_links_are_about(self) -> None:
        results = [
            ("npm:a@1", Kit.decision(States.ALLOW, "R100")),
            ("npm:b@1", Kit.decision(States.BLOCK, "R201", digest="c" * 64)),
        ]
        body = PrComment.render(results, BASE)
        assert (
            "## Cordon: BLOCK" in body
            and "subject=npm%3Ab%401" in body
            and "subject=npm%3Aa%401" not in body
        )

    def test_package_text_cannot_make_markup_or_a_link(self) -> None:
        hostile = Kit.decision(
            States.REVIEW,
            text="<img src=x onerror=1> [click](https://evil.example/x) | `rm`\n# head",
        )
        body = PrComment.render([("npm:x@1", hostile)], BASE)
        reason = next(line for line in body.splitlines() if "click" in line)
        assert (
            not re.search(r"(?<!\\)[<>\[\]`|]", reason)
            and "](https://evil" not in reason
            and "\\[click\\]" in reason
        )

    @pytest.mark.parametrize(
        "base",
        ["http://cordon.example.com", "https://", "javascript:alert(1)", "https://h.example/?x=1"],
    )
    def test_the_base_must_be_https_with_no_query(self, base: str) -> None:
        with pytest.raises(ValueError):
            PrComment.render([("npm:x@1", Kit.decision(States.REVIEW))], base)


class TestTheNotification:
    def test_a_review_result_raises_one_notification_to_the_owner(self) -> None:
        results = [
            ("npm:a@1", Kit.decision(States.REVIEW)),
            ("npm:b@1", Kit.decision(States.REVIEW, digest="c" * 64)),
        ]
        note = PrComment.notification(results, "owner@acme", "acme/app#12")
        assert (
            note is not None
            and note["to"] == "owner@acme"
            and note["subjects"] == ["npm:a@1", "npm:b@1"]
        )

    def test_the_same_decisions_on_the_same_pull_request_give_the_same_key(self) -> None:
        one = PrComment.notification([("npm:a@1", Kit.decision(States.REVIEW))], "o", "acme/app#12")
        again = PrComment.notification(
            [("npm:a@1", Kit.decision(States.REVIEW))], "o", "acme/app#12"
        )
        other = PrComment.notification(
            [("npm:a@1", Kit.decision(States.REVIEW))], "o", "acme/app#13"
        )
        assert one is not None and again is not None and other is not None
        assert one["key"] == again["key"] != other["key"]

    @pytest.mark.parametrize("state", [States.ALLOW, States.ALLOW_WITH_CONDITIONS, States.BLOCK])
    def test_any_other_result_raises_none(self, state: str) -> None:
        assert (
            PrComment.notification([("npm:a@1", Kit.decision(state))], "o", "acme/app#12") is None
        )
