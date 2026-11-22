"""A candidate that loses its catch under a transform is rejected."""

from __future__ import annotations

import re

from bench.cdi.mutations import AdversarialGate, Mutations

SAMPLE = '''# send the key home
def collect():
    path = "/home/user/.ssh/id_rsa"
    return open(path).read()
'''
TEXTS = [SAMPLE, SAMPLE.replace("collect", "gather"), SAMPLE.replace("id_rsa", "id_ed25519")]


class Rules:
    @staticmethod
    def literal(text: str) -> bool:
        return bool(re.search(r"\.ssh/id_", text))

    @staticmethod
    def named(text: str) -> bool:
        return "collect" in text or "gather" in text


class TestTheTransforms:
    def test_rename_changes_what_the_text_declares_and_nothing_else(self) -> None:
        out = Mutations.rename(SAMPLE)
        assert "collect" not in out and "def v0x" in out and "open(" in out

    def test_reencode_spells_the_string_with_escapes(self) -> None:
        out = Mutations.reencode(SAMPLE)
        assert ".ssh" not in out and "\\x2f" in out

    def test_split_cuts_the_string_and_joins_it(self) -> None:
        out = Mutations.split('x = "abcdef"')
        assert out == 'x = "abc" + "def"'

    def test_minify_drops_comments_and_blank_runs(self) -> None:
        out = Mutations.minify(SAMPLE)
        assert "send the key" not in out and "\n\n" not in out


class TestACandidateThatLosesItsCatchIsRejected:
    def test_a_literal_match_is_beaten_by_re_encoding_and_splitting(self) -> None:
        verdict = AdversarialGate.check(Rules.literal, TEXTS)
        assert verdict["accepted"] is False and "reencode" in verdict["beaten_by"] and "split" in verdict["beaten_by"]
        assert verdict["caught"] == 3 and verdict["retained"]["reencode"] == 0.0

    def test_a_match_on_a_name_is_beaten_by_renaming(self) -> None:
        verdict = AdversarialGate.check(Rules.named, TEXTS)
        assert verdict["accepted"] is False and verdict["beaten_by"] == ["rename"]

    def test_the_reason_names_the_transform_and_the_share(self) -> None:
        verdict = AdversarialGate.check(Rules.named, TEXTS)
        assert verdict["reasons"] == ["under rename it keeps 0% of its catch, below 80%"]

    def test_a_candidate_that_keeps_its_catch_under_every_transform_is_accepted(self) -> None:
        def robust(text: str) -> bool:
            return "open(" in text

        verdict = AdversarialGate.check(robust, TEXTS)
        assert verdict["accepted"] is True and verdict["beaten_by"] == []

    def test_a_candidate_that_caught_nothing_is_rejected(self) -> None:
        verdict = AdversarialGate.check(lambda _t: False, TEXTS)
        assert verdict["accepted"] is False and verdict["reasons"] == ["it caught none of the texts, so nothing was shown"]

    def test_a_loss_inside_the_allowed_share_is_accepted(self) -> None:
        texts = [f"open({i})" for i in range(9)] + ["open(x) # note"]
        verdict = AdversarialGate.check(lambda t: "# note" in t or "open(" in t and "#" not in t, texts, minimum=0.8)
        assert verdict["accepted"] is True

    def test_nothing_is_written_to_the_texts(self) -> None:
        before = list(TEXTS)
        AdversarialGate.check(Rules.literal, TEXTS)
        assert TEXTS == before
