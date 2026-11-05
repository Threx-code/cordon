"""`CAP.CREDENTIAL.SWEEP` (`detect/code/credential_sweep`): the substring prefilter decides nothing
the patterns would not. Each store's text is in every match of its pattern, so a file holding fewer
than `SWEEP_MIN` of the texts holds fewer than `SWEEP_MIN` matches; and the hits are those of every
pattern searched, on every text generated here."""

from __future__ import annotations

import random
import re
from typing import ClassVar

from hypothesis import given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.code.credential_sweep import CredentialSweep
from cordon_scanner.foundation.content import FileContent


class Reference:
    """The sweep as it was before the prefilter: every pattern searched."""

    @staticmethod
    def hits(text: str) -> tuple[int, int] | None:
        found = [
            (m.start(), name)
            for name, pattern in CredentialSweep.STORES.items()
            if (m := pattern.search(text))
        ]
        if len({name for _, name in found}) < CredentialSweep.SWEEP_MIN:
            return None
        first = min(offset for offset, _ in found)
        return len(text[:first].encode("utf-8")), text.count("\n", 0, first) + 1

    @staticmethod
    def ours(text: str) -> tuple[int, int] | None:
        hits = CredentialSweep.hits(FileContent.from_bytes("x.py", text.encode()))
        return (hits[0].byte_start, hits[0].line) if hits else None

    #: Every store's path, near misses of them, and the separators between.
    PIECES: ClassVar[list[str]] = [
        *("~/" + literal for literal in CredentialSweep.LITERALS.values()),
        "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/identity", "~/.config/gh/hosts.yml",
        "~/.config/gcloud/credentials.db", "~/.azure/accessTokens", "~/.docker/config.json",
        "x.npmrc", "a.netrc", ".npmrcx", ".git-credentialsx", ".ssh/id_rsax", ".aws/credential",
        " ", "\n", "/", "é", "'", '"',
    ]  # fmt: skip


class TestThePrefilter:
    def test_every_store_has_its_text(self) -> None:
        assert CredentialSweep.LITERALS.keys() == CredentialSweep.STORES.keys()

    @settings(max_examples=200, deadline=None)
    @given(data=st.data())
    def test_every_match_holds_its_text(self, data: st.DataObject) -> None:
        for name, pattern in CredentialSweep.STORES.items():
            # a leading lookbehind adds no character to a match: generate from the rest
            source = re.sub(r"^\(\?<!\[[^\]]*\]\)", "", pattern.pattern)
            text = data.draw(st.from_regex(source, fullmatch=False))
            for match in pattern.finditer(text):
                assert CredentialSweep.LITERALS[name] in match.group(0), (name, match.group(0))

    def test_the_hits_are_every_patterns(self) -> None:
        rng = random.Random(20261031)  # noqa: S311 -- a fixture, not key material
        swept = 0
        for _ in range(20_000):
            text = "".join(rng.choice(Reference.PIECES) for _ in range(rng.randint(0, 14)))
            want = Reference.hits(text)
            assert Reference.ours(text) == want, text
            swept += want is not None
        assert swept > 1_000  # the generated texts reach the sweep, not only its refusal

    def test_three_stores_are_a_sweep_at_the_first(self) -> None:
        text = "x = 1\nread('~/.npmrc')\nread('~/.aws/credentials')\nread('~/.kube/config')\n"
        assert Reference.ours(text) == (text.index("~/.npmrc") + 2, 2)
        assert Reference.ours("read('~/.npmrc'); read('~/.aws/credentials')") is None
