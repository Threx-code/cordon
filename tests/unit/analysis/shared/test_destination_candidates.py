"""`Destinations.candidates`: the matches `destination_matcher().finditer` gives, found from where
a host occurs instead of trying the alternation at every byte -- the same starts, ends and order on
every text generated here, mixed case, boundaries and overlapping hosts included."""

from __future__ import annotations

import random
from typing import ClassVar

from cordon_scanner.analysis.shared.destinations import ALL_HOSTS, Destinations


class Texts:
    NEAR: ClassVar[list[bytes]] = [
        b"",
        b".",
        b"-",
        b"_",
        b"a",
        b"Z",
        b"9",
        b"/",
        b" ",
        b"'",
        b"\n",
        b"x.",
        b"\xc3\xa9",
        b"\x00",
    ]

    @staticmethod
    def make(rng: random.Random) -> bytes:
        hosts = sorted(ALL_HOSTS)
        out = []
        for _ in range(rng.randint(0, 8)):
            host = rng.choice(hosts)
            if rng.random() < 0.3:
                host = "".join(c.upper() if rng.random() < 0.5 else c for c in host)
            if rng.random() < 0.2:
                host = host[: rng.randint(1, len(host))]  # a cut host: a near miss
            piece = (
                rng.choice(Texts.NEAR)
                + host.encode()
                + rng.choice([*Texts.NEAR, b"/x", b"op", b"9"])
            )
            out.append(piece)
            if rng.random() < 0.3:
                out.append(bytes(rng.randrange(256) for _ in range(rng.randint(0, 12))))
        return b"".join(out)


class TestTheCandidates:
    @staticmethod
    def spans(found: object) -> list[tuple[int, int, bytes]]:
        return [(m.start(), m.end(), m.group(0)) for m in found]  # type: ignore[attr-defined]

    def test_the_matches_finditer_gives(self) -> None:
        rng = random.Random(20261031)  # noqa: S311 -- a fixture, not key material
        matcher = Destinations.destination_matcher()
        matched = 0
        for _ in range(30_000):
            raw = Texts.make(rng)
            want = self.spans(matcher.finditer(raw))
            assert self.spans(Destinations.candidates(raw)) == want, raw
            matched += bool(want)
        assert matched > 10_000  # the texts reach matches, not only refusals

    def test_edges(self) -> None:
        matcher = Destinations.destination_matcher()
        for raw in (
            b"", b"transfer.sh", b"transfer.shop", b"xtransfer.sh", b".transfer.sh", b"-transfer.sh",
            b"TRANSFER.SH/x", b"media.discord.com/api/webhooks/1", b"outlook.office.com/webhookb2",
            b"hooks.slack.com/services/T", b"hooks.slack.com", b"pastebin.compastebin.com",
            b"pastebin.com pastebin.com", b"ngrok.io.ngrok.io",
        ):  # fmt: skip
            assert self.spans(Destinations.candidates(raw)) == self.spans(matcher.finditer(raw)), (
                raw
            )
