"""`LiteralSearch.matches`: a provider pattern tried only where its leading literal starts gives
exactly what `finditer` gives, span for span, for every provider pattern, on data built to hit the
edges: the literal after a word byte (the `\\b` fails), literals back to back and overlapping, a
match running into the next literal, the literal at the start and at the end of the data."""

from __future__ import annotations

import random

from cordon_scanner.detect.secrets.detector import PROVIDER_PATTERNS
from cordon_scanner.detect.secrets.literal_search import LiteralSearch

ALPHABET = b"0123456789abcdefABCDEF_-.: \n\"'xyzXYZ"


class Kit:
    @staticmethod
    def data(rng: random.Random, literals: list[bytes]) -> bytes:
        parts: list[bytes] = []
        for _ in range(rng.randint(1, 40)):
            choice = rng.random()
            if choice < 0.45 and literals:
                lead = rng.choice(literals)
                before = rng.choice([b"", b" ", b"x", b"_", b"-", b".", b'"', lead[:1]])
                body = bytes(
                    rng.choice(ALPHABET) for _ in range(rng.choice([8, 14, 31, 32, 33, 64, 70]))
                )
                parts.append(before + lead + body)
            elif choice < 0.6 and literals:
                lead = rng.choice(literals)
                parts.append(lead * rng.randint(2, 4))
            else:
                parts.append(bytes(rng.choice(ALPHABET) for _ in range(rng.randint(0, 50))))
        return b"".join(parts)

    @staticmethod
    def spans(found: object) -> list[tuple[int, int]]:
        return [m.span() for m in found]  # type: ignore[attr-defined]


class TestTheSameMatches:
    def test_every_provider_pattern_finds_what_finditer_finds(self) -> None:
        rng = random.Random(20261031)  # noqa: S311 -- a fixture, not key material
        literals = sorted({lit for spec in PROVIDER_PATTERNS for lit in spec.prefilter})
        for _ in range(4_000):
            raw = Kit.data(rng, literals)
            for spec in PROVIDER_PATTERNS:
                assert Kit.spans(
                    LiteralSearch.matches(spec.pattern, spec.prefilter, raw)
                ) == Kit.spans(spec.pattern.finditer(raw)), (
                    spec.rule_id,
                    raw,
                )

    def test_a_real_token_shape_is_found_at_the_start_and_end(self) -> None:
        twilio = next(s for s in PROVIDER_PATTERNS if s.rule_id == "SECRET.TWILIO.KEY.001")
        token = b"SK" + b"0123456789abcdef" * 2
        for raw in (token, b"x " + token, token + b" y", b"xSK" + token[2:], token + token):
            assert Kit.spans(
                LiteralSearch.matches(twilio.pattern, twilio.prefilter, raw)
            ) == Kit.spans(twilio.pattern.finditer(raw))

    def test_the_anchored_search_applies_only_where_it_is_exact(self) -> None:
        """A pattern that is not `\\b` then one plain literal is searched as written."""
        leading = LiteralSearch.leading
        assert leading(rb"\bSK[0-9a-f]{32}\b", 0, (b"SK",)) == b"SK"
        assert leading(rb"\bSK?[0-9a-f]{32}\b", 0, (b"SK",)) is None  # K optional
        assert leading(rb"(?:a|SK)[0-9]{4}", 0, (b"SK",)) is None  # does not start there
        assert leading(rb"\bSK[0-9]{4}", 2, (b"SK",)) is None  # case-insensitive
        assert leading(rb"\b(?:ghp|gho)_[0-9]{4}", 0, (b"ghp_", b"gho_")) is None  # two literals
        anchored = [
            s.rule_id
            for s in PROVIDER_PATTERNS
            if LiteralSearch.leading(s.pattern.pattern, s.pattern.flags, s.prefilter)
        ]
        assert {
            "SECRET.TWILIO.KEY.001",
            "SECRET.MAILGUN.KEY.001",
            "SECRET.OPENAI.KEY.001",
            "SECRET.AIRTABLE.TOKEN.001",
        } <= set(anchored)
