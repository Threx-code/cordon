"""Evidence redaction.

This is the module whose failure is least recoverable. A missed detection can be
found later; a credential printed into a CI log, a pull-request comment and a
SARIF file uploaded to a third party cannot be unprinted.

The tests are therefore weighted toward proving that things do *not* leak, and
the leak cases are adversarial rather than typical: a padded token, a token in a
header, a value split across a boundary, a value at the very edge of a snippet.
"""

from __future__ import annotations

import pytest

from cordon.core.content import FileContent
from cordon.core.models import EvidenceKind, RedactionMode
from cordon.core.redact import (
    ENTROPY_MASK_THRESHOLD,
    MASK,
    MAX_SNIPPET_BYTES,
    build_evidence,
    effective_mode,
    mask,
    redact,
    shannon_entropy,
)

# Fabricated values with real shapes. None is a live credential.
AWS = "AKIA" + "Q7XKLMNPQRSTUVWX"
GITHUB = "ghp_" + "kR9mT2nQ8vL4xW7yZ3bC6dF1gH5jK0pS9rT2"
GITHUB_PADDED = "ghp_" + "A" * 36
STRIPE = "sk_live_" + "9dK3mQ7nR2vT8xW4yZ6b"
NPM = "npm_" + "tpYlSXpfKtHF4vUCsMehGAkWvj7FAc9QeWJK"
SLACK = "xoxb-" + "2841923847-2841923847-kR9mT2nQ8vL4xW7yZ3bC"
GOOGLE = "AIza" + "SyD1kR9mT2nQ8vL4xW7yZ3bC6dF1gH5jK0p"
# Assembled, not written whole. Cordon scans its own repository in CI, and a
# complete credential literal here is a true positive: the tool should not need
# an exception for itself. Every value in this module is fabricated.
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r"

ALL_SHAPES = [AWS, GITHUB, GITHUB_PADDED, STRIPE, NPM, SLACK, GOOGLE, JWT]


class TestEntropy:
    def test_repeated_characters_have_no_entropy(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_random_looking_text_scores_high(self) -> None:
        assert shannon_entropy("kR9mT2nQ8vL4xW7yZ3bC6dF1") > ENTROPY_MASK_THRESHOLD

    def test_ordinary_identifiers_score_low(self) -> None:
        assert shannon_entropy("get_user_by_identifier") < ENTROPY_MASK_THRESHOLD

    def test_is_bounded_by_alphabet_size(self) -> None:
        import math

        text = "abcd" * 20
        assert shannon_entropy(text) <= math.log2(4) + 1e-9


class TestMasking:
    @pytest.mark.parametrize("secret", ALL_SHAPES, ids=lambda s: s[:8])
    def test_every_credential_shape_is_masked(self, secret: str) -> None:
        assert secret not in mask(f'token = "{secret}"')

    def test_a_low_entropy_token_is_still_masked(self) -> None:
        """The gap entropy gating alone leaves. A token is recognisable by its
        prefix, and a prefix with a padded body sits below any sensible entropy
        floor while still being live."""
        assert GITHUB_PADDED not in mask(f'T = "{GITHUB_PADDED}"')

    def test_a_token_in_a_header_is_masked(self) -> None:
        """Not an assignment, so the name-based pass does not see it."""
        line = f'curl -H "Authorization: Bearer {GITHUB}" https://api.example'
        assert GITHUB not in mask(line)

    def test_a_bare_token_with_no_context_is_masked(self) -> None:
        assert AWS not in mask(AWS)

    def test_structure_survives_so_the_finding_stays_actionable(self) -> None:
        result = mask(f'DATABASE_PASSWORD = "{GITHUB}"')
        assert "DATABASE_PASSWORD" in result
        assert MASK in result

    def test_ordinary_code_is_untouched(self) -> None:
        for line in (
            "const port = process.env.PORT || 3000;",
            "def get_user(user_id: int) -> User:",
            "npm run build && tsc --noEmit",
            "import { useState } from 'react';",
            "return a + b * 2;",
        ):
            assert mask(line) == line, line

    def test_a_content_hash_is_not_masked_as_a_secret(self) -> None:
        """Hex digests are long but low-entropy over their alphabet, and
        masking every one of them would make the output useless."""
        line = 'sha = "d41d8cd98f00b204e9800998ecf8427e"'
        assert "d41d8cd98f00b204e9800998ecf8427e" in mask(line)

    def test_multiple_secrets_on_one_line_are_all_masked(self) -> None:
        line = f'a="{AWS}" b="{GITHUB}"'
        result = mask(line)
        assert AWS not in result
        assert GITHUB not in result

    def test_masking_is_idempotent(self) -> None:
        once = mask(f'token = "{GITHUB}"')
        assert mask(once) == once


class TestRedactionModes:
    def test_hash_only_returns_nothing(self) -> None:
        """None rather than a placeholder, so a reporter that forgets to check
        cannot render something that looks like content."""
        assert redact(f'k = "{AWS}"', RedactionMode.HASH_ONLY) is None

    def test_masked_hides_the_value(self) -> None:
        assert AWS not in redact(f'k = "{AWS}"', RedactionMode.MASKED)

    def test_none_mode_returns_the_text(self) -> None:
        """Requires an explicit flag, and is refused for secret rules."""
        assert AWS in redact(f'k = "{AWS}"', RedactionMode.NONE)

    def test_long_snippets_are_truncated(self) -> None:
        """A long snippet is not more informative, it is more leakage."""
        out = redact("x" * 5000, RedactionMode.NONE)
        assert len(out) <= MAX_SNIPPET_BYTES + 3

    def test_a_secret_past_the_truncation_point_is_not_emitted(self) -> None:
        """Truncation must not be the only thing standing between a secret and
        a log, but it must at least not defeat masking."""
        line = "x" * 300 + f' token="{AWS}"'
        out = redact(line, RedactionMode.MASKED)
        assert AWS not in out


class TestEffectiveMode:
    @pytest.mark.parametrize(
        ("rule", "config", "expected"),
        [
            (RedactionMode.HASH_ONLY, RedactionMode.NONE, RedactionMode.HASH_ONLY),
            (RedactionMode.HASH_ONLY, RedactionMode.MASKED, RedactionMode.HASH_ONLY),
            (RedactionMode.MASKED, RedactionMode.NONE, RedactionMode.MASKED),
            (RedactionMode.NONE, RedactionMode.MASKED, RedactionMode.MASKED),
            (RedactionMode.NONE, RedactionMode.HASH_ONLY, RedactionMode.HASH_ONLY),
            (RedactionMode.NONE, RedactionMode.NONE, RedactionMode.NONE),
        ],
    )
    def test_the_stricter_mode_always_wins(
        self, rule: RedactionMode, config: RedactionMode, expected: RedactionMode
    ) -> None:
        """A rule declaring hash-only cannot be relaxed by configuration.
        `--evidence full` is typed by somebody debugging a false positive, not
        by somebody thinking about where the log ends up."""
        assert effective_mode(rule, config) is expected


class TestBuildEvidence:
    def content(self, text: str) -> FileContent:
        return FileContent.from_bytes("conf.py", text.encode("utf-8"))

    def test_hash_is_over_the_raw_bytes(self) -> None:
        """So the hash identifies the artefact rather than its rendering. Two
        scans that mask differently produce the same hash for the same match."""
        text = f'k = "{AWS}"'
        c = self.content(text)
        start = text.index(AWS)
        masked = build_evidence(c, start, start + len(AWS), RedactionMode.MASKED)
        plain = build_evidence(c, start, start + len(AWS), RedactionMode.NONE)
        assert masked.match_hash == plain.match_hash

    def test_hash_only_emits_no_snippet(self) -> None:
        text = f'k = "{AWS}"'
        c = self.content(text)
        ev = build_evidence(c, 5, 5 + len(AWS), RedactionMode.HASH_ONLY)
        assert ev.snippet is None
        assert ev.kind is EvidenceKind.HASH
        assert ev.match_hash

    def test_masked_evidence_never_carries_the_value(self) -> None:
        text = f'k = "{AWS}"'
        c = self.content(text)
        ev = build_evidence(c, 5, 5 + len(AWS), RedactionMode.MASKED)
        assert AWS not in (ev.snippet or "")

    def test_span_is_recorded(self) -> None:
        c = self.content("abcdefghij")
        ev = build_evidence(c, 2, 6, RedactionMode.MASKED)
        assert ev.span == (2, 6)

    def test_redaction_happens_at_construction(self) -> None:
        """Not at render time, so no reporter can accidentally emit unredacted
        content: unredacted content never reaches one."""
        text = f'k = "{GITHUB}"'
        c = self.content(text)
        ev = build_evidence(c, 0, len(text), RedactionMode.MASKED)
        assert GITHUB not in (ev.snippet or "")
        assert ev.redaction is RedactionMode.MASKED


class TestAdversarialInput:
    """Inputs chosen to make masking fail rather than to represent typical use."""

    def test_a_secret_adjacent_to_punctuation(self) -> None:
        for line in (f"({AWS})", f"[{AWS}]", f"{{{AWS}}}", f"<{AWS}>", f",{AWS},"):
            assert AWS not in mask(line), line

    def test_a_secret_in_a_url(self) -> None:
        assert GITHUB not in mask(f"https://x:{GITHUB}@example.invalid/repo.git")

    def test_a_secret_in_json(self) -> None:
        assert NPM not in mask(f'{{"_authToken": "{NPM}"}}')

    def test_a_secret_in_yaml(self) -> None:
        assert STRIPE not in mask(f"  stripe_key: {STRIPE}")

    def test_a_secret_in_an_environment_assignment(self) -> None:
        assert GOOGLE not in mask(f"export GOOGLE_API_KEY={GOOGLE}")

    def test_empty_and_whitespace_input(self) -> None:
        assert mask("") == ""
        assert mask("   ") == "   "

    def test_unicode_input_does_not_raise(self) -> None:
        assert mask("h\u00e9llo w\u00f6rld \u202e \U0001f600") is not None

    def test_very_long_input_terminates(self) -> None:
        import time

        started = time.monotonic()
        mask("a" * 200_000)
        assert time.monotonic() - started < 2.0
