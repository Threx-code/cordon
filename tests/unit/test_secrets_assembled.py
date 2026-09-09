"""Credentials split across a concatenation.

Every provider pattern needs a contiguous run of bytes. `"ghp_" + "..."` is not
one, and the value is identical to the interpreter -- which makes a `+` the
cheapest way to commit a live credential past a secret scanner, cheaper than
encoding it, because the code still reads as ordinary.

The negative cases carry as much weight as the positive ones. Concatenation is
overwhelmingly used to build paths, messages and queries, so a rule that treats
assembly itself as suspicious would report on most files in most repositories
and be turned off within a day.

Every value here is fabricated, and every one is passed through `assemble` so
that this file does not become the leak it tests for.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.secrets import SecretDetector, fold_concatenations
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from support import assemble

AWS = assemble("AKIA", "Q7XKLMNPQRSTUVWX")
GITHUB = assemble("ghp_", "kR9mT2nQ8vL4xW7yZ3bC6dF1gH5jK0pS9rT2")
NPM = assemble("npm_", "tpYlSXpfKtHF4vUCsMehGAkWvj7FAc9QeWJK")


def split(value: str, at: int, operator: str = "+") -> str:
    """The source form of a value hidden across a concatenation.

    Built here rather than written into a fixture. A split credential spelled
    out in this file would be a true positive the moment the detector below
    starts working, which is the point of the whole module.
    """
    return f'"{value[:at]}" {operator} "{value[at:]}"'


CONTEXT = ScanContext(config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()))


def findings_for(source: str, *, path: str = "settings.py", language: str = "python") -> list[str]:
    unit = FileUnit(
        content=FileContent.from_bytes(path, source.encode("utf-8")),
        language=language,
    )
    return [f.rule_id for f in SecretDetector().inspect(unit, CONTEXT)]


class TestFolding:
    """The byte-level fallback, used for every language the AST tier cannot
    parse and for Python that will not parse."""

    def test_two_literals_joined_by_plus(self) -> None:
        folded = list(fold_concatenations(f"T = {split(GITHUB, 4)}".encode()))
        assert [value for _, _, value in folded] == [GITHUB.encode()]

    def test_a_dot_joins_them_too(self) -> None:
        """PHP and Perl concatenate with `.`, and a split credential in either
        looks exactly like one in JavaScript."""
        source = f"$t = {split(GITHUB, 4, '.')};".encode()
        assert [value for _, _, value in fold_concatenations(source)] == [GITHUB.encode()]

    def test_literals_on_consecutive_lines_are_not_one_value(self) -> None:
        """The requirement that an operator be present, not merely permitted.
        Without it, a list of regex patterns in a rule pack, a table of URLs in
        `pyproject.toml` and a fenced code block in a document all fold into
        credentials -- all three of which this flagged before the fix."""
        assert list(fold_concatenations(b'- "aaaaaaaaaaaaaaaa"\n- "bbbbbbbbbbbbbbbb"\n')) == []

    def test_list_elements_are_not_one_value(self) -> None:
        assert list(fold_concatenations(b'x = ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]')) == []

    def test_a_single_literal_is_not_returned(self) -> None:
        """Contiguous bytes the ordinary patterns have already matched.
        Returning it here would double every finding."""
        assert list(fold_concatenations(b'T = "aaaaaaaaaaaaaaaaaaaa"')) == []

    def test_a_three_part_split(self) -> None:
        """A run of any length folds, not just a pair."""
        folded = list(fold_concatenations(b'T = "aaaa" + "bbbb" + "cccc"'))
        assert [value for _, _, value in folded] == [b"aaaabbbbcccc"]


class TestProviderShapes:
    """A folded value is matched by the provider patterns exactly as a literal
    one is, so these need no rules of their own."""

    @pytest.mark.parametrize(
        ("value", "rule"),
        [
            (AWS, "SECRET.AWS.ACCESS_KEY.001"),
            (GITHUB, "SECRET.GITHUB.TOKEN.001"),
            (NPM, "SECRET.NPM.TOKEN.001"),
        ],
        ids=lambda v: v[:6] if isinstance(v, str) else v,
    )
    def test_a_split_provider_token_reports_its_own_rule(self, value: str, rule: str) -> None:
        assert rule in findings_for(f"T = {split(value, 6)}\n")

    def test_the_split_and_whole_forms_are_one_secret(self) -> None:
        """The hash is over the value rather than its spelling, so a credential
        written both ways in one file is reported once."""
        source = f'A = "{GITHUB}"\nB = {split(GITHUB, 4)}\n'
        assert findings_for(source).count("SECRET.GITHUB.TOKEN.001") == 1

    def test_javascript_goes_through_the_byte_fallback(self) -> None:
        source = f"const t = {split(NPM, 4)};\n"
        assert "SECRET.NPM.TOKEN.001" in findings_for(
            source, path="deploy.js", language="javascript"
        )

    def test_python_that_will_not_parse_falls_back(self) -> None:
        """A file that does not parse must not become a file that is not
        examined. The AST tier returns nothing for it and the byte fold runs."""
        source = f"this is not python =\nT = {split(GITHUB, 4)}\n"
        assert "SECRET.GITHUB.TOKEN.001" in findings_for(source)


class TestTheEntropyHeuristic:
    def test_a_high_entropy_assembled_value_is_reported(self) -> None:
        value = assemble("kR9mT2nQ8vL4xW7yZ3bC", "6dF1gH5jK0pS9rT2")
        assert "SECRET.GENERIC.ASSIGNMENT.001" in findings_for(f"KEY = {split(value, 20)}\n")

    def test_a_low_entropy_assembled_value_is_not(self) -> None:
        """The audit's own negative case."""
        assert findings_for('SLUG = "pre" + "fix" + "-" + "release"\n') == []

    def test_a_sentence_is_not_a_credential(self) -> None:
        """Shannon entropy rewards a varied alphabet, so prose and SQL clear any
        floor prose is supposed to sit below -- `"SELECT id, name" + " FROM
        packages"` scores 4.48. What separates them is that a generated secret
        is one token."""
        for source in (
            'Q = "SELECT id, name" + " FROM packages" + " WHERE ecosystem = ?"\n',
            'M = "could not read " + "the manifest, so its hooks were unread"\n',
        ):
            assert findings_for(source) == [], source

    def test_a_short_assembled_value_is_not_tested_on_entropy(self) -> None:
        """Entropy over a short sample is bounded by log2 of its length, so the
        number would mean nothing."""
        assert findings_for('X = "aB3d" + "E5fG"\n') == []

    def test_a_path_built_from_pieces_is_not_a_credential(self) -> None:
        assert findings_for('P = "/var/cache/" + "cordon-scanner/rules"\n') == []


class TestPrefixes:
    def test_a_padded_token_is_caught_despite_its_entropy(self) -> None:
        """A prefix with a padded body sits below any sensible entropy floor
        while still being live, which is the gap entropy alone leaves. Here the
        provider pattern answers first, which is the better outcome: it names
        the provider rather than reporting an unidentified value."""
        value = assemble("ghp_", "A" * 36)
        assert "SECRET.GITHUB.TOKEN.001" in findings_for(f"T = {split(value, 10)}\n")

    def test_a_prefixed_value_no_provider_pattern_matches(self) -> None:
        """The prefix branch on its own. GitLab tokens have no provider pattern
        here, and a padded body puts this far below the entropy floor -- so the
        prefix is the only thing identifying it, which is what the prefix list
        is for."""
        value = assemble("glpat-", "A" * 20)
        assert "SECRET.GENERIC.ASSIGNMENT.001" in findings_for(f"T = {split(value, 10)}\n")

    def test_a_private_key_header_split_apart(self) -> None:
        source = 'M = "-----BEGIN " + "PRIVATE KEY" + "-----"\n'
        assert findings_for(source)


class TestPlaceholders:
    def test_an_assembled_placeholder_is_still_a_placeholder(self) -> None:
        """`AKIAIOSFODNN7EXAMPLE` is AWS's own documentation key. Splitting it
        does not make it a credential."""
        assert findings_for('K = "AKIA" + "IOSFODNN7EXAMPLE"\n') == []

    def test_an_interpolated_value_is_a_template(self) -> None:
        assert findings_for('T = "ghp_" + "{token}"\n') == []


class TestEvidence:
    def test_the_value_is_never_emitted(self) -> None:
        """The rule the whole detector is built on. A folded credential is
        still a credential, and the finding must not carry it."""
        source = f"T = {split(GITHUB, 4)}\n"
        unit = FileUnit(
            content=FileContent.from_bytes("s.py", source.encode("utf-8")),
            language="python",
        )
        for finding in SecretDetector().inspect(unit, CONTEXT):
            assert GITHUB not in (finding.evidence.snippet or "")
            assert finding.evidence.match_hash
