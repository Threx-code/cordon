"""Every parser, fed input chosen to break it.

The scan target is untrusted, and a parser is where untrusted input first meets
code. There are three ways one can fail and only the first is acceptable:

**Report the input as unparseable.** Correct, and already tested per parser.

**Raise something the caller does not expect.** The engine catches broadly
around detectors, so the visible effect is a dropped finding and a scan marked
incomplete -- a file quietly not examined because of how it was written, which
is a blinding primitive that costs an attacker nothing.

**Not return.** A parser that loops or backtracks forever turns a scan into a
hang, and a hung pre-commit hook gets `--no-verify`.

So the properties asserted here are deliberately weak and deliberately
universal: for arbitrary bytes, every parser terminates, and raises nothing
outside the set its callers handle. What each parser *means* is tested
elsewhere; this is about what it does when the input was written by someone who
read the source.

Marked `fuzz` and run in CI. Hypothesis's example database is not shared
between runs there, so the value is breadth over time rather than a fixed
corpus -- which is the right trade for input shapes nobody enumerated.
"""

from __future__ import annotations

import contextlib
from typing import ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.core.config import Config, ConfigError, RestrictedYamlParser
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.errors import CordonError, RulePackError
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.rules.loader import RuleLoader

pytestmark = pytest.mark.fuzz

SETTINGS = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# Bytes weighted toward what actually reaches these parsers: structural
# punctuation, encoding boundaries, and the characters that terminate things.
_STRUCTURAL = "{}[]:,\"'\\\n\r\t #-|>&*!%@`$()/.=+ ab1"
_HAZARDS = "".join(map(chr, (0x00, 0x1B, 0x7F, 0xFEFF, 0x202E, 0x2066, 0x200B)))
"""NUL, escape, delete, a byte-order mark, a right-to-left override, an
isolate, a zero-width space.

Assembled rather than written, because Cordon scans its own repository and a
literal override here is a true positive for its own bidi rule -- the same
convention the redaction tests use for credential shapes."""

INTERESTING = st.one_of(
    st.binary(max_size=400),
    st.text(alphabet=st.sampled_from(_STRUCTURAL + _HAZARDS), max_size=400).map(
        lambda s: s.encode("utf-8", "surrogatepass")
    ),
)

TOLERATED = (CordonError, ConfigError, RulePackError, ValueError, UnicodeDecodeError)
"""What a caller is prepared for. Anything else is the defect being hunted."""


class TestRestrictedYaml:
    """The configuration parser, which reads a file the scan target may own."""

    @SETTINGS
    @given(raw=INTERESTING)
    def test_it_terminates_and_raises_only_what_callers_handle(self, raw: bytes) -> None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        with contextlib.suppress(TOLERATED):
            RestrictedYamlParser._load_yaml_subset(text, source="fuzz")

    @SETTINGS
    @given(raw=INTERESTING)
    def test_config_parsing_never_raises_unexpectedly(self, raw: bytes) -> None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        try:
            data = RestrictedYamlParser._load_yaml_subset(text, source="fuzz")
        except TOLERATED:
            return
        if not isinstance(data, dict):
            return
        with contextlib.suppress(TOLERATED):
            Config.from_dict(data, source="fuzz")


class TestEcosystemParsers:
    """Manifests and lockfiles, which are the scan target's own files."""

    NAMES: ClassVar[list[str]] = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "poetry.lock",
        "Pipfile.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "composer.json",
        "composer.lock",
        "Gemfile",
        "Gemfile.lock",
        "pom.xml",
        "build.gradle",
        "pubspec.yaml",
        "Podfile.lock",
    ]

    @SETTINGS
    @given(raw=INTERESTING, name=st.sampled_from(NAMES))
    def test_a_manifest_parser_never_raises_unexpectedly(self, raw: bytes, name: str) -> None:
        content = FileContent.from_bytes(name, raw)
        eco_id = EcosystemRegistry.manifest_ecosystem(name)
        if eco_id is None:
            return
        ecosystem = EcosystemRegistry.get(eco_id)
        assert ecosystem is not None
        try:
            manifest = ecosystem.parse_manifest(content)
        except TOLERATED:
            return
        # A parse that "succeeded" must still produce coordinates that are safe
        # to publish: bounded, single-line, and free of adjacent line content.
        for declared in manifest.dependencies:
            assert "\n" not in declared.name and " " not in declared.name
            assert len(declared.name) <= 128

    @SETTINGS
    @given(raw=INTERESTING, name=st.sampled_from(NAMES))
    def test_a_lockfile_parser_never_raises_unexpectedly(self, raw: bytes, name: str) -> None:
        content = FileContent.from_bytes(name, raw)
        eco_id = EcosystemRegistry.lockfile_ecosystem(name)
        if eco_id is None:
            return
        ecosystem = EcosystemRegistry.get(eco_id)
        assert ecosystem is not None
        try:
            graph = ecosystem.parse_lockfile(content)
        except TOLERATED:
            return
        for entry in graph.entries:
            assert "\n" not in entry.version and " " not in entry.version
            assert len(entry.version) <= 64


class TestRulePacks:
    """A rule pack may be supplied with `--rules`, which is a file the operator
    was handed and did not necessarily write."""

    @SETTINGS
    @given(raw=INTERESTING)
    def test_loading_never_raises_unexpectedly(self, raw: bytes, tmp_path_factory) -> None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        path = tmp_path_factory.mktemp("pack") / "p.yaml"
        path.write_text(text, encoding="utf-8")
        with contextlib.suppress(TOLERATED):
            RuleLoader().load_file(path)


class TestContentClassification:
    """Runs before any detector, on every file, and decides whether a file is
    examined as source at all."""

    @SETTINGS
    @given(raw=INTERESTING, name=st.text(max_size=40))
    def test_classification_terminates_for_any_bytes(self, raw: bytes, name: str) -> None:
        content = FileContent.from_bytes(name or "x", raw)
        assert isinstance(content.is_binary, bool)
        assert isinstance(content.truncated, bool)
        _ = content.sha256

    @SETTINGS
    @given(raw=INTERESTING)
    def test_line_offsets_stay_inside_the_content(self, raw: bytes) -> None:
        """A finding's reported line must exist. An offset table that runs past
        the end sends a reviewer to a line that is not there."""
        content = FileContent.from_bytes("f.txt", raw)
        for offset in (0, len(content.raw) // 2, max(0, len(content.raw) - 1)):
            line = content.line_of(offset)
            assert 1 <= line <= content.line_count + 1, (line, content.line_count)
            assert content.column_of(offset) >= 1
            # The line a finding names must be one a reader can open to.
            assert isinstance(content.line_text(line), str)
