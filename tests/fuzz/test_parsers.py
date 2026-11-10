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
import io
import os
import tarfile
import time
import zipfile
from typing import ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.config.settings import Config, ConfigError
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.errors import CordonError, RulePackError
from cordon_scanner.foundation.formats.restricted_yaml import RestrictedYamlParser
from cordon_scanner.rules.loader import RuleLoader
from cordon_scanner.sources.archive import ArchiveReader

pytestmark = pytest.mark.fuzz

#: CI runs 300 examples a test; a hardening campaign raises it (S1, reviews/release-080).
EXAMPLES = int(os.environ.get("CORDON_FUZZ_EXAMPLES", "300"))

SETTINGS = settings(
    max_examples=EXAMPLES,
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


class TestFormatReaders:
    """Pickles, OLE/VBA, OOXML, PDF, RTF and image trailers: bytes from the scan target, parsed
    by structure. Seeded with valid files and mutated, because random bytes rarely get past a
    magic number and the interesting failures are one field deep."""

    @staticmethod
    def _seeds() -> list[tuple[str, bytes]]:
        import pickle

        from kits.formatkit import FormatKit

        return [
            ("model.pkl", pickle.dumps({"weights": [1.0, 2.0]}, protocol=4)),
            ("model.pkl", b"\x80\x02cos\nsystem\nq\x00X\x04\x00\x00\x00trueq\x01\x85q\x02Rq\x03."),
            ("legacy.doc", FormatKit.vba_project("Sub AutoOpen()\r\nEnd Sub\r\n")),
            (
                "book.xlsm",
                FormatKit.ooxml(
                    {"xl/vbaProject.bin": FormatKit.vba_project("Sub X()\r\nEnd Sub\r\n")}
                ),
            ),
            (
                "r.docx",
                FormatKit.ooxml(
                    {
                        "word/_rels/settings.xml.rels": FormatKit.relationship(
                            "attachedTemplate", "https://a.invalid/t"
                        )
                    }
                ),
            ),
            (
                "a.pdf",
                b"%PDF-1.4\n1 0 obj<</OpenAction<</S/JavaScript/JS(x)>>/Filter/FlateDecode>>stream\nx\x9c\x03\x00\x00\x00\x00\x01\nendstream\n",
            ),
            ("a.rtf", rb"{\rtf1{\object\objupdate{\*\objdata 0105000045717561}}}"),
            ("a.png", FormatKit.png(b"PK\x03\x04" + b"\x00" * 40)),
            ("a.jpg", FormatKit.jpeg(thumbnail=True)),
            ("a.gif", FormatKit.gif()),
        ]

    @SETTINGS
    @given(
        seed=st.integers(min_value=0, max_value=9),
        cut=st.integers(min_value=0, max_value=4096),
        flips=st.lists(
            st.tuples(st.integers(min_value=0, max_value=4095), st.integers(0, 255)), max_size=12
        ),
    )
    def test_a_mutated_file_raises_only_format_error(self, seed: int, cut: int, flips) -> None:
        from cordon_scanner.analysis.formats import FormatError, documents, media, pickles

        name, raw = self._seeds()[seed]
        mutated = bytearray(raw)
        for offset, value in flips:
            if mutated:
                mutated[offset % len(mutated)] = value
        data = bytes(mutated[: max(cut, 8)] if cut < len(mutated) else mutated)
        with contextlib.suppress(FormatError):
            if name.endswith(".pkl"):
                pickles.PickleReader.read(data, truncated=True)
            elif name.endswith((".png", ".jpg", ".gif")):
                media.ImageTrailers.trailer(data)
            elif documents.DocumentReader.kind_of(data, name) is not None:
                documents.DocumentReader.read(data, name)


class TestArchives:
    """Every downloaded package meets the archive readers first, and none were fuzzed (S1). The
    seeds are small valid archives of each format the reader opens (and 7z and rar headers), and
    each example damages one: flipped bytes, a cut, an insertion. The walk must end, within its
    deadline and well after it, and raise nothing outside what its callers handle."""

    SUFFIXES: ClassVar[tuple[str, ...]] = (".zip", ".tar", ".tar.gz", ".gz", ".a", ".7z", ".rar")
    #: Built once, with fixed timestamps: a seed whose bytes changed between examples (a zip's or a
    #: gzip header's clock) made Hypothesis's draws inconsistent.
    _SEEDS: ClassVar[dict[str, bytes]] = {}

    @staticmethod
    def seeds() -> dict[str, bytes]:
        if not TestArchives._SEEDS:
            TestArchives._SEEDS.update(TestArchives._built())
        return TestArchives._SEEDS

    @staticmethod
    def _built() -> dict[str, bytes]:
        member = b"import os\nprint(os.getcwd())\n" * 4
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in (("pkg/a.py", member), ("pkg/inner.zip", b"PK\x03\x04")):
                archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data)
        tarred: dict[str, bytes] = {}
        for mode, suffix in (("w", ".tar"), ("w:gz", ".tar.gz")):
            buffer = io.BytesIO()
            with (
                tarfile.open(fileobj=buffer, mode=mode, compresslevel=9)
                if mode != "w"
                else tarfile.open(fileobj=buffer, mode=mode) as archive
            ):
                info = tarfile.TarInfo("pkg/a.py")
                info.mtime = 0
                info.size = len(member)
                archive.addfile(info, io.BytesIO(member))
            tarred[suffix] = buffer.getvalue()
        import gzip

        header = b"!<arch>\n" + b"a.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) * 2
        ar = header + b"644".ljust(8) + str(len(member)).encode().ljust(10) + b"`\n" + member
        return {
            ".zip": zipped.getvalue(),
            **tarred,
            ".gz": gzip.compress(member, mtime=0),
            ".a": ar,
            ".7z": b"7z\xbc\xaf\x27\x1c\x00\x04" + member,
            ".rar": b"Rar!\x1a\x07\x01\x00" + member,
        }

    @staticmethod
    def damaged(data: bytes, draw) -> bytes:
        body = bytearray(data)
        for _ in range(draw(st.integers(0, 6))):
            if body:
                body[draw(st.integers(0, len(body) - 1))] = draw(st.integers(0, 255))
        if body and draw(st.booleans()):
            del body[draw(st.integers(0, len(body))) :]
        if draw(st.booleans()):
            at = draw(st.integers(0, len(body)))
            body[at:at] = draw(st.binary(max_size=64))
        return bytes(body)

    @SETTINGS
    @given(data=st.data())
    def test_a_damaged_archive_ends_and_raises_only_what_callers_handle(self, data) -> None:
        suffix = data.draw(st.sampled_from(TestArchives.SUFFIXES))
        raw = TestArchives.damaged(TestArchives.seeds()[suffix], data.draw)
        started = time.monotonic()
        with contextlib.suppress(TOLERATED):
            for _name, _member in ArchiveReader.walk_archive(
                raw, path=f"pkg{suffix}", deadline=started + 10
            ):
                pass
        assert time.monotonic() - started < 30, f"{suffix}: the walk ran past its deadline"
