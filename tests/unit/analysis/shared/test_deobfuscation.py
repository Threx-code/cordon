"""Obfuscation reversed statically, and graded by what the recovered code does (review 98).

The fixtures are built here, from harmless strings, in the shape javascript-obfuscator writes: a
string array, a rotation loop whose `parseInt` checksum names the right arrangement, and a decoder
reached through an alias. Nothing is run, in the test or in the code under test.
"""

from __future__ import annotations

import base64
import io
import json
import tarfile
from pathlib import Path
from typing import ClassVar

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.deobfuscation import (
    OBFUSCATOR_IO_ALPHABET,
    STANDARD_ALPHABET,
    Checksum,
    Deobfuscator,
    Layers,
    ObfuscatorIo,
)
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity


class ObfuscatedKit:
    STRINGS: ClassVar[list[str]] = [
        "log",
        "hello\x20world",
        "1203abc",
        "27xyz",
        "9q",
        "length",
        "4lm",
        "exports",
    ]
    # The obfuscator's names are hexadecimal (`_0x5e1f`); readable stand-ins are swapped in below.
    OFFSET = 0x1A2
    SHIFT = 3

    @staticmethod
    def encode(value: str) -> str:
        """obfuscator.io's base64: standard base64 written in its own alphabet."""
        table = str.maketrans(STANDARD_ALPHABET[:64], OBFUSCATOR_IO_ALPHABET[:64])
        return base64.b64encode(value.encode()).decode().rstrip("=").translate(table)

    @classmethod
    def program(cls, mode: str = "plain", body: str = "") -> str:
        values = [cls.encode(s) if mode == "base64" else s for s in cls.STRINGS]
        # The array as shipped is the decoded order rotated back by SHIFT; the loop undoes it.
        shipped = values[-cls.SHIFT :] + values[: -cls.SHIFT]
        index = {s: cls.OFFSET + i for i, s in enumerate(cls.STRINGS)}
        terms = [("1203abc", 1), ("27xyz", 2), ("9q", 3), ("4lm", 4)]
        expression = "+".join(f"parseInt(_0xd(0x{index[s]:x}))/0x{d:x}" for s, d in terms)
        target = Checksum(expression).value(lambda fn, args: cls.STRINGS[int(args[0]) - cls.OFFSET])
        decode = f"var _0xa='{OBFUSCATOR_IO_ALPHABET}';" if mode == "base64" else ""
        quoted = ",".join(f"'{v}'" for v in shipped)
        return (
            (
                f"function _0xarr(){{const _0xl=[{quoted}];_0xarr=function(){{return _0xl;}};return _0xarr();}}"
                f"function _0xdec(_0xi,_0xk){{const _0xs=_0xarr();return _0xdec=function(_0xn,_0xm)"
                f"{{_0xn=_0xn-0x{cls.OFFSET:x};{decode}let _0xv=_0xs[_0xn];return _0xv;}},_0xdec(_0xi,_0xk);}}"
                f"(function(_0xf,_0xt){{const _0xd=_0xdec,_0xa=_0xf();while(!![]){{try{{const _0xc={expression};"
                f"if(_0xc===_0xt)break;else _0xa['push'](_0xa['shift']());}}catch(_0xe){{_0xa['push']"
                f"(_0xa['shift']());}}}}}}(_0xarr,{target:g}));"
                f"const _0xq=_0xdec;console[_0xq(0x{index['log']:x})](_0xq(0x{index['hello world']:x}));"
                f"{body}"
            )
            .replace("_0xarr", "_0x5e1f")
            .replace("_0xdec", "_0x2c4d")
            .replace("_0xl=", "_0x3a1b=")
            .replace("_0xl;", "_0x3a1b;")
            .replace("_0xs", "_0x6b2e")
            .replace("_0xv", "_0x7c3f")
            .replace("_0xq", "_0x4d5a")
            .replace("_0xc=", "_0x1e9b=")
            .replace("_0xc===", "_0x1e9b===")
        )

    @classmethod
    def package(cls, tmp_path: Path, program: str) -> Path:
        files = {
            # Run on install, so the obfuscation finding starts at the gate.
            "package/package.json": json.dumps(
                {
                    "name": "obf-demo",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node index.js"},
                }
            ),
            "package/index.js": program,
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "obf-demo-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target


class TestTheStringArray:
    def test_a_plain_array_is_rotated_by_its_checksum_and_substituted(self):
        recovery = ObfuscatorIo.recover(ObfuscatedKit.program())
        assert recovery is not None
        assert "console.log('hello world')" in recovery.text
        # The decoder calls itself with its own parameters; that call has no literal to resolve.
        assert recovery.remaining <= 2

    def test_a_base64_array_is_decoded(self):
        recovery = ObfuscatorIo.recover(ObfuscatedKit.program("base64"))
        assert recovery is not None
        assert "console.log('hello world')" in recovery.text

    def test_a_file_with_no_array_is_left_alone(self):
        assert ObfuscatorIo.recover("const a = 1; while(!![]){ break; }") is None


class TestLayers:
    def test_an_invisible_run_is_read_as_the_bytes_it_spells(self):
        hidden = "".join(
            chr(0xE0100 + b - 16) if b >= 16 else chr(0xFE00 + b) for b in b"console.log(1)//pad"
        )
        text, layers = Layers.peel(f"const s='{hidden}'; run(s);")
        assert layers == 1
        assert "console.log(1)" in text

    def test_constant_decodes_are_peeled_and_unreadable_ones_are_not(self):
        encoded = base64.b64encode(b"console.log('second layer')").decode()
        assert Layers.decoded(f"eval(atob('{encoded}'))") == [
            ("atob", "console.log('second layer')")
        ]
        assert Layers.decoded("atob('AAECAwQFBgcICQoLDA0ODw==')") == []


class TestGrading:
    def test_the_obfuscation_keeps_its_grade_whatever_the_recovered_code_does(self, tmp_path):
        # Compromised releases whose payload sits elsewhere recover to inert code; the hiding is
        # still the finding (review 98: @draftlab/auth 0.24.2).
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(ObfuscatedKit.package(tmp_path, ObfuscatedKit.program()))
        packed = [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.PACKED.001"]
        assert packed
        assert any(f.severity >= Severity.HIGH for f in packed)

    def test_what_the_recovered_code_does_is_reported_on_it(self, tmp_path):
        body = "require('child_process').execSync(process.env.HOME_CMD);"
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(
            ObfuscatedKit.package(tmp_path, ObfuscatedKit.program(body=body))
        )
        assert any("#deobfuscated.js" in (f.location.path or "") for f in result.findings) or any(
            f.location.path and f.location.path.endswith("index.js") for f in result.findings
        )

    def test_recovered_text_with_another_hidden_layer_keeps_the_grade(self, tmp_path):
        encoded = base64.b64encode(b"console.log('next')").decode()
        program = ObfuscatedKit.program(body=f"eval(Buffer.from('{encoded}','base64').toString());")
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(ObfuscatedKit.package(tmp_path, program))
        assert not PolicyGate.evaluate(result, config.policy).passed

    def test_the_recovery_entry_point_handles_only_javascript(self):
        assert Deobfuscator.recover(ObfuscatedKit.program(), "python") is None


class TestIntegerLiterals:
    """Source integers as Go and sloppy-mode JavaScript read them."""

    def test_forms(self) -> None:
        from cordon_scanner.analysis.shared.deobfuscation import IntegerLiteral

        assert IntegerLiteral.value("05") == 5
        assert IntegerLiteral.value("0101") == 65
        assert IntegerLiteral.value("089") == 89
        assert IntegerLiteral.value("0x41") == 65
        assert IntegerLiteral.value("0o17") == 15
        assert IntegerLiteral.value("1_000") == 1000
        assert IntegerLiteral.value("0") == 0
