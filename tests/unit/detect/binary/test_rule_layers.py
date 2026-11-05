"""Rules over decoded layers (`detect/binary/rule_layers`): a rule that asks (`layers = "decoded"`)
also reads what a file carries under a wrapper, each match naming its layer; every other rule, the
built-in pack's included, reads the raw bytes only, so nothing proven against YARA changes. The
payload here is a marker string, nothing harmful."""

from __future__ import annotations

import base64
import gzip
import json
import runpy
import sys
import zlib
from pathlib import Path

import pytest

from cordon_scanner.detect.binary.rule_files import BUILTIN, RuleFileEngine
from cordon_scanner.detect.binary.rule_layers import RuleLayers
from support import requires_forked_workers

MARK = b"CORDON-LAYER-PROBE-PAYLOAD-0001"
_STRING = f'strings: $m = "{MARK.decode()}" condition: $m }}'
RULES = (
    f'rule layered {{ meta: layers = "decoded" category = "malicious" {_STRING}\n'
    f'rule raw_only {{ meta: category = "malicious" {_STRING}\n'
)


class Kit:
    @staticmethod
    def b64(data: bytes) -> bytes:
        return base64.b64encode(data)

    @staticmethod
    def scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, body: bytes) -> dict:
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / name).write_bytes(body)
        rules = tmp_path / "r.yar"
        rules.write_text(RULES, encoding="utf-8")
        out = tmp_path / "out.json"
        argv = ["cordon-scanner", "scan", str(tmp_path / "pkg"), "--offline", "--no-color", "--quiet",
                "--rule-file", str(rules), "-f", f"json:{out}"]  # fmt: skip
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit):
            runpy.run_module("cordon_scanner", run_name="__main__")
        report: dict = json.loads(out.read_text(encoding="utf-8"))
        return report

    @staticmethod
    def rule_messages(report: dict) -> list[str]:
        return [
            f["message"] for f in report["findings"] if f["rule_id"].startswith("MALWARE.RULEFILE")
        ]


class TestLayers:
    @pytest.mark.parametrize(
        ("text", "how"),
        [
            (b'const p = atob("' + base64.b64encode(MARK) + b'");', "atob"),
            (b"x = Buffer.from('" + base64.b64encode(MARK) + b"', 'base64')", "Buffer.from base64"),
            (b"x = Buffer.from('" + MARK.hex().encode() + b"', 'hex')", "Buffer.from hex"),
            (b'payload = base64.b64decode(b"' + base64.b64encode(MARK) + b'")', "b64decode"),
            (b'payload = bytes.fromhex("' + MARK.hex().encode() + b'")', "bytes.fromhex"),
            (b'payload = binascii.unhexlify("' + MARK.hex().encode() + b'")', "unhexlify"),
        ],
    )
    def test_each_wrapper_is_taken_off(self, text: bytes, how: str) -> None:
        layers = RuleLayers.of(text)
        assert [(layer.how, layer.data, layer.depth) for layer in layers] == [(how, MARK, 2)]

    def test_layers_are_peeled_in_turn_and_named(self) -> None:
        inner = (
            b"payload = zlib.decompress(base64.b64decode('"
            + base64.b64encode(zlib.compress(MARK * 4))
            + b"'))"
        )
        outer = b'const p = atob("' + base64.b64encode(inner) + b'");'
        layers = RuleLayers.of(outer)
        assert [(layer.how, layer.depth) for layer in layers] == [
            ("atob", 2),
            ("b64decode", 3),
            ("zlib inflate", 4),
        ]
        assert layers[-1].data == MARK * 4

    def test_a_compression_bomb_costs_only_the_cap(self) -> None:
        bomb = gzip.compress(bytes(64 << 20))
        layers = RuleLayers.of(b"x = b64decode('" + base64.b64encode(bomb) + b"')")
        assert [layer.how for layer in layers] == ["b64decode", "gzip inflate"]
        assert len(layers[-1].data) == RuleLayers.MAX_BYTES

    def test_short_or_broken_literals_are_left(self) -> None:
        assert RuleLayers.of(b'atob("aGk=")') == []
        assert RuleLayers.of(b'atob("!!!!!!!!!!!!!!!!!!!!")') == []
        assert RuleLayers.of(b'bytes.fromhex("abc")') == []
        # and a literal of the same forms, long and well formed, is peeled (not every one refused)
        long_text = base64.b64encode(b"x" * 64)
        assert [layer.how for layer in RuleLayers.of(b'atob("' + long_text + b'")')] == ["atob"]

    def test_the_built_in_pack_reads_raw_bytes_only(self) -> None:
        """No built-in rule asks for layers, so the pack's results stay the ones proven against
        yara-python, file for file."""
        assert RuleFileEngine(BUILTIN, use_cache=False).layered == frozenset()


class TestThroughTheScan:
    def test_only_the_rule_that_asks_reads_the_layer_and_the_match_names_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = b'const run = atob("' + base64.b64encode(MARK) + b'");\n'
        messages = Kit.rule_messages(Kit.scan(tmp_path, monkeypatch, "index.js", body))
        assert messages == [
            "The rule layered matched this file's layer decoded from atob (layer 2)."
        ]

    def test_a_raw_match_is_not_reported_again_for_a_layer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = MARK + b"\n" + b'atob("' + base64.b64encode(MARK) + b'")\n'
        messages = sorted(Kit.rule_messages(Kit.scan(tmp_path, monkeypatch, "index.js", body)))
        assert messages == [
            "The rule layered matched this file.",
            "The rule raw_only matched this file.",
        ]


class TestALayerFailsClosed:
    @requires_forked_workers
    def test_a_layer_past_the_bound_fails_the_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The raw file is base64 text with no zero byte in it; its decoded layer is 256 KB of
        zeros, past a lowered bound. The layer's refusal fails the scan as the raw file's would."""
        from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places

        monkeypatch.setattr(Places, "MOST", 100_000)
        rules = tmp_path / "z.yar"
        rules.write_text(
            'rule z { meta: layers = "decoded" category = "malicious" '
            "strings: $z = { 00 00 00 00 } condition: #z > 5 }",
            encoding="utf-8",
        )
        (tmp_path / "pkg").mkdir()
        # 256 KB of zeros: 262,144 places against the lowered bound of 100,000, so the layer is
        # refused by the bound, well inside the per-file time budget even on a loaded host.
        body = b'x = atob("' + base64.b64encode(bytes(1 << 18)) + b'");\n'
        (tmp_path / "pkg" / "index.js").write_bytes(body)
        out = tmp_path / "out.json"
        argv = ["cordon-scanner", "scan", str(tmp_path / "pkg"), "--offline", "--no-color", "--quiet",
                "--rule-file", str(rules), "-f", f"json:{out}"]  # fmt: skip
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as code:
            runpy.run_module("cordon_scanner", run_name="__main__")
        report = json.loads(out.read_text(encoding="utf-8"))
        ids = {f["rule_id"]: f["severity"] for f in report["findings"]}
        assert ids.get("SUSPECT.RULEFILE.UNMATCHED.001") == "high"
        assert code.value.code not in (0, None)
