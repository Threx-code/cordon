"""A Python file read in windows (`engine/window_pass.py`): the structural detectors do not parse a
piece of it that cannot parse -- its prefix and plain windows, cut inside a statement at
`max_file_bytes` -- since a failed parse costs most of a whole one, about 233 MB per MB, once per
reader, and the statement-aligned pass reads the same bytes as whole statements from byte 0. A piece
that may parse is parsed as before, and every other detector reads as before."""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import email.message
import json.decoder
import tokenize
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.statements import PythonStatements
from cordon_scanner.engine.window_pass import WindowPass
from cordon_scanner.foundation.config.settings import Config
from support import requires_forked_workers

DECODE = "b64" + "decode"
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
)
LIMIT = 16 * 1024


class WindowedKit:
    @staticmethod
    def source(functions: int) -> str:
        body = "".join(
            f"def f{n}(a, b):\n    x = a.b.c({n}, 'text {n}', [1, 2, b])\n    return x\n\n"
            for n in range(functions)
        )
        return "from setuptools import setup\n" + body + PLANT + "setup(name='x')\n"

    @staticmethod
    def scan(tmp_path, text: str, name: str = "setup.py"):
        (tmp_path / name).write_text(text, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False)
        limits = dataclasses.replace(
            config.limits, max_file_bytes=LIMIT, per_file_timeout=0, total_timeout=0
        )
        return Scanner(config.with_overrides(limits=limits)).scan(tmp_path)

    @staticmethod
    def findings(result) -> list[tuple[str, int | None]]:
        return sorted((f.rule_id, f.location.line) for f in result.findings)

    @staticmethod
    def parsed_sizes(tmp_path, monkeypatch: pytest.MonkeyPatch, text: str) -> list[int]:
        """The length of every text a scan actually parses (not withheld), the file named so no
        ecosystem reads it as a manifest. Parsing happens in the detection worker (item 28), so
        each parse is recorded where this process can read it afterwards: a file outside the
        scanned tree, one line per parse."""
        record = tmp_path / "parsed.txt"
        parse = PythonSyntax.parse

        def counted(source, *a, **k):
            # (no store at all on a tree without withholding: every parse counts)
            if getattr(PythonSyntax, "_WITHHELD", {}).get(id(source)) is not source:
                with record.open("a", encoding="utf-8") as out:
                    out.write(f"{len(source)}\n")
            return parse(source, *a, **k)

        monkeypatch.setattr(PythonSyntax, "parse", staticmethod(counted))
        scanned = tmp_path / "scanned"
        scanned.mkdir()
        WindowedKit.scan(scanned, text, name="module.py")
        return (
            [int(n) for n in record.read_text(encoding="utf-8").split()] if record.exists() else []
        )


class TestTheWithholding:
    def test_a_withheld_text_is_not_parsed_and_the_store_is_emptied(self) -> None:
        text = "x = 1\n"
        with PythonSyntax.withholding(text), pytest.raises(SyntaxError):
            PythonSyntax.parse(text)
        assert PythonSyntax.parse(text) is not None
        assert not PythonSyntax._WITHHELD

    @requires_forked_workers
    def test_a_piece_cut_inside_a_statement_is_not_parsed(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        text = WindowedKit.source(1200)
        assert len(text) > 4 * LIMIT
        sizes = WindowedKit.parsed_sizes(tmp_path, monkeypatch, text)
        assert sizes  # the aligned windows were parsed: the file is read as Python
        assert LIMIT not in sizes  # the prefix and plain windows, cut at the limit, were not

    @requires_forked_workers
    def test_a_prefix_that_ends_on_a_whole_line_is_parsed(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cut where a line ends, a prefix may parse: it is parsed, as today, never withheld."""
        lines = [f"x_{n:09d} = 1".ljust(31) + "\n" for n in range(4 * LIMIT // 32 + 1)]
        text = "".join(lines)  # 32-byte lines, so the limit falls where a line ends
        assert text[LIMIT - 1] == "\n" and PythonStatements.may_parse(text[:LIMIT])
        assert LIMIT in WindowedKit.parsed_sizes(tmp_path, monkeypatch, text)

    def test_only_the_structural_detectors_are_withheld(self) -> None:
        content = SimpleNamespace(truncated=True, window_source=object(), text="def f(:\n")
        unit = SimpleNamespace(content=content, language="python")
        assert isinstance(WindowPass.withheld("obfuscation", unit), contextlib.nullcontext)
        assert not isinstance(WindowPass.withheld("capability", unit), contextlib.nullcontext)

    def test_a_payload_past_the_prefix_is_found(self, tmp_path) -> None:
        found = WindowedKit.findings(WindowedKit.scan(tmp_path, WindowedKit.source(1200)))
        assert {"SUSPECT.DECODE_EXEC.001", "MALWARE.INSTALL.DECODED_LAUNCH.001"} & {
            rule for rule, _ in found
        }

    def test_the_findings_are_those_without_it(self, tmp_path, monkeypatch) -> None:
        text = WindowedKit.source(1200)
        withheld = WindowedKit.findings(WindowedKit.scan(tmp_path, text))
        monkeypatch.setattr(
            PythonSyntax, "withholding", staticmethod(lambda text: contextlib.nullcontext())
        )
        assert WindowedKit.findings(WindowedKit.scan(tmp_path, text)) == withheld


class TestAStrayByte:
    def test_a_module_read_in_windows_with_a_byte_that_is_not_utf8_is_scanned(
        self, tmp_path
    ) -> None:
        """pkqer 1: a stray byte in an oversized module reached the statement cut's tokenizer as a
        lone surrogate, and the scan ended in an internal error with no report."""
        text = WindowedKit.source(1200)
        at = text.index("def f600(")
        data = text[:at].encode() + b'S = "\xa7"\n' + text[at:].encode()
        (tmp_path / "setup.py").write_bytes(data)
        config = Config.default().with_overrides(use_cache=False)
        limits = dataclasses.replace(
            config.limits, max_file_bytes=LIMIT, per_file_timeout=0, total_timeout=0
        )
        result = Scanner(config.with_overrides(limits=limits)).scan(tmp_path)
        assert {"SUSPECT.DECODE_EXEC.001", "MALWARE.INSTALL.DECODED_LAUNCH.001"} & {
            f.rule_id for f in result.findings
        }


class TestNeverWithholdingWhatParses:
    """The one way withholding could lose a finding: `may_parse` saying no (the pure-Python
    tokenizer) to a text the C parser accepts. Real modules cut at arbitrary offsets, with the
    spellings the two readers might differ on, must never be refused when they parse."""

    SOURCES: ClassVar[list[str]] = [
        Path(module.__file__).read_text(encoding="utf-8")
        for module in (ast, dataclasses, contextlib, tokenize, json.decoder, email.message)
        if module.__file__
    ]

    @staticmethod
    def spelled(text: str, how: str) -> str:
        if how == "crlf":
            return text.replace("\n", "\r\n")
        if how == "bom":
            return "﻿" + text
        if how == "formfeed":
            return text.replace("\n\n", "\n\x0c\n")
        if how == "tabs":
            return text.replace("\n    ", "\n\t")
        if how == "fstring":
            return text + '\nvalue = f"{\'a\' + f"{1:>{3}}"}"\n'
        return text

    @settings(max_examples=10_000, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        which=st.integers(min_value=0),
        at=st.integers(min_value=0),
        how=st.sampled_from(["plain", "crlf", "bom", "formfeed", "tabs", "fstring"]),
    )
    def test_a_refused_piece_never_parses(self, which: int, at: int, how: str) -> None:
        text = self.spelled(self.SOURCES[which % len(self.SOURCES)], how)
        piece = text[: at % (len(text) + 1)]
        if not PythonStatements.may_parse(piece):
            with pytest.raises((SyntaxError, ValueError)):
                ast.parse(piece)

    def test_a_refusal_of_parseable_text_is_caught(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The property's own check: a `may_parse` that refused a whole module would fail it."""
        monkeypatch.setattr(PythonStatements, "may_parse", staticmethod(lambda text: False))
        with pytest.raises(pytest.fail.Exception):
            whole = len(self.SOURCES[0])  # the cut that keeps the whole module, which parses
            self.test_a_refused_piece_never_parses.hypothesis.inner_test(self, 0, whole, "plain")
