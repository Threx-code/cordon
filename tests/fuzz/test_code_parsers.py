"""S1 for the analysis team's parsers: the Python, JavaScript and data-YAML readers, fed input
chosen to break them (reviews/release-080/SECURITY-HARDENING.md, S1).

The same two properties as test_parsers.py:
- every reader terminates, here within a per-example time bound;
- it raises nothing outside what its caller turns into a gap.
A RecursionError escapes on purpose (S2 ii): the detector runner records it as
OPERATIONAL.DETECTOR.FAILED, so it is tolerated here, as SyntaxError and ValueError are for the
parse entry points.

CI runs CORDON_FUZZ_EXAMPLES (300) a test. The hardening campaign sets it high and runs each class
for 30 minutes on the release head.
"""

from __future__ import annotations

import contextlib
import os
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.analysis.python.python_two_reader import PythonTwoReader
from cordon_scanner.foundation.formats.datayaml import DataYaml, DataYamlError

pytestmark = pytest.mark.fuzz

EXAMPLES = int(os.environ.get("CORDON_FUZZ_EXAMPLES", "300"))
SETTINGS = settings(
    max_examples=EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
#: Wall seconds one example of at most a few KB may take. Far above a linear reader's cost; a
#: reader past it on input this small is super-linear, and that is the defect.
BOUND = 10.0


class CodeKit:
    PY_TOKENS = (
        "import os",
        "from . import x",
        "def f(a, *b, **c):",
        "class A(B):",
        "lambda x: x",
        "if x:",
        "else:",
        "try:",
        "except E as e:",
        "except E, e:",
        "finally:",
        "with open(p) as f:",
        "for i in range(3):",
        "while 1:",
        "return",
        "yield",
        "await",
        "async def g():",
        "global g",
        "print x",
        "exec c in g",
        "os.system(c)",
        "eval(s)",
        "exec(compile(s, 'f', 'exec'))",
        "base64.b64decode(b)",
        "__import__('os')",
        "getattr(os, n)()",
        "x = [",
        "]",
        "(",
        ")",
        "{",
        "}",
        ":",
        ",",
        "=",
        "+",
        "*",
        "**",
        "@d",
        "\\",
        "'",
        '"',
        "'''",
        '"""',
        "f'{x}'",
        "b'\\x00'",
        "0L",
        "0777",
        "`x`",
        "<>",
        "#",
        "\n",
        "\n    ",
        "\t",
        "\x0c",
        "\r",
        " ",
        "if __name__ == '__main__':",
        "match x:",
        "case 1:",
        "type T = int",
        "def h[T](x: T):",
        "x := 1",
        "...",
        "nonlocal y",
    )
    JS_TOKENS = (
        "const a = require('child_process');",
        "import x from 'y';",
        "export default",
        "function f(a){",
        "}",
        "=>",
        "(",
        ")",
        "{",
        "[",
        "]",
        "`${",
        "`",
        "'",
        '"',
        "/re/g",
        "/*",
        "*/",
        "//",
        "\n",
        "a.exec(c)",
        "eval(s)",
        "new Function(s)",
        "fetch(u)",
        "http.get(u, r => {",
        "process.env",
        "Buffer.from(s, 'base64')",
        "spawn('sh', ['-c', c], {detached: true})",
        "class A extends B {",
        "async",
        "await",
        "yield",
        "?.",
        "??",
        "...",
        ";",
        ",",
        "=",
        "+",
        "0x",
        "\\u{61}",
        "#!/usr/bin/env node",
        "module.exports =",
        "if (",
        "else",
        "for (;;)",
        "while (1)",
        "try {",
        "catch (e) {",
        "label:",
    )
    YAML_TOKENS = (
        "a: b",
        "- x",
        "  ",
        "\n",
        ": ",
        "|",
        ">",
        "&a",
        "*a",
        "!!str",
        "!tag",
        "? k",
        "{",
        "}",
        "[",
        "]",
        ",",
        "'",
        '"',
        "#",
        "---",
        "...",
        "<<: *a",
        "on: push",
        "jobs:",
        "  run: x",
        "\t",
        "%YAML 1.2",
    )

    @staticmethod
    def program(tokens: tuple[str, ...]) -> st.SearchStrategy[str]:
        return st.lists(st.sampled_from(tokens), max_size=300).map(" ".join)

    @staticmethod
    def timed(run) -> None:
        started = time.monotonic()
        try:
            run()
        finally:
            spent = time.monotonic() - started
            assert spent < BOUND, f"{spent:.1f}s on a small input: super-linear"


PY = st.one_of(CodeKit.program(CodeKit.PY_TOKENS), st.text(max_size=2000))
JS = st.one_of(CodeKit.program(CodeKit.JS_TOKENS), st.text(max_size=2000))
YAML = st.one_of(CodeKit.program(CodeKit.YAML_TOKENS), st.text(max_size=2000))
PY_TOLERATED = (SyntaxError, ValueError, RecursionError)


class TestPythonReaders:
    @SETTINGS
    @given(source=PY)
    def test_the_analyser_terminates_and_raises_only_gaps(self, source: str) -> None:
        def run() -> None:
            with contextlib.suppress(PY_TOLERATED):
                PythonAnalyzer.analyse(source, follow_literals=True)

        CodeKit.timed(run)

    @SETTINGS
    @given(source=PY)
    def test_the_flow_facts_terminate_and_raise_only_gaps(self, source: str) -> None:
        def run() -> None:
            with contextlib.suppress(PY_TOLERATED):
                PythonFlowFacts.of(source)

        CodeKit.timed(run)

    @SETTINGS
    @given(source=PY)
    def test_the_python_2_reader_keeps_line_numbers(self, source: str) -> None:
        def run() -> None:
            try:
                reading = PythonTwoReader.read(source)
            except (ValueError, RecursionError):
                return
            if reading.text is not None:
                # what it read stands where the file had it (a form feed moved it: lava-test 0.14)
                assert reading.text.count("\n") == source.count("\n") or "\r" in source

        CodeKit.timed(run)


class TestJavaScriptReaders:
    @SETTINGS
    @given(source=JS)
    def test_the_flow_reader_terminates_and_raises_only_gaps(self, source: str) -> None:
        def run() -> None:
            try:
                JsFlow.flows(source)
                JsFlow.requests(source)
                JsFlow.deferred_spans(source)
                JsFlow.summaries(source)
            except (ValueError, RecursionError):
                pass

        CodeKit.timed(run)


class TestDataYaml:
    @SETTINGS
    @given(text=YAML)
    def test_it_terminates_and_raises_only_its_error(self, text: str) -> None:
        def run() -> None:
            with contextlib.suppress(DataYamlError, RecursionError):
                DataYaml.load(text, source="fuzz")

        CodeKit.timed(run)
