"""Which function each JavaScript or TypeScript call reaches, from Cordon's own resolver."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.front.resolve import CallResolver


class Resolved:
    @staticmethod
    def names(source: str, *, typescript: bool = False) -> list[str]:
        return [c.name for c in CallResolver(typescript=typescript).resolve_calls(source)]


class TestAliases:
    @pytest.mark.parametrize(
        ("source", "name"),
        [
            ('const cp = require("child_process");\ncp.exec(c);', "child_process.exec"),
            ('const { exec: run } = require("child_process"); run(c);', "child_process.exec"),
            ('const run = require("child_process").exec; run(c);', "child_process.exec"),
            ('import * as cp from "node:child_process";\ncp.spawn(c);', "node:child_process.spawn"),
            ('import { exec as e } from "child_process"; e(c);', "child_process.exec"),
            ('require("child_process").exec(c);', "child_process.exec"),
            ('const r = require; const cp = r("child_process"); cp.fork(m);', "child_process.fork"),
            (
                'const cp = require("child_process"); const a = cp; a.execSync(x);',
                "child_process.execSync",
            ),
            ('cp.exec(c);\nvar cp = require("child_process");', "child_process.exec"),
            ("globalThis.eval(x);", "eval"),
            (
                "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n"
                "const { spawn } = require('child_process'); spawn('npm');",
                "child_process.spawn",
            ),
            (
                "async function f() { const { spawn } = await import('child_process'); spawn(x); }",
                "child_process.spawn",
            ),
            ("import { Buffer } from 'buffer'; Buffer.from(b, 'base64');", "Buffer.from"),
        ],
    )
    def test_each_spelling_reaches_the_module(self, source: str, name: str) -> None:
        assert name in Resolved.names(source)

    def test_typescript_import_equals(self) -> None:
        assert "child_process.fork" in Resolved.names(
            'import cp = require("child_process"); cp.fork(m);', typescript=True
        )


class TestScopes:
    def test_a_parameter_shadows_the_module_binding(self) -> None:
        names = Resolved.names(
            'const cp = require("child_process"); function f(cp) { cp.exec(c); }'
        )
        assert "cp.exec" in names
        assert "child_process.exec" not in names

    def test_a_function_binding_does_not_leak_to_the_module(self) -> None:
        source = (
            "const exec = require('child_process').execSync;\n"
            "function a() { const { exec } = require('child_process'); exec(x); }\n"
            "exec(y);\n"
        )
        assert sorted(Resolved.names(source)) == sorted(
            ["require", "require", "child_process.exec", "child_process.execSync"]
        )


class TestValues:
    def test_computed_members_and_bundler_calls(self) -> None:
        source = 'const cp = require("child_process"); cp["ex" + "ec"](a); (0, cp.spawn)(b);'
        names = Resolved.names(source)
        assert "child_process.exec" in names
        assert "child_process.spawn" in names

    def test_folded_module_names(self) -> None:
        assert "child_process.exec" in Resolved.names(
            'const m = "child_" + "process"; require(m).exec(c);'
        )
        assert "vm.runInNewContext" in Resolved.names(
            "const n = String.fromCharCode(118, 109); require(n).runInNewContext(s);"
        )

    def test_folded_arguments_and_built_ones(self) -> None:
        calls = CallResolver().resolve_calls("Buffer.from(b, 'ba' + 'se64'); x.exec(`ls ${d}`);")
        assert [(c.name, c.arguments, c.has_constructed_argument) for c in calls] == [
            ("Buffer.from", ("", "base64"), False),
            ("x.exec", ("",), True),
        ]


class TestPlaces:
    def test_line_and_byte_column(self) -> None:
        (call,) = CallResolver().resolve_calls("// é\nconst s = 'ü'; f(s);")
        assert (call.line, call.column) == (2, len("const s = 'ü'; ".encode()))

    def test_parts_resolve_as_one_file(self) -> None:
        first = 'const cp = require("child_process");\n'
        second = "cp.exec(c);\n"
        located = CallResolver().resolve_parts(
            [(0, 0, 0, first), (len(first.encode()), 1, 0, second)]
        )
        (offset, call) = located[-1]
        assert call.name == "child_process.exec"
        assert (offset, call.line) == (len(first.encode()), 2)

    def test_a_tsx_file_is_read_with_its_markup(self) -> None:
        source = "const cp = require('child_process');\nexport const V = () => <div>{cp.exec(x)}</div>;\n"
        assert "child_process.exec" in Resolved.names(source, typescript=True)
