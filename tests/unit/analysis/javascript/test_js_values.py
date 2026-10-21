"""JsValues: the strings an expression can spell, read only where literals in the file decide them
(review 98 #28). Every way the file can leave a part undecided makes the set unknown."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.js_flow import _Analysis
from cordon_scanner.analysis.javascript.js_values import JsValues


class ValuesHelpers:
    @staticmethod
    def values(source: str) -> frozenset[str] | None:
        """The value set of the first argument of the file's last call of `use(...)`."""
        analysis = _Analysis(source)
        analysis.run()
        calls = [k for k in range(analysis.n - 1) if analysis.is_name(k, "use")]
        k = calls[-1]
        s, e = analysis._args(k + 1)[0]
        return JsValues(analysis).strings(s, e, analysis.scope_of(k))


values = ValuesHelpers.values


class TestDecided:
    def test_a_template_of_ternaries(self) -> None:
        got = values(
            'const ext = os === "win" ? "zip" : "tgz";\n'
            'const cpu = arch === "x64" ? "x86_64" : "aarch64";\n'
            "use(`https://h.example/a/uv-${cpu}.${ext}`);\n"
        )
        assert got == {
            "https://h.example/a/uv-x86_64.zip",
            "https://h.example/a/uv-x86_64.tgz",
            "https://h.example/a/uv-aarch64.zip",
            "https://h.example/a/uv-aarch64.tgz",
        }

    def test_a_field_of_the_object_a_function_returns(self) -> None:
        got = values(
            "function asset(p) {\n"
            "  if (!p) return void 0;\n"
            '  const ext = p === "w" ? "zip" : "tgz";\n'
            '  return { ext, url: "https://h.example/x." + ext };\n'
            "}\n"
            "function go(p) { const a = asset(p); if (!a) return; use(a.url); }\n"
        )
        assert got == {"https://h.example/x.zip", "https://h.example/x.tgz"}

    def test_every_assignment_of_a_name(self) -> None:
        got = values('let t;\nif (a) t = "one";\nelse t = "two";\nuse("v-" + t);\n')
        assert got == {"v-one", "v-two"}

    def test_undefined_reads_as_its_own_text(self) -> None:
        assert values('const c = a ? "x" : void 0;\nuse(`p-${c}`);\n') == {"p-x", "p-undefined"}


class TestUndecided:
    def test_a_parameter(self) -> None:
        assert values('function f(dir) { use("https://h.example/" + dir); }\n') is None

    def test_the_environment(self) -> None:
        assert values('use(process.env.BASE + "/x");\n') is None

    def test_a_call_outside_the_file(self) -> None:
        assert values('const v = lib.version();\nuse("https://h.example/" + v);\n') is None

    def test_a_destructured_name(self) -> None:
        assert values('const { u = "https://h.example/x" } = options;\nuse(u);\n') is None

    def test_a_compound_assignment(self) -> None:
        assert values('let u = "https://h.example/";\nu += tail;\nuse(u);\n') is None

    def test_an_object_written_through_a_member(self) -> None:
        source = 'const a = { url: "https://h.example/x" };\na.url = other;\nuse(a.url);\n'
        assert values(source) is None

    def test_an_object_handed_to_a_call(self) -> None:
        source = 'const a = { url: "https://h.example/x" };\nObject.assign(a, o);\nuse(a.url);\n'
        assert values(source) is None

    def test_a_spread_in_the_literal(self) -> None:
        assert values('const a = { url: "https://h.example/x", ...o };\nuse(a.url);\n') is None

    def test_a_function_reassigned(self) -> None:
        source = (
            'function base() { return "https://h.example/"; }\nbase = other;\nuse(base() + "x");\n'
        )
        assert values(source) is None

    def test_too_many_strings(self) -> None:
        names = [f"p{i}" for i in range(4)]
        lines = [f'const {n} = a ? "{n}a" : b ? "{n}b" : c ? "{n}c" : "{n}d";' for n in names]
        source = "\n".join(lines) + "\nuse(" + " + ".join(names) + ");\n"
        assert values(source) is None  # 4 ** 4 = 256 strings, past the limit
