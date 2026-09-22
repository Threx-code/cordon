"""The per-language providers behind the `kind: ast` match kind.

The property that matters: one `AstCall` shape across languages, so a single
`kind: ast` rule resolves calls in each -- and a language with no installed
provider is reported as such, never silently treated as scanned.
"""

from __future__ import annotations

import pytest

from cordon_scanner.detect import ast_providers

tree_sitter = pytest.importorskip("tree_sitter", reason="the ast-js extra is not installed")


class TestTheRegistry:
    def test_python_always_has_a_provider(self) -> None:
        provider = ast_providers.ast_provider_for("python")
        assert provider is not None
        calls = provider.resolve_calls("import os\nos.system('id')\n")
        assert any(c.name == "os.system" for c in calls)

    def test_a_language_with_no_provider_is_none(self) -> None:
        assert ast_providers.ast_provider_for("ruby") is None
        assert ast_providers.ast_provider_for(None) is None

    def test_missing_provider_language_is_none_when_installed(self) -> None:
        # tree_sitter is importable in the test environment, so js is not missing.
        assert ast_providers.missing_provider_language("javascript") is None
        assert ast_providers.missing_provider_language("ruby") is None


class TestTheJavaScriptProvider:
    @pytest.fixture
    def js(self):
        provider = ast_providers.ast_provider_for("javascript")
        assert provider is not None
        return provider

    def _names(self, provider, source: str) -> set[str]:
        return {c.name for c in provider.resolve_calls(source)}

    def test_a_destructured_require_resolves_to_the_module(self, js) -> None:
        names = self._names(js, "const { exec } = require('child_process');\nexec('id');")
        assert "child_process.exec" in names

    def test_an_aliased_require_resolves_member_calls(self, js) -> None:
        names = self._names(js, "const cp = require('child_process');\ncp.execSync(x);")
        assert "child_process.execSync" in names

    def test_a_renamed_named_import_resolves(self, js) -> None:
        """The case the regex tier structurally cannot see: the function name
        itself is renamed, so `exec` appears nowhere at the call site."""
        names = self._names(js, "import { exec as e } from 'child_process';\ne('id');")
        assert "child_process.exec" in names

    def test_a_default_and_namespace_import_resolve(self, js) -> None:
        assert "m.f" in self._names(js, "import d from 'm';\nd.f();")
        assert "m2.g" in self._names(js, "import * as ns from 'm2';\nns.g();")

    def test_the_node_prefix_is_preserved(self, js) -> None:
        names = self._names(js, "const cp = require('node:child_process');\ncp.exec(x);")
        assert "node:child_process.exec" in names

    def test_an_unrelated_member_call_is_not_confused(self, js) -> None:
        names = self._names(js, "const x = require('lodash');\nx.map(a);\nself.exec(q);")
        assert "child_process.exec" not in names
        assert "child_process.execSync" not in names

    def test_a_two_literal_argument_is_not_constructed(self, js) -> None:
        (call,) = [c for c in js.resolve_calls("f('a.' + 'b.com');") if c.name == "f"]
        assert call.has_constructed_argument is False

    def test_a_built_argument_is_constructed(self, js) -> None:
        (call,) = [c for c in js.resolve_calls("f(host + '.evil');") if c.name == "f"]
        assert call.has_constructed_argument is True

    def test_unparseable_source_yields_nothing_rather_than_raising(self, js) -> None:
        # tree-sitter is error-tolerant, but this must never raise regardless.
        assert isinstance(js.resolve_calls("const const const {{{"), list)


class TestDegradationWhenTheExtraIsAbsent:
    def test_a_missing_grammar_makes_the_language_have_no_provider(self, monkeypatch) -> None:
        """Simulates the base install without the extra: the provider build
        raises ImportError, so the registry returns None and names the extra to
        install -- rather than crashing or pretending the language was scanned."""
        monkeypatch.setattr(ast_providers, "_CACHE", {})

        def _raise(_language: str):
            raise ImportError("tree_sitter not installed")

        monkeypatch.setattr(ast_providers, "_TreeSitterProvider", _raise)
        assert ast_providers.ast_provider_for("javascript") is None
        assert ast_providers.missing_provider_language("javascript") == "ast-js"
