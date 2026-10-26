"""The per-language providers behind the `kind: ast` match kind.

The property that matters: one `AstCall` shape across languages, so a single
`kind: ast` rule resolves calls in each -- and every provider is the project's
own code in the core install, so no language depends on an extra being present.
"""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.shared import ast_providers


class TestTheRegistry:
    def test_python_always_has_a_provider(self) -> None:
        provider = ast_providers.AstProviders.ast_provider_for("python")
        assert provider is not None
        calls = provider.resolve_calls("import os\nos.system('id')\n")
        assert any(c.name == "os.system" for c in calls)

    def test_a_language_with_no_provider_is_none(self) -> None:
        assert ast_providers.AstProviders.ast_provider_for("ruby") is None
        assert ast_providers.AstProviders.ast_provider_for(None) is None

    def test_javascript_and_typescript_have_the_projects_own_provider(self) -> None:
        from cordon_scanner.analysis.javascript.front.resolve import CallResolver

        for language in ("javascript", "typescript"):
            assert isinstance(ast_providers.AstProviders.ast_provider_for(language), CallResolver)


class TestTheJavaScriptProvider:
    @pytest.fixture
    def js(self):
        provider = ast_providers.AstProviders.ast_provider_for("javascript")
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
        assert isinstance(js.resolve_calls("const const const {{{"), list)


class TestTheCoreInstall:
    def test_javascript_and_typescript_resolve_with_no_third_party_module(
        self, monkeypatch
    ) -> None:
        """The base install: no tree-sitter importable, and both languages still resolve,
        through the project's own front end."""
        import builtins

        real_import = builtins.__import__

        def _no_tree_sitter(name: str, *args, **kwargs):
            if name.startswith("tree_sitter"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(ast_providers, "_CACHE", {})
        monkeypatch.setattr(builtins, "__import__", _no_tree_sitter)
        for language in ("javascript", "typescript"):
            provider = ast_providers.AstProviders.ast_provider_for(language)
            assert provider is not None
            names = {
                c.name
                for c in provider.resolve_calls("const cp = require('child_process');\ncp.exec(x);")
            }
            assert "child_process.exec" in names
