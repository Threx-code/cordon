"""Per-language resolvers behind the `kind: ast` match kind.

The `ast` match kind resolves a call through imports, aliases, bindings and
folded constants, so a rule that names `child_process.exec` matches it however
the call site spells it. That resolution is language-specific, so it lives
behind a provider. Every provider is this project's own code, in the core: the
Python one over the stdlib `ast`, and the JavaScript and TypeScript one over
Cordon's own front end (`analysis/javascript/front`). No parser written
elsewhere reads a scanned file.

One shape, every language. A provider returns `AstCall` records -- the same
records the Python resolver produces and the same ones `AstQuery` consumes -- so
a single `kind: ast` rule applies to every language a provider exists for, with
no per-language rule authoring.

Absent is stated, never silent. A rule whose language has no provider simply
does not match there, and that language's files are still scanned by the regex
tier; nothing is ever installed to add one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cordon_scanner.analysis.python.pyast import AstCall


class AstProvider(Protocol):
    """Resolves the calls in one language's source into `AstCall` records."""

    def resolve_calls(self, source: str) -> list[AstCall]: ...


class PythonAstProvider:
    """The built-in Python provider, over the stdlib `ast`.

    A thin adapter: `pyast.PythonAnalyzer.calls` already produces `AstCall`
    records with imports, aliases, bindings and folded constants resolved, so
    this only names it as the provider for `python`.
    """

    def resolve_calls(self, source: str) -> list[AstCall]:
        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

        return PythonAnalyzer.calls(source)


_CACHE: dict[str, AstProvider | None] = {}


class AstProviders:
    """Which parser serves a language, when one is installed."""

    @staticmethod
    def ast_provider_for(language: str | None) -> AstProvider | None:
        """The provider for a language, or None when none is installed.

        None is a real answer: the language has no semantic tier, and the regex tier
        alone scans it. Cached per language.
        """
        if not language:
            return None
        if language in _CACHE:
            return _CACHE[language]

        provider: AstProvider | None
        if language == "python":
            provider = PythonAstProvider()
        elif language in ("javascript", "typescript"):
            from cordon_scanner.analysis.javascript.front.resolve import CallResolver

            provider = CallResolver(typescript=language == "typescript")
        else:
            provider = None
        _CACHE[language] = provider
        return provider


__all__ = ["AstProvider", "AstProviders", "PythonAstProvider"]
