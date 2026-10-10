"""Whether a vulnerable dependency is actually reached from first-party code.

The single biggest complaint about vulnerability scanners is noise: a report
lists a CVE in a package three levels down that the project never calls, at the
same severity as one in a function it invokes on every request. Reachability is
the answer, and this is its first, coarsest tier -- import reachability: is the
flagged package imported by the code in this repository at all?

Two rules keep it honest.

It annotates, it never suppresses. A finding is not removed for being
unreached; its severity is lowered and it is tagged, so a team can gate on
"reached only" while the unreached ones stay in the report where a reviewer can
still see them. Silently dropping a finding on a reachability guess is the exact
"looks clean but was not looked at" failure this project is built against.

Unknown is not unreached. Import reachability cannot see a dynamic import, a
package imported under a name it does not publish, or a path that runs through a
dependency rather than through first-party code. So the only finding it lowers
is one on a TRANSITIVE dependency that first-party code does not import -- a
package pulled in by something else and not named here. A direct dependency not
seen imported is left UNKNOWN, not lowered, because the import may be dynamic or
renamed. And this applies to a vulnerability, never to a known-malicious
package: a compromised release must not be installed whether or not it is
called, so its severity does not move.

The precise tier -- is the vulnerable *symbol* on a call path -- builds on the
`AstProvider` call resolution and is a later layer; this one needs only the set
of imported module names, which is cheap.
"""

from __future__ import annotations

import ast
import contextlib
import enum
import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Final

from cordon_scanner.core.models import Severity
from cordon_scanner.core.pysyntax import PythonSyntax
from cordon_scanner.intel.advisory_text import AdvisoryTextSymbols

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Dependency, Finding
    from cordon_scanner.detect.base import Unit

VULNERABLE_RULE = "VULNERABLE.DEPENDENCY.KNOWN.001"
VULNERABILITY_RULES = frozenset({VULNERABLE_RULE, "VULNERABLE.DEPENDENCY.EXPLOITED.001"})


class Reachability(enum.StrEnum):
    CALLED = "called"
    """First-party code calls into the package, or passes one of its functions on."""
    CALLED_UNREACHED = "called_unreached"
    """Calls into the package exist only inside private functions nothing in the project names.
    Python only; a call by a name built at runtime would escape this, so it lowers, never drops."""
    IMPORTED = "imported"
    """Imported at runtime, and no call or reference into it was seen. Module-level code in the
    package still runs on import, so this is not a claim the vulnerable code cannot run."""
    TYPE_ONLY = "type_only"
    """Imported only for type checking -- `if TYPE_CHECKING:` or `import type` -- which runs nothing."""
    NOT_IMPORTED = "not_imported"
    UNKNOWN = "unknown"
    VULNERABLE_CALLED = "vulnerable_called"
    """First-party code calls a function the advisory names as the vulnerable one."""
    VULNERABLE_NOT_CALLED = "vulnerable_not_called"
    """The advisory names its vulnerable functions and first-party code calls none of them."""


@dataclass
class Usage:
    """How first-party code uses one top-level module."""

    runtime_import: bool = False
    type_only_import: bool = False
    symbols: set[str] = field(default_factory=set)
    """Dotted names called or referenced through the import, `yaml.load`, `lodash.merge`, from code
    a root reaches."""
    unreached_symbols: set[str] = field(default_factory=set)
    """The same, used only inside private functions nothing in the project mentions."""


#: PyPI distribution names whose import name differs. Without these a real import
#: would be missed and the finding wrongly lowered. Small and common on purpose:
#: an unlisted mismatch falls to UNKNOWN (not lowered), which is the safe
#: direction.
_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "pyyaml": ("yaml",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
    "msgpack-python": ("msgpack",),
    "opencv-python": ("cv2",),
    "protobuf": ("google",),
    "setuptools": ("setuptools", "pkg_resources"),
    "gitpython": ("git",),
    "pyjwt": ("jwt",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "python-jose": ("jose",),
    "python-multipart": ("multipart",),
    "pyopenssl": ("OpenSSL",),
    "python-ldap": ("ldap",),
    "pysaml2": ("saml2",),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "pyzmq": ("zmq",),
    "python-magic": ("magic",),
}

_SEVERITY_DOWN: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
    Severity.INFO: Severity.INFO,
}


class ImportReachability:
    """Whether first-party code imports, calls or never reaches a vulnerable dependency."""

    @staticmethod
    def annotate(
        findings: list[Finding],
        units: Sequence[Unit],
        dependencies: tuple[Dependency, ...],
    ) -> list[Finding]:
        """Return the findings with vulnerability findings annotated by reachability."""
        usage = ImportReachability.collect_usage(units)
        go = GoUsage.of(units)
        by_purl = {d.purl: d for d in dependencies}
        out: list[Finding] = []
        for finding in findings:
            dep = by_purl.get(finding.location.package or "")
            if finding.rule_id in VULNERABILITY_RULES and dep is not None:
                vulnerable = dict(finding.evidence.metadata).get("vulnerable_symbols", "")
                named = [v for v in vulnerable.split(",") if v]
                if AdvisoryTextSymbols.is_text(named):
                    out.append(ImportReachability._from_text(finding, dep, usage, named))
                    continue
                if vulnerable and go.files:
                    verdict, symbols = go.verdict([v for v in vulnerable.split(",") if v])
                    out.append(
                        ImportReachability._annotated(
                            finding, verdict, symbols, stdlib=dep.name == "stdlib"
                        )
                    )
                    continue
                verdict, symbols = ImportReachability._verdict(dep, usage)
                out.append(ImportReachability._annotated(finding, verdict, symbols))
            else:
                out.append(finding)
        return out

    @staticmethod
    def _from_text(
        finding: Finding, dep: Dependency, usage: dict[str, Usage], named: list[str]
    ) -> Finding:
        """Function-level for PyPI and npm, from the names the advisory's prose gives.

        One direction only: a call to a named function raises the finding to the top; no call
        leaves the import-level verdict exactly as it would have been. Prose names the function its
        reporter found, not every one that reaches the flaw, so its silence proves nothing.
        """
        verdict, used = ImportReachability._verdict(dep, usage)
        called = sorted({u for u in used for n in named if AdvisoryTextSymbols.matches(u, n)})
        if called:
            return ImportReachability._annotated(finding, Reachability.VULNERABLE_CALLED, called)
        return ImportReachability._annotated(finding, verdict, used)

    @staticmethod
    def collect_usage(units: Sequence[Unit]) -> dict[str, Usage]:
        """How the first-party source in the scan uses each top-level module it imports."""
        from cordon_scanner.detect.base import FileUnit

        usage: dict[str, Usage] = {}
        python: list[ast.Module] = []
        javascript: list[str] = []
        for unit in units:
            if not isinstance(unit, FileUnit):
                continue
            if unit.language == "python":
                with contextlib.suppress(SyntaxError, ValueError, RecursionError):
                    python.append(PythonSyntax.parse(unit.content.text))
            elif unit.language in ("javascript", "typescript"):
                javascript.append(unit.content.text)
        words = ImportReachability._js_word_counts(javascript)
        for text in javascript:
            ImportReachability._js_usage(text, usage, words)
        referenced = ImportReachability._referenced_names(python)
        for tree in python:
            ImportReachability._python_usage(tree, usage, referenced)
        return usage

    @staticmethod
    def _referenced_names(trees: Sequence[ast.Module]) -> set[str]:
        """Every name first-party Python mentions: called, passed, assigned or looked up as an attribute.
        A private function absent from this set is one nothing in the project can reach by name."""
        names: set[str] = set()
        for tree in trees:
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    names.add(node.attr)
                elif (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and node.value.isidentifier()
                ):
                    names.add(
                        node.value
                    )  # getattr(obj, "name"), __all__ entries, registries by string
        return names

    @staticmethod
    def _function_reachable(
        node: ast.FunctionDef | ast.AsyncFunctionDef, referenced: set[str]
    ) -> bool:
        """Public API, a decorated function (a registration this analysis cannot see), a dunder, or a
        name something in the project mentions."""
        name = node.name
        return (
            not name.startswith("_")
            or (name.startswith("__") and name.endswith("__"))
            or bool(node.decorator_list)
            or name in referenced
        )

    @staticmethod
    def collect_imports(units: Sequence[Unit]) -> set[str]:
        """Every module name imported at runtime by the first-party source in the scan."""
        return {
            name
            for name, use in ImportReachability.collect_usage(units).items()
            if use.runtime_import
        }

    @staticmethod
    def _verdict(dep: Dependency, usage: dict[str, Usage]) -> tuple[Reachability, list[str]]:
        candidates = ImportReachability._import_candidates(dep.name)
        matched = [usage[c] for c in candidates if c in usage]
        symbols = sorted({s for use in matched for s in use.symbols})
        unreached = sorted({s for use in matched for s in use.unreached_symbols} - set(symbols))
        if any(use.runtime_import for use in matched):
            if symbols:
                return Reachability.CALLED, symbols
            if unreached:
                return Reachability.CALLED_UNREACHED, unreached
            return Reachability.IMPORTED, []
        if any(use.type_only_import for use in matched):
            return Reachability.TYPE_ONLY, []
        if not dep.direct:
            return Reachability.NOT_IMPORTED, []
        return Reachability.UNKNOWN, []

    @staticmethod
    def _import_candidates(name: str) -> set[str]:
        normalized = name.lower().replace("_", "-")
        candidates = {name, normalized, normalized.replace("-", "_")}
        candidates |= set(_IMPORT_ALIASES.get(normalized, ()))
        # A scoped npm package imports under its full `@scope/name`; an unscoped one
        # under its name. Its subpaths (`lodash/fp`) import the package, so the bare
        # name covers them.
        return candidates

    @staticmethod
    def _annotated(
        finding: Finding,
        verdict: Reachability,
        symbols: Sequence[str] = (),
        *,
        stdlib: bool = False,
    ) -> Finding:
        named = ", ".join(symbols[:MAX_SYMBOLS_NAMED]) + (
            " and more" if len(symbols) > MAX_SYMBOLS_NAMED else ""
        )
        note = {
            Reachability.CALLED: (
                f" Reachability: first-party code calls into this package ({named}); compare those with "
                "the functions the advisory names."
            ),
            Reachability.CALLED_UNREACHED: (
                f" Reachability: first-party code calls into this package ({named}) only from private "
                "functions nothing in the project names, so it is lowered rather than dropped: a call by a "
                "name built at runtime would not show here."
            ),
            Reachability.IMPORTED: (
                " Reachability: this package is imported by first-party code, and no call into it was "
                "seen. Its module-level code still runs on import, so severity is unchanged."
            ),
            Reachability.TYPE_ONLY: (
                " Reachability: first-party code imports this package only for type checking, which "
                "runs none of it, so it is lowered rather than dropped."
            ),
            Reachability.NOT_IMPORTED: (
                " Reachability: this transitive dependency is not imported by first-party code, "
                "so it is unlikely to be reached -- an import-level check, not a call-graph proof, "
                "so it is lowered rather than dropped."
            ),
            Reachability.VULNERABLE_CALLED: (
                f" Reachability: first-party code calls the vulnerable function the advisory names "
                f"({named}). Fix this one first."
            ),
            Reachability.VULNERABLE_NOT_CALLED: (
                " Reachability: the advisory names its vulnerable functions and first-party code calls "
                "none of them. A dependency still could, so it is lowered rather than dropped"
                + (
                    " -- and not lowered at all for the standard library, which dependencies use "
                    "constantly."
                    if stdlib
                    else "."
                )
            ),
            Reachability.UNKNOWN: (
                " Reachability: could not be determined (a direct dependency not seen imported may "
                "be loaded dynamically or under another name), so severity is unchanged."
            ),
        }[verdict]

        severity = finding.severity
        if verdict in (
            Reachability.NOT_IMPORTED,
            Reachability.TYPE_ONLY,
            Reachability.CALLED_UNREACHED,
        ) or (verdict is Reachability.VULNERABLE_NOT_CALLED and not stdlib):
            severity = _SEVERITY_DOWN[finding.severity]

        metadata = (*finding.evidence.metadata, ("reachability", verdict.value))
        if symbols:
            metadata = (*metadata, ("reachability_symbols", ",".join(symbols[:50])))
        return replace(
            finding,
            severity=severity,
            message=finding.message + note,
            evidence=replace(finding.evidence, metadata=metadata),
        )

    @staticmethod
    def _type_checking_test(node: ast.AST) -> bool:
        return (isinstance(node, ast.Name) and node.id == "TYPE_CHECKING") or (
            isinstance(node, ast.Attribute) and node.attr == "TYPE_CHECKING"
        )

    @staticmethod
    def _python_usage(tree: ast.Module, usage: dict[str, Usage], referenced: set[str]) -> None:
        type_only_nodes: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and ImportReachability._type_checking_test(node.test):
                for child in node.body:
                    type_only_nodes.update(id(n) for n in ast.walk(child))
        bindings: dict[str, tuple[str, str]] = {}
        """Local name -> (top-level module, dotted path it stands for)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0]
                    use = usage.setdefault(top, Usage())
                    if id(node) in type_only_nodes:
                        use.type_only_import = True
                        continue
                    use.runtime_import = True
                    local = alias.asname or top
                    bindings[local] = (top, alias.name if alias.asname else top)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                top = node.module.split(".", 1)[0]
                use = usage.setdefault(top, Usage())
                if id(node) in type_only_nodes:
                    use.type_only_import = True
                    continue
                use.runtime_import = True
                for alias in node.names:
                    if alias.name != "*":
                        bindings[alias.asname or alias.name] = (top, f"{node.module}.{alias.name}")
        if not bindings:
            return
        # The base of `yaml.load` is itself a Name; the chain is recorded once, whole.
        inner = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        # Nodes inside a function no root reaches, directly or through an enclosing one.
        unreached: set[int] = set()
        for function in ast.walk(tree):
            if isinstance(
                function, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not ImportReachability._function_reachable(function, referenced):
                for child in function.body:
                    unreached.update(id(n) for n in ast.walk(child))
        for node in ast.walk(tree):
            if id(node) in inner:
                continue
            if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
                getattr(node, "ctx", None), ast.Load
            ):
                continue
            dotted = ImportReachability._dotted(node)
            if dotted is None:
                continue
            head, _, rest = dotted.partition(".")
            if head in bindings:
                top, path = bindings[head]
                symbol = f"{path}.{rest}" if rest else path
                (usage[top].unreached_symbols if id(node) in unreached else usage[top].symbols).add(
                    symbol
                )

    @staticmethod
    def _dotted(node: ast.AST) -> str | None:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _js_top(spec: str) -> str | None:
        if spec.startswith((".", "/")):
            return None  # a relative path is first-party, not a dependency
        parts = spec.split("/")
        return "/".join(parts[:2]) if spec.startswith("@") else parts[0]

    @staticmethod
    def _js_usage(
        text: str, usage: dict[str, Usage], referenced: dict[str, int] | None = None
    ) -> None:
        for match in _JS_IMPORT.finditer(text):
            top = ImportReachability._js_top(match.group(1))
            if top is not None:
                usage.setdefault(top, Usage())
        bindings: dict[str, tuple[str, str]] = {}
        import_spans: list[tuple[int, int]] = []
        for match in _JS_BINDING.finditer(text):
            import_spans.append(match.span())
            type_only, default, namespace, named, spec = match.group(1, 2, 3, 4, 5)
            if spec is None:
                default, named, spec = match.group(6), match.group(7), match.group(8)
            top = ImportReachability._js_top(spec)
            if top is None:
                continue
            use = usage.setdefault(top, Usage())
            if type_only:
                use.type_only_import = True
                continue
            use.runtime_import = True
            if default:
                bindings[default] = (top, spec)
            if namespace:
                bindings[namespace] = (top, spec)
            for part in (named or "").split(","):
                part = part.strip()
                if not part or part.startswith("type "):
                    continue
                original, _, alias = part.replace(":", " as ").partition(" as ")
                bindings[(alias or original).strip()] = (top, f"{spec}.{original.strip()}")
        for match in _JS_IMPORT.finditer(text):
            top = ImportReachability._js_top(match.group(1))
            if top is not None and not any(
                start <= match.start() < end for start, end in import_spans
            ):
                usage[top].runtime_import = True  # a bare `import 'x'` or an inline require
        if not bindings:
            return
        names = "|".join(re.escape(name) for name in sorted(bindings, key=len, reverse=True))
        reference = re.compile(rf"(?<![\w$.])({names})((?:\.[\w$]+)*)")
        dead = ImportReachability._js_unreached_spans(text, referenced or {})
        for match in reference.finditer(text):
            if any(start <= match.start() < end for start, end in import_spans):
                continue
            top, path = bindings[match.group(1)]
            unreached = any(start <= match.start() < end for start, end in dead)
            (usage[top].unreached_symbols if unreached else usage[top].symbols).add(
                path + match.group(2)
            )

    @staticmethod
    def _js_word_counts(texts: Sequence[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for text in texts:
            for word in _JS_WORD.findall(text):
                counts[word] = counts.get(word, 0) + 1
        return counts

    @staticmethod
    def _js_unreached_spans(text: str, counts: dict[str, int]) -> list[tuple[int, int]]:
        """Bodies of top-level functions that are not exported and whose name appears nowhere else in
        the project's JavaScript -- defined, and never called, passed or exported."""
        spans: list[tuple[int, int]] = []
        for match in _JS_FUNCTION.finditer(text):
            name = match.group("fn") or match.group("var")
            if not name or match.group("export") or counts.get(name, 0) > 1:
                continue
            if re.search(
                rf"module\.exports[^;\n]{{0,200}}\b{re.escape(name)}\b|exports\.{re.escape(name)}\b",
                text,
            ):
                continue
            open_brace = text.find("{", match.end())
            if open_brace < 0 or open_brace - match.end() > 400:
                continue
            depth, index = 0, open_brace
            limit = min(len(text), open_brace + MAX_JS_BODY)
            while index < limit:
                char = text[index]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        spans.append((open_brace, index))
                        break
                index += 1
        return spans


_GO_IMPORT_LINE = re.compile(
    r'^\s*(?:import\s+)?(?:([A-Za-z_][\w]*|\.|_)\s+)?"([^"\s]{1,300})"\s*$'
)
_GO_VERSION_SUFFIX = re.compile(r"^v\d+$")


@dataclass
class GoUsage:
    """Which import paths first-party Go code uses, under what names, and the code itself."""

    files: list[tuple[dict[str, str], str]] = field(default_factory=list)
    """Per file: import path to the name it is used under, and the source."""

    @classmethod
    def of(cls, units: Sequence[Unit]) -> GoUsage:
        from cordon_scanner.detect.base import FileUnit

        usage = cls()
        for unit in units:
            if not isinstance(unit, FileUnit) or not unit.path.endswith(".go"):
                continue
            if "/vendor/" in f"/{unit.path}" or unit.path.endswith("_test.go"):
                continue
            usage.files.append((cls._imports(unit.content.text), unit.content.text))
        return usage

    @staticmethod
    def _imports(text: str) -> dict[str, str]:
        imports: dict[str, str] = {}
        block = False
        for line in text.splitlines()[:400]:
            stripped = line.strip()
            if stripped.startswith("import ("):
                block = True
                continue
            if block and stripped.startswith(")"):
                block = False
                continue
            if not (block or stripped.startswith("import ")):
                continue
            found = _GO_IMPORT_LINE.match(stripped)
            if found is None:
                continue
            alias, path = found.group(1), found.group(2)
            segments = path.split("/")
            default = (
                segments[-2]
                if len(segments) > 1 and _GO_VERSION_SUFFIX.match(segments[-1])
                else segments[-1]
            )
            default = default.split(".")[0].replace("-", "_")
            imports[path] = alias or default
        return imports

    def verdict(self, vulnerable: list[str]) -> tuple[Reachability, list[str]]:
        """CALLED with the vulnerable names first-party code uses, or NOT_CALLED, or UNKNOWN."""
        called: list[str] = []
        imported_any = False
        for entry in vulnerable:
            path, _, symbol = entry.partition(":")
            if not symbol:
                continue
            for imports, text in self.files:
                name = imports.get(path)
                if name is None:
                    continue
                imported_any = True
                if name in ("_",):
                    continue
                head, _, method = symbol.partition(".")
                if method:
                    # `Type.Method`: without types, any `.Method(` in a file that imports the
                    # package counts. The over-approximation is the safe direction.
                    hit = re.search(rf"\.{re.escape(method)}\s*\(", text) is not None
                elif name == ".":
                    hit = re.search(rf"(?<![\w.]){re.escape(head)}\s*\(", text) is not None
                else:
                    hit = re.search(rf"\b{re.escape(name)}\.{re.escape(head)}\b", text) is not None
                if hit:
                    called.append(f"{path}.{symbol}")
                    break
        if called:
            return Reachability.VULNERABLE_CALLED, sorted(set(called))
        if imported_any:
            return Reachability.VULNERABLE_NOT_CALLED, []
        return Reachability.UNKNOWN, []


MAX_SYMBOLS_NAMED = 8


_JS_IMPORT = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s+)['"]([^'"]{1,200})['"]""",
)
_JS_BINDING = re.compile(
    r"""^\s*import\s+(type\s+)?([\w$]+)?\s*,?\s*(?:\*\s+as\s+([\w$]+)|\{([^}]{0,2000})\})?\s*from\s*['"]([^'"]{1,200})['"]"""
    r"""|(?:const|let|var)\s+(?:([\w$]+)|\{([^}]{0,2000})\})\s*=\s*require\s*\(\s*['"]([^'"]{1,200})['"]\s*\)""",
    re.MULTILINE,
)


_JS_FUNCTION: Final = re.compile(
    r"(?m)^(?P<export>[ \t]{0,40}export[ \t]{1,8}(?:default[ \t]{1,8})?)?[ \t]{0,40}"
    r"(?:async[ \t]{1,8})?(?:function[ \t]{0,8}\*?[ \t]{0,8}(?P<fn>[A-Za-z_$][\w$]{0,80})[ \t]{0,8}\("
    r"|(?:const|let|var)[ \t]{1,8}(?P<var>[A-Za-z_$][\w$]{0,80})[ \t]{0,8}=[ \t]{0,8}(?:async[ \t]{1,8})?"
    r"(?:function\b|\([^)\n]{0,300}\)[ \t]{0,8}=>|[A-Za-z_$][\w$]{0,80}[ \t]{0,8}=>))"
)
_JS_WORD: Final = re.compile(r"[A-Za-z_$][\w$]{0,80}")
MAX_JS_BODY: Final = 200_000


__all__ = ["ImportReachability", "Reachability", "Usage"]
