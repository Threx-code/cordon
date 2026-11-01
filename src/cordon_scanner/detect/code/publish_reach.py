"""Whether a published package's publishing script can run on the machine that installs it.

`SUSPECT.REGISTRY.SELF_PUBLISH.001` reads one act, a publishing command handed to something that
runs it. In a published npm package that act is a worm only where something runs it for a consumer:
an install hook, a library entry point (`main`, `exports`), or a file one loads. A `bin` is a command
a person runs, as a release script is: a publishing CLI publishes when its user asks it to. A release
task in `tasks/` or a spam publisher's `auto.js` that nothing requires, no hook runs and no entry
names publishes only when its owner runs it (review 98 G6: 35 benign units blocked on it alone; its
six labelled spam siblings adjudicated clause (c), no consumer payload). Outside a published
package -- a source tree, an installed `node_modules` -- nothing is lowered: entry points are not
known there.

One exception, by the owner's decision (1 Nov, release item 57; notes/57-self-propagating-publish.md):
a script that rewrites its own package's identity and republishes it in a loop is registry
self-propagation, and it blocks although only a person runs it. Keyed on what the file does, read from
its own tokens, never on its name: a write to its own package.json, a rename of its package (release
tooling bumps versions but never renames, so the version alone is not it), and a loop or timer, beside
the publish the rule matched.
Measured on a3b9c5f1's rows: 410 content-miss malware units in 81 layout groups, 12 benign of 24,685;
the loop condition removed 7 benign and no malware. Option A stands for every other person-run script.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.dependencies import EcosystemFactsProvider

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext


class PublishReach:
    RULE: ClassVar[str] = "SUSPECT.REGISTRY.SELF_PUBLISH.001"
    REASON: ClassVar[str] = "a publishing script nothing installs or loads"
    SELF_PROPAGATING: ClassVar[str] = (
        "it renames its own package in package.json and republishes it in a loop: "
        "it runs only when a person runs it, and then republishes this package under new identities "
        "from their registry account"
    )
    _WRITES: ClassVar[frozenset[str]] = frozenset(
        {"writeFileSync", "writeFile", "outputJson", "outputJsonSync", "writeJson", "writeJsonSync"}
    )
    _LOOPS: ClassVar[frozenset[str]] = frozenset({"for", "while", "setInterval", "setTimeout"})

    @staticmethod
    def unreached(rule_id: str, path: str, ctx: ScanContext) -> bool:
        """Whether this is the publishing rule, in a published npm package's file that no install
        hook, entry point or entry's import runs."""
        if (
            rule_id != PublishReach.RULE
            or not ctx.package_distribution
            or not EcosystemFactsProvider.published().hooks_run_javascript(ctx.distribution)
        ):
            return False
        return not (
            ctx.in_install_hook(path)
            or path in ctx.library_entry_paths
            or path in ctx.library_closure_paths
        )

    @classmethod
    def self_propagating(cls, text: str) -> bool:
        """Whether the file writes its own package.json and RENAMES its package (release tooling bumps
        versions, it never renames: outer-layer review), with a loop or timer: the self-propagation
        shape, from the file's tokens by co-presence. The rename is of the manifest's own variable --
        one assigned from `JSON.parse(...)` or `require(...package.json...)` in the file -- so a class
        property (`this.name = name`) or an error's name is not it: `m.name =`, `m['name'] =`,
        `Object.assign(m, {name: ...})`, or a rebuild `{...m, name: ...}`."""
        from cordon_scanner.analysis.javascript.js_eval import JsEval

        if "package.json" not in text:
            return False
        tokens = JsEval.tokens(text, templates=True)
        manifests = cls._manifest_names(tokens)
        if not manifests:
            return False
        manifest = writes = loops = renamed = False
        for i, tok in enumerate(tokens):
            value = str(tok.value)
            if tok.kind == "str" and "package.json" in value:
                manifest = True
            elif tok.kind == "name" and value in cls._WRITES:
                writes = True
            elif tok.kind == "name" and value in cls._LOOPS:
                loops = True
            if not renamed and value == "name" and tok.kind in ("name", "str"):
                renamed = cls._renames_at(tokens, i, manifests)
        return manifest and writes and loops and renamed

    @staticmethod
    def _manifest_names(tokens: list[Any]) -> frozenset[str]:
        """Names assigned from `JSON.parse(` or `require(` naming package.json: `const m = JSON.parse(`."""
        out: set[str] = set()
        for i in range(len(tokens) - 3):
            name, eq = tokens[i], tokens[i + 1]
            if name.kind != "name" or eq.kind != "punct" or eq.value != "=":
                continue
            ahead = [str(t.value) for t in tokens[i + 2 : i + 8]]
            parsed = ahead[:2] == ["JSON", "."] and "parse" in ahead
            required = ahead[:1] == ["require"] and any("package.json" in a for a in ahead)
            if parsed or required:
                out.add(str(name.value))
        return frozenset(out)

    @staticmethod
    def _renames_at(tokens: list[Any], i: int, manifests: frozenset[str]) -> bool:
        """Whether the `name` token at `i` renames a manifest variable."""

        def punct(j: int, *values: str) -> bool:
            return 0 <= j < len(tokens) and tokens[j].kind == "punct" and tokens[j].value in values

        def manifest_at(j: int) -> bool:
            return (
                0 <= j < len(tokens)
                and tokens[j].kind == "name"
                and str(tokens[j].value) in manifests
            )

        tok = tokens[i]
        if (
            tok.kind == "name"
            and punct(i - 1, ".")
            and manifest_at(i - 2)
            and punct(i + 1, "=", "+=")
        ):
            return True
        if (
            tok.kind == "str"
            and punct(i - 1, "[")
            and manifest_at(i - 2)
            and punct(i + 1, "]")
            and punct(i + 2, "=", "+=")
        ):
            return True
        if punct(i + 1, ":") and punct(i - 1, "{", ","):
            # An object key: Object.assign(<manifest>, {name}) or {...<manifest>, name}.
            window = tokens[max(0, i - 12) : i]
            values = [str(t.value) for t in window]
            spread = any(
                values[j] == "..." and str(window[j + 1].value) in manifests
                for j in range(len(values) - 1)
            )
            assigned = "assign" in values and any(str(t.value) in manifests for t in window)
            return spread or assigned
        return False
