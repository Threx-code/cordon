"""Cross-file flow from per-file summaries (programme 3C, release item 60, notes/60-cross-file-flow.md).

A worker reads one file and states, symbolically, what its exports do with their parameters and what
it hands to the package's other modules; the parent joins those statements across the require graph
with set arithmetic, never reading a file (item 56's rule):

```
  WORKER  JsFlow.summaries(text)                   PARENT  CrossFile.compose(files, tree)
  ───────────────────────────                      ─────────────────────────────────────────
  js.export   [name, params]                       callouts resolved to (file, export) by path
  js.summary  [name, from, to]                     fixpoint over summaries and callouts:
     from: "P<i>" | a source kind | "C<k>"            labels L into B.f's P<i> -> sink  ⇒ a flow
     to:   "return" | "sink:<kind>:<dest>" | "data:<kind>:<dest>" (a data argument)            B.f returns S, A's C<k> reaches a sink ⇒ a flow
  js.callout  [module, name, i, labels, line,          a P<j> of A's export g in L ⇒ g's summary grows
               caller, "C<k>"]
  js.callsink ["C<k>", kind, dest, line]           each flow: (caller file, line, sources, sink, dest)
```

Bounded: the per-file caps below, labels from the declared vocabulary (source kinds, P<0..63>, C<k>),
a destination is its class (drop, ip, fixed, unknown), never a host; the fixpoint stops at MAX_ROUNDS.
A dynamic require or computed export name gives no edge (rule 3: no flow is invented).
"""

from __future__ import annotations

import posixpath
import re
from typing import Any, ClassVar

from cordon_scanner.analysis.javascript.flow.vocabulary import SOURCES


class JsSummaries:
    """The worker's half: one file's exports, their summaries, and its calls into local modules."""

    MAX_EXPORTS: ClassVar[int] = 256
    MAX_CALLOUTS: ClassVar[int] = 2048
    MAX_LABELS: ClassVar[int] = 16
    MAX_PARAM: ClassVar[int] = 63

    #: At most this many summaries and call-site sinks a file sends: with MAX_EXPORTS and the callouts'
    #: cap (each call adds at most 8), a file's set stays under the channel's FILE_COUNT.
    MAX_SUMMARIES: ClassVar[int] = 4096
    MAX_CALLSINKS: ClassVar[int] = 2048
    MAX_REEXPORTS: ClassVar[int] = 64
    KINDS: ClassVar[tuple[str, ...]] = (
        "js.export",
        "js.summary",
        "js.callout",
        "js.callsink",
        "js.reexport",
        "js.require",
    )
    #: The `js.require` fact of a file whose calls into the package are not all known: a module
    #: named by a computed value (`require("./" + name)`, `import(x)`), or a file the analysis could
    #: not read whole. Composition is incomplete wherever one is (rule 3), and what needs it to be
    #: complete -- note 78's lowering -- is withdrawn.
    UNRESOLVED: ClassVar[str] = "dynamic"
    #: The `js.require` fact of a file past the analysis's size limit that reaches no other file: no
    #: local or computed require or import anywhere in its whole text (`reaches_out`). Composition is
    #: incomplete only if another file calls into it or re-exports it (`CrossFileJoin.unresolved`): a
    #: 5 MB generated protobuf module made every Baileys release unknown (note 78's pair).
    UNREAD: ClassVar[str] = "unread"
    #: A require or import of a local path, or of anything but one literal; an ES import or re-export
    #: from a local path. Read over the whole text, linearly: one bounded alternative per position.
    _REACHES_OUT: ClassVar[re.Pattern[str]] = re.compile(
        r"""\b(?:require|import)\s{0,64}\(\s{0,64}(?:['"](?:\.{1,2}/|/)|[^'"\s)])"""
        r"""|\bfrom\s{0,64}['"](?:\.{1,2}/|/)|\bimport\s{0,64}['"](?:\.{1,2}/|/)"""
    )

    @classmethod
    def reaches_out(cls, text: str) -> bool:
        """Whether a file calls into, or loads, any other file by a local or a computed name."""
        return cls._REACHES_OUT.search(text) is not None

    @classmethod
    def shared(cls, a: Any) -> dict[str, list[Any]]:
        """`facts` from an analysis another caller ran, under the same guard."""
        from cordon_scanner.analysis.javascript.flow.vocabulary import _OverBudget

        try:
            return cls.joined(cls.of_analysis(a))
        except (RecursionError, _OverBudget, IndexError, KeyError, ValueError, TypeError):
            # S2: unresolved, not empty; an unresolved require keeps the join incomplete
            return {"js.require": [cls.UNRESOLVED]}

    @classmethod
    def joined(cls, facts: dict[str, list[Any]]) -> dict[str, list[Any]]:
        """`facts`, or nothing when they join no file to another."""
        if not any(facts.get(k) for k in ("js.summary", "js.callout", "js.reexport", "js.require")):
            return {}
        return {k: v for k, v in facts.items() if v}

    @classmethod
    def of_analysis(cls, a: Any) -> dict[str, list[Any]]:
        """The facts of a file whose analysis has run (`JsFlow._flows` shares its own)."""
        exports = cls._exports(a)
        by_fid = {fid: name for name, fid in exports.items() if fid}
        out: dict[str, list[Any]] = {
            "js.export": [],
            "js.summary": [],
            "js.callout": [],
            "js.callsink": [],
            "js.reexport": [[m] for m in cls._reexports(a)][: cls.MAX_REEXPORTS],
            "js.require": [cls.UNRESOLVED] if cls._computed_require(a) else [],
        }
        for name, fid in list(exports.items())[: cls.MAX_EXPORTS]:
            fn = a.fns[fid - 1] if fid else None
            out["js.export"].append([name, len(fn.params) if fn else 0])
            if fn is not None:
                room = cls.MAX_SUMMARIES - len(out["js.summary"])
                out["js.summary"].extend(cls._summary(name, fn)[: max(room, 0)])
        for k in range(a.n - 1):
            if len(out["js.callout"]) >= cls.MAX_CALLOUTS:
                break
            if not (a.t[k].kind == "name" and a.is_p(k + 1, "(") and a.match[k + 1] > 0):
                continue
            callee = a.local_callee(k)
            if callee is None:
                continue
            module, export = callee
            if not module or not export:
                continue  # a call into a module by no name the join can match: no edge (rule 3)
            scope = a.scope_of(k)
            caller = by_fid.get(scope, "")
            args = a._args(k + 1) or []
            for i, (s, e) in enumerate(args[:8] or [(k, k)]):
                labels = cls._labels(a.taint(s, e, scope), scope if caller else 0) if args else []
                out["js.callout"].append(
                    [module, export, i if args else -1, labels, a.line(k), caller, f"C{k}"]
                )
        for k, sinks in a.c_sinks.items():
            for sink, _host, dest, line in sorted(sinks, key=lambda x: (x[3], x[0])):
                if len(out["js.callsink"]) < cls.MAX_CALLSINKS:
                    out["js.callsink"].append([f"C{k}", sink, dest, line])
        return out

    @staticmethod
    def _kind(label: Any) -> str:
        """A label's kind: a source kind is its own; a symbolic label is tagged ("P", "Q", "R", "C")."""
        return label if isinstance(label, str) else str(label[0])

    @classmethod
    def _name(cls, label: Any, fid: int) -> str | None:
        """A label's name in the declared vocabulary, or None: source kinds, the parameters of the
        function `fid` (P<i>), and local call results (C<k>). Dispatched on the label's kind by a
        table, so a new kind is a new entry (the isinstance_chains rule)."""
        kind = cls._kind(label)
        if kind in SOURCES:
            return kind
        name = cls._NAMES.get(kind)
        return name(label, fid, cls.MAX_PARAM) if name is not None else None

    @staticmethod
    def _parameter(label: Any, fid: int, most: int) -> str | None:
        return f"P{label[2]}" if fid and label[1] == fid and label[2] <= most else None

    @staticmethod
    def _call(label: Any, _fid: int, _most: int) -> str | None:
        return f"C{label[1]}"

    _NAMES: ClassVar[dict[str, Any]] = {}

    @classmethod
    def _labels(cls, value: set[Any], fid: int) -> list[str]:
        """A value's labels in the declared vocabulary (`_name`), at most MAX_LABELS."""
        names = {cls._name(x, fid) for x in value}
        return sorted(n for n in names if n is not None)[: cls.MAX_LABELS]

    @classmethod
    def _summary(cls, name: str, fn: Any) -> list[list[Any]]:
        out: list[list[Any]] = []
        # A DATA_ARGS spawn's data argument (note 69) is its own kind, `data:`: the join strips what a
        # server sent or a blob decoded from it, as the same-file call site does (`Calls`), so a
        # cross-file flow is judged exactly as a same-file one (note 60, rule 5).
        for kind, items in (("sink", fn.sinks.items()), ("data", fn.data_sinks.items())):
            for (how, idx), sinks in items:
                if how == "R":
                    continue  # a file read at a parameter's path: judged where the path is known
                position = idx[0] if how == "Q" else idx  # a field of the parameter: the parameter
                if position > cls.MAX_PARAM:
                    continue
                for sink, _host, dest, _line in sinks:
                    out.append([name, f"P{position}", f"{kind}:{sink}:{dest}"])
        for label in fn.ret:
            frm = cls._name(label, fn.fid)
            if frm is not None:
                out.append([name, frm, "return"])
        return sorted({tuple(x): x for x in out}.values())

    @staticmethod
    def _computed_require(a: Any) -> bool:
        """Whether a `require(...)` or `import(...)` names its module by anything but one literal."""
        for i in range(a.n - 2):
            if not (a.is_name(i, "require") or a.is_name(i, "import")) or not a.is_p(i + 1, "("):
                continue
            if a.is_p(i - 1, ".") or a.match[i + 1] <= 0:
                continue  # a method of that name (`x.require(...)`), or an unclosed call
            if not (a.match[i + 1] == i + 3 and a.t[i + 2].kind == "str"):
                return True
        return False

    @staticmethod
    def _reexports(a: Any) -> list[str]:
        """Modules whose exports this file hands on whole: `module.exports = require("./c")`,
        `export * from "./c"`, `export {x} from "./c"`. Local paths only."""
        t, out = a.t, []
        for i in range(a.n - 4):
            if (
                a.is_name(i, "module")
                and a.is_p(i + 1, ".")
                and a.is_name(i + 2, "exports")
                and a.is_p(i + 3, "=")
                and a.is_name(i + 4, "require")
                and a.is_p(i + 5, "(")
                and i + 6 < a.n
                and t[i + 6].kind == "str"
            ):
                out.append(str(t[i + 6].value))
            elif a.is_name(i, "export") and (a.is_p(i + 1, "*") or a.is_p(i + 1, "{")):
                k = a.match[i + 1] + 1 if a.is_p(i + 1, "{") and a.match[i + 1] > 0 else i + 2
                if a.is_name(k, "from") and k + 1 < a.n and t[k + 1].kind == "str":
                    out.append(str(t[k + 1].value))
        return [m for m in out if m.startswith(("./", "../", "/"))]

    @classmethod
    def _exports(cls, a: Any) -> dict[str, int]:
        """Export name -> the function it names (0 when not a function this file defines):
        `module.exports.x = ...`, `exports.x = ...`, `module.exports = f` or `= {a, b: c}`,
        `export function x`, `export const x = ...`, `export default ...`."""
        t, out = a.t, {}

        def fn_at(s: int) -> int:
            fid = a.fn_at_token.get(s) or (
                a.fn_at_token.get(s + 1) if a.is_name(s, "async") else None
            )
            if fid:
                return int(fid)
            if a.is_name(s) and not a.is_p(s + 1, "("):
                return int(a.fn_by_name.get(a.resolve(str(t[s].value), a.scope_of(s)), 0))
            return 0

        for i in range(a.n - 3):
            if a.is_name(i, "module") and a.is_p(i + 1, ".") and a.is_name(i + 2, "exports"):
                j = i + 3
            elif a.is_name(i, "exports") and not a.is_p(i - 1, "."):
                j = i + 1
            else:
                j = -1
            if j >= 0:
                if a.is_p(j, ".") and a.is_name(j + 1) and a.is_p(j + 2, "="):
                    out[str(t[j + 1].value)] = fn_at(j + 3)
                elif a.is_p(j, "=") and a.is_p(j + 1, "{") and a.match[j + 1] > 0:
                    entries = a.literal_entries(j + 1, a.match[j + 1] + 1) or []
                    for key, vs, _ve in entries:
                        out[key] = fn_at(vs)
                elif a.is_p(j, "="):
                    out["default"] = fn_at(j + 1)
            if a.is_name(i, "export"):
                if a.is_name(i + 1, "default"):
                    out["default"] = fn_at(i + 2)
                elif a.is_name(i + 1, "function") and a.is_name(i + 2):
                    out[str(t[i + 2].value)] = fn_at(i + 1)
                elif (
                    a.is_name(i + 1, "async") and a.is_name(i + 2, "function") and a.is_name(i + 3)
                ):
                    out[str(t[i + 3].value)] = fn_at(i + 1)
                elif (
                    a.is_name(i + 1)
                    and str(t[i + 1].value) in ("const", "let", "var")
                    and a.is_name(i + 2)
                    and a.is_p(i + 3, "=")
                ):
                    out[str(t[i + 2].value)] = fn_at(i + 4)
        return out


class CrossFile:
    """The parent's half: per-file facts joined across the package's require graph."""

    MAX_ROUNDS: ClassVar[int] = 8
    #: What a data argument does not carry as code (`Calls._CODE_LABELS`): a reply or a decoded blob.
    CODE_LABELS: ClassVar[frozenset[str]] = frozenset({"network_response", "decoded"})
    _EXTENSIONS: ClassVar[tuple[str, ...]] = ("", ".js", ".cjs", ".mjs", ".ts", "/index.js")

    @classmethod
    def resolve(cls, module: str, from_path: str, tree: frozenset[str]) -> str | None:
        """A relative require's file in the tree, by Node's resolution of a path: the name, then with
        an extension, then its directory's index.js. None outside the tree."""
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), module))
        for ext in cls._EXTENSIONS:
            if base + ext in tree:
                return base + ext
        return None

    @classmethod
    def compose(
        cls, files: dict[str, dict[str, list[Any]]], tree: frozenset[str]
    ) -> list[tuple[str, int, tuple[str, ...], str, str]]:
        """Every cross-file flow: (caller file, line, source kinds, sink, destination class)."""
        summaries: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for path, facts in files.items():
            for name, frm, to in facts.get("js.summary", ()):
                summaries.setdefault((path, str(name)), set()).add((str(frm), str(to)))
        # (caller file, C<k>) -> what the call's result carries, from the callee's summaries.
        results: dict[tuple[str, str], set[str]] = {}
        flows: set[tuple[str, int, tuple[str, ...], str, str]] = set()
        for _ in range(cls.MAX_ROUNDS):
            changed = False
            for path, facts in files.items():
                for module, name, i, labels, line, caller, cid in facts.get("js.callout", ()):
                    target = cls._exporter(str(module), str(name), path, tree, files, summaries)
                    if target is None:
                        continue
                    held = set(labels) | set().union(
                        *(results.get((path, lab), set()) for lab in labels if lab.startswith("C"))
                    )
                    for frm, to in sorted(summaries.get((target, str(name)), ())):
                        if frm == f"P{i}" and to.startswith(("sink:", "data:")):
                            how, sink, dest = to.split(":", 2)
                            strip = cls.CODE_LABELS if how == "data" else frozenset()
                            concrete = tuple(sorted({x for x in held if x in SOURCES} - strip))
                            if concrete:
                                flows.add((path, int(line), concrete, sink, dest))
                            for p in (x for x in held if x.startswith("P") and caller):
                                changed |= cls._grow(summaries, (path, str(caller)), (p, to))
                        elif to == "return" and (frm == f"P{i}" or frm in SOURCES):
                            carried = held if frm == f"P{i}" else {frm}
                            before = len(results.get((path, str(cid)), set()))
                            results.setdefault((path, str(cid)), set()).update(carried)
                            changed |= len(results[(path, str(cid))]) != before
            for path, facts in files.items():
                for cid, sink, dest, line in facts.get("js.callsink", ()):
                    concrete = tuple(
                        sorted({x for x in results.get((path, str(cid)), ()) if x in SOURCES})
                    )
                    if concrete:
                        flows.add((path, int(line), concrete, str(sink), str(dest)))
                for name, frm, to in facts.get("js.summary", ()):
                    if str(frm).startswith("C") and to == "return":
                        for lab in results.get((path, str(frm)), ()):
                            changed |= cls._grow(summaries, (path, str(name)), (lab, "return"))
            if not changed:
                break
        # Each flow is (file, line, sorted source kinds, sink, destination): plain tuples of strings and
        # an int, so their natural order is total (test_total_sorts).
        return sorted(flows)

    @classmethod
    def _exporter(
        cls,
        module: str,
        name: str,
        from_path: str,
        tree: frozenset[str],
        files: dict[str, dict[str, list[Any]]],
        summaries: dict[tuple[str, str], set[tuple[str, str]]],
    ) -> str | None:
        """The file whose summary answers for `name` from `module`: the module itself, or the module it
        re-exports, followed at most four levels."""
        target = cls.resolve(module, from_path, tree)
        for _ in range(4):
            if target is None or (target, name) in summaries:
                return target
            onward = files.get(target, {}).get("js.reexport", ())
            if not onward:
                return target
            target = cls.resolve(str(onward[0][0]), target, tree)
        return target

    @staticmethod
    def _grow(
        summaries: dict[tuple[str, str], set[tuple[str, str]]],
        key: tuple[str, str],
        entry: tuple[str, str],
    ) -> bool:
        held = summaries.setdefault(key, set())
        if entry in held:
            return False
        held.add(entry)
        return True


JsSummaries._NAMES.update(
    {"P": JsSummaries._parameter, "Q": JsSummaries._parameter, "C": JsSummaries._call}
)

__all__ = ["CrossFile", "JsSummaries"]
