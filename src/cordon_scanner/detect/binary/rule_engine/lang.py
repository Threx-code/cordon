"""cordon-rule: rule files compiled and matched by Cordon's own code.

`--rule-file` matches every file against a rule file: Cordon's own pack, or an operator's. A native
library reading attacker-supplied bytes is the attack surface this project refuses, so the engine is
Cordon's own, in four parts:

- `rule_engine.syntax` reads rule text into rules whose conditions are trees;
- `rule_engine.scan` (with `rule_engine.pattern`) finds every string's matches in a file;
- `rule_engine.build` checks each condition against the modules' declared types and builds it into
  closures, once;
- this module ties them together: `Rules.compile(text)`, then `rules.match(data)`.

The language it reads, and what each part means, is documented for operators in
`tutorials/31-rule-files.md`; the conformance suite (`tests/unit/detect/binary/rule_engine/test_lang.py`)
and the differentials over generated rules hold the engine to it.

No file can make a scan unbounded: a string records at most `MAX_MATCHES` matches, a pattern
never reads more than `rule_engine.threads.REACH` bytes past where a run of it starts, and the search
gives up at the deadline `match` is given.
"""

from __future__ import annotations

import binascii
import dataclasses
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.builtin import Builtin
from cordon_scanner.detect.binary.modules.values import Module
from cordon_scanner.detect.binary.rule_engine.build import Builder, Frame
from cordon_scanner.detect.binary.rule_engine.syntax import (
    Both,
    Either,
    Found,
    Grammar,
    Invoke,
    Literal,
    Members,
    Node,
    Of,
    RuleDef,
    RuleError,
    StringDef,
)

MAX_MATCHES = 1_000_000


@dataclass
class Match:
    """What a matching rule reports: its name, tags, meta, and each string instance."""

    rule: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[tuple[int, str, bytes]]


class Tree:
    """Walks over condition trees."""

    @staticmethod
    def parts(node: Any) -> Iterator[Any]:
        """Everything directly inside `node`: nodes, steps, lists and names."""
        if dataclasses.is_dataclass(node) and not isinstance(node, type):
            for f in dataclasses.fields(node):
                yield getattr(node, f.name)
        elif isinstance(node, (list, tuple)):
            yield from node

    @staticmethod
    def calls(node: Any) -> bool:
        """Whether running `node` calls a module function (which may do something, as
        `console.log` does)."""
        if isinstance(node, Invoke):
            return True
        return any(Tree.calls(p) for p in Tree.parts(node))

    @staticmethod
    def needs_match(node: Node) -> bool:
        """Whether `node` is false whenever no string of the rule has a match: a string found,
        `at` or `in`, or `any`/`all`/a literal number of at least 1 of a set of strings; `and` when
        either side needs one, `or` when both do. Anything else -- a count, a loop, `none of`, a
        percentage, a quantity read from the file -- may be true without a match."""
        if isinstance(node, Found):
            return True
        if isinstance(node, Both):
            return Tree.needs_match(node.left) or Tree.needs_match(node.right)
        if isinstance(node, Either):
            return Tree.needs_match(node.left) and Tree.needs_match(node.right)
        if isinstance(node, Of):
            names = node.members.names
            strings = names is None or all(n.startswith("$") for n in names)
            q = node.quantity
            amount = q.amount.value if isinstance(q.amount, Literal) else None
            some = q.word in ("any", "all") or (
                type(amount) is int and amount >= 1 and q.word is None
            )
            return strings and some
        return False


class Strings:
    """The rules' strings: each made ready to search for, then searched for in a file, and
    placed where a condition fixes them."""

    @staticmethod
    def prepare(rules: list[RuleDef]) -> None:
        from cordon_scanner.detect.binary.rule_engine.pattern import PatternError
        from cordon_scanner.detect.binary.rule_engine.scan import Search

        for s in (s for rule in rules for s in rule.strings):
            try:
                s.search = Search(s.kind, s.value, s.modifiers)
            except PatternError as exc:
                raise RuleError(f"string {s.name}: {exc}") from exc

    @staticmethod
    def search(
        s: StringDef, data: bytes, deadline: float | None, seen: dict[Any, Any]
    ) -> list[tuple[int, int]]:
        """Where `s` matches in `data`, as (offset, length) pairs in offset order. Running out of
        time, or a pattern needing more than its bounds allow, refuses the file."""
        from cordon_scanner.detect.binary.rule_engine.pattern import RunError

        why: str | None = None
        cause: BaseException | None = None
        try:
            hits: list[tuple[int, int]] = s.search.find(data, s.fixed, deadline, seen)
        except TimeoutError as exc:
            why, cause = "matching took longer than the time allowed", exc
        except RunError as exc:
            why, cause = f"string {s.name}: {exc}", exc
        if why is not None:
            raise RuleError(why) from cause
        return hits

    @staticmethod
    def place(rule: RuleDef) -> None:
        """Marks each string whose first part is plain bytes and whose every use is `$a at
        <constant>` (one constant): it counts only there, as the search records it only there."""
        names = [s.name for s in rule.strings]
        where: dict[str, int | None] = dict.fromkeys(names)
        loose: set[str] = set()

        def fix(name: str, at: Node) -> None:
            value = at.value if isinstance(at, Literal) and type(at.value) is int else None
            for n in names if name == "$" else [name]:
                if n not in where:
                    continue
                if where[n] is None:
                    where[n] = value
                if value is None or where[n] != value:
                    loose.add(n)

        def name_used(name: str) -> None:
            if name == "$":
                loose.update(names)
            elif name.endswith("*"):
                loose.update(n for n in names if n.startswith(name[:-1]))
            else:
                loose.add(name)

        def visit(node: Any) -> None:
            if isinstance(node, Found) and node.at is not None:
                fix(node.string, node.at)
                visit(node.at)
                return
            if isinstance(node, Members) and node.names is None:
                loose.update(names)
                return
            if isinstance(node, str):
                if node.startswith("$"):
                    name_used(node)
                return
            for part in Tree.parts(node):
                visit(part)

        visit(rule.condition)
        for s in rule.strings:
            # a string of linked parts counts from its first, so that part decides
            plain = s.search is not None and s.search.parts[0].text is not None
            if plain and s.name not in loose and where[s.name] is not None:
                s.fixed = where[s.name]


class Rules:
    """Compiled rules: `Rules.compile(text)`, then `rules.match(data)`."""

    #: The built-in modules, loaded once.
    BUILT_IN: ClassVar[dict[str, Module]] = {}

    def __init__(self, rules: list[RuleDef], modules: dict[str, Module]) -> None:
        self.rules, self.modules = rules, modules
        self._index: tuple[Any, list[StringDef]] | None = None

    @staticmethod
    def loaded(given: dict[str, Any] | None) -> dict[str, Module]:
        if not Rules.BUILT_IN:
            Rules.BUILT_IN.update(Builtin.modules())
        return {**Rules.BUILT_IN, **(given or {})}

    @staticmethod
    def compile(
        text: str, externals: dict[str, Any] | None = None, modules: dict[str, Any] | None = None
    ) -> Rules:
        """`modules` adds modules (`modules.values.Module`s) to the built-in ones."""
        loaded = Rules.loaded(modules)
        given = dict(externals or {})
        try:
            rules = Grammar(text, given, frozenset(loaded)).read()
            Strings.prepare(rules)
        except (IndexError, ValueError, binascii.Error) as exc:
            if isinstance(exc, RuleError):
                raise
            raise RuleError(f"the rules do not parse: {exc}") from exc
        try:
            Builder(rules, loaded, given).build()
        except RuleError:
            raise
        except (ValueError, TypeError, IndexError, KeyError, OverflowError) as exc:
            raise RuleError(f"the rules do not compile: {type(exc).__name__}: {exc}") from exc
        for rule in rules:
            rule.needs_match = (
                bool(rule.strings)
                and Tree.needs_match(rule.condition)
                and not Tree.calls(rule.condition)
            )
            Strings.place(rule)
        return Rules(rules, loaded)

    def index(self) -> tuple[Any, list[StringDef]]:
        """One index of every string's anchors, built once for the rule set."""
        if self._index is None:
            from cordon_scanner.detect.binary.rule_engine.scan import AnchorIndex

            strings = [s for r in self.rules for s in r.strings]
            self._index = (AnchorIndex([s.search for s in strings]), strings)
        return self._index

    def match(
        self, data: bytes, timeout: float | None = None, console: Callable[[str], Any] | None = None
    ) -> list[Match]:
        """The rules `data` matches; a `RuleError` once `timeout` seconds have passed. `console`
        receives each `console.log`/`console.hex` message."""
        deadline = time.monotonic() + timeout if timeout is not None else None
        modules = self.modules
        if console is not None:
            modules = {**modules, "console": Builtin.console(console)}
        frame = Frame(data, modules)
        seen: dict[Any, Any] = {}
        index, strings = self.index()
        live = {id(strings[i]) for i in index.live(data, seen)}
        found_by: dict[str, dict[str, list[tuple[int, int]]]] = {}
        all_global = True
        for rule in self.rules:
            found = {
                s.name: Strings.search(s, data, deadline, seen) if id(s) in live else []
                for s in rule.strings
            }
            found_by[rule.name] = frame.found = found
            if rule.needs_match and not any(found.values()):
                result = False
            else:
                frame.env = [None] * rule.width
                result = rule.run(frame)
            frame.decided[rule.name] = result
            if rule.is_global and not result:
                all_global = False
        out: list[Match] = []
        if not all_global:
            return out
        for rule in self.rules:
            if not frame.decided[rule.name] or rule.private:
                continue
            instances = [
                (at, s.name, data[at : at + n])
                for s in rule.strings
                if not s.private
                for at, n in found_by[rule.name][s.name]
            ]
            out.append(Match(rule.name, list(rule.tags), dict(rule.meta), instances))
        return out


__all__ = ["Match", "RuleError", "Rules"]
