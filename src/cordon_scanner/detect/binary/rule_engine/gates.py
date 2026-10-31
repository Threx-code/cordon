"""What a rule needs before its strings are searched, so a rule that cannot hold costs no search.

Two kinds, both read from the condition when it is compiled, both exact (a gated rule's result is the
one running it would give):

- **Conjunct gates.** The condition's top-level `and` parts that read no string: a module's value, an
  integer read from the file, `filesize`, another rule. Each is run first; one that is false (or
  undefined) makes the rule false, since `x and y` is false when `x` is.
- **Required strings.** Clauses, each a set of strings at least one of which must match for the
  condition to hold: `$a`, `$a at`/`in`, `any of`/`n of` (n at least 1) give one clause; `all of` one per
  string; `and` the clauses of both sides; `or` one clause, the smallest of each side together. A
  clause none of whose strings has an anchor in the file is false at once; the rest are searched with
  the clause of fewest live strings first, and the first clause found empty ends the rule's search.

A rule whose condition reaches `console` is never gated: its messages are part of its result.

- **Magic.** A gate that compares an integer read at offset 0 with a constant (`uint16(0) == 0x5A4D`)
  is false on every file whose leading bytes differ, so that rule's anchors are not looked for in such
  a file at all (`MagicIndex`): the anchor index is built per set of leading-byte requirements a file
  meets, once each, and holds only the strings of rules whose requirements it meets.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.detect.binary.rule_engine.syntax import (
    Both,
    Compare,
    Count,
    EachString,
    Either,
    Found,
    Literal,
    Node,
    Of,
    Path,
    Place,
    Read,
    RuleDef,
)

Magic = tuple[int, bool, bool, int]
"""A leading-bytes requirement: the read's width, whether big-endian, whether signed, the value."""


class Gates:
    @staticmethod
    def parts(node: Any) -> list[Any]:
        from cordon_scanner.detect.binary.rule_engine.lang import Tree

        return list(Tree.parts(node))

    @staticmethod
    def reaches(node: Any, test: Callable[[Any], bool]) -> bool:
        stack = [node]
        while stack:
            n = stack.pop()
            if test(n):
                return True
            stack.extend(Gates.parts(n))
        return False

    @staticmethod
    def reads_strings(node: Any) -> bool:
        def strings(n: Any) -> bool:
            if isinstance(n, (Found, Count, Place, EachString)):
                return True
            return isinstance(n, Of) and (
                n.members.names is None or any(m.startswith("$") for m in n.members.names)
            )

        return Gates.reaches(node, strings)

    @staticmethod
    def console(node: Any) -> bool:
        return Gates.reaches(
            node, lambda n: isinstance(n, Path) and n.module and n.root == "console"
        )

    @staticmethod
    def conjuncts(node: Node) -> list[Node]:
        out, stack = [], [node]
        while stack:
            n = stack.pop()
            if isinstance(n, Both):
                stack += [n.right, n.left]
            else:
                out.append(n)
        return out

    @staticmethod
    def clauses(node: Node, names: list[str]) -> list[frozenset[str]]:
        """The required-string clauses of `node` (empty: nothing is required)."""
        if isinstance(node, Found):
            return [frozenset({node.string})]
        if isinstance(node, Both):
            return Gates.clauses(node.left, names) + Gates.clauses(node.right, names)
        if isinstance(node, Either):
            left, right = Gates.clauses(node.left, names), Gates.clauses(node.right, names)
            if not left or not right:
                return []
            return [min(left, key=len) | min(right, key=len)]
        if isinstance(node, Of):
            members = Gates.members(node, names)
            if members is None or node.quantity.percent:
                return []
            q = node.quantity
            amount = q.amount.value if isinstance(q.amount, Literal) else None
            if q.word == "all":
                return [frozenset({m}) for m in members]
            if q.word == "any" or (q.word is None and type(amount) is int and amount >= 1):
                return [frozenset(members)] if members else []
        return []

    @staticmethod
    def members(node: Of, names: list[str]) -> list[str] | None:
        """The strings an `of` names, or None where it names rules."""
        if node.members.names is None:
            return list(names)
        out: list[str] = []
        for m in node.members.names:
            if not m.startswith("$"):
                return None
            out += [n for n in names if n.startswith(m[:-1])] if m.endswith("*") else [m]
        return out

    @staticmethod
    def prepare(rule: RuleDef, build: Callable[[Node], Callable[[Any], bool]]) -> None:
        """The rule's gates and clauses; `build` compiles a part of its condition into a test."""
        if not rule.strings or Gates.console(rule.condition):
            return
        names = [s.name for s in rule.strings]
        parts = Gates.conjuncts(rule.condition)
        rule.gates = (
            [build(p) for p in parts if not Gates.reads_strings(p)] if len(parts) > 1 else []
        )
        rule.clauses = [c for c in Gates.clauses(rule.condition, names) if c <= set(names)]
        rule.magic = frozenset(m for p in parts if rule.gates and (m := Gates.magic(p)) is not None)

    @staticmethod
    def magic(node: Node) -> Magic | None:
        """The requirement `node` states on the file's first bytes, where it is `read(0) == constant`."""
        if not isinstance(node, Compare) or node.op != "==":
            return None
        for read, value in ((node.left, node.right), (node.right, node.left)):
            if (
                isinstance(read, Read) and isinstance(read.at, Literal) and read.at.value == 0
                and isinstance(value, Literal) and type(value.value) is int
            ):  # fmt: skip
                return (read.width, read.big, read.signed, value.value)
        return None

    @staticmethod
    def hopeless(rule: RuleDef, live: set[int]) -> bool:
        """Whether the rule is false without running anything: a clause with no string whose anchor
        occurs, or a condition that needs a match when no string can have one. Checked before the
        gates, which cost a module's values."""
        if not rule.strings or not (rule.clauses or rule.needs_match):
            return False
        alive = {s.name for s in rule.strings if id(s) in live}
        return (rule.needs_match and not alive) or any(c.isdisjoint(alive) for c in rule.clauses)

    @staticmethod
    def search(
        rule: RuleDef, live: set[int], find: Callable[[Any], list[tuple[int, int]]]
    ) -> tuple[dict[str, list[tuple[int, int]]], bool]:
        """The rule's strings searched as its clauses allow: (what was found, whether the rule may
        hold). A string not searched is reported as no match."""
        alive = {s.name for s in rule.strings if id(s) in live}
        if any(clause.isdisjoint(alive) for clause in rule.clauses):
            return {s.name: [] for s in rule.strings}, False
        found: dict[str, list[tuple[int, int]]] = {
            s.name: [] for s in rule.strings if s.name not in alive
        }
        if rule.clauses:
            by_name = {s.name: s for s in rule.strings}
            for clause in sorted(rule.clauses, key=lambda c: len(c & alive)):
                hit = False
                for name in clause & alive:
                    if name not in found:
                        found[name] = find(by_name[name])
                    if found[name]:
                        hit = True
                        break
                if not hit:
                    return {s.name: found.get(s.name, []) for s in rule.strings}, False
        for s in rule.strings:
            if s.name not in found:
                found[s.name] = find(s)
        return found, True


class MagicIndex:
    """The rule set's anchor indexes by the leading-byte requirements a file meets."""

    def __init__(self, rules: list[RuleDef], build: Callable[[list[Any]], Any]) -> None:
        self.rules, self.build = rules, build
        self.strings = [s for r in rules for s in r.strings]
        self.keys = sorted({m for r in rules for m in r.magic})
        self.built: dict[frozenset[Magic], tuple[Any, list[Any]]] = {}

    @staticmethod
    def meets(data: bytes, m: Magic) -> bool:
        width, big, signed, value = m
        if len(data) < width:
            return False
        return int.from_bytes(data[:width], "big" if big else "little", signed=signed) == value

    def live(self, data: bytes, seen: dict[Any, Any]) -> set[int]:
        """The ids of the strings with an anchor in `data`, among the rules whose leading-byte
        requirements `data` meets."""
        met = frozenset(m for m in self.keys if MagicIndex.meets(data, m))
        entry = self.built.get(met)
        if entry is None:
            strings = [s for r in self.rules if r.magic <= met for s in r.strings]
            entry = self.built[met] = (self.build([s.search for s in strings]), strings)
        index, strings = entry
        return {id(strings[i]) for i in index.live(data, seen)}


__all__ = ["Gates", "MagicIndex"]
