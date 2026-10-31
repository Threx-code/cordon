"""A rule set divided into shares one large file can be matched against at the same time.

YARA matches a file on one thread. A rule's answer depends on the file and on the rules its condition
names (a rule reference, or a rule set such as `any of (loader_*)`), and on nothing else, except
that a false global rule makes every rule false. So a rule set divides into groups that never read
each other, and each share of groups can be matched on its own and the answers put together:
exactly the serial answer, rule for rule.

Grouped conservatively: any identifier in a condition that names a rule, or any `prefix*` that
could match one, links the two, whatever the position, so a share never lacks a rule it reads.
A group that holds a global rule goes into every share, so each share decides the globals itself
and all agree. Over-grouping costs only parallelism, never an answer.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator, Sequence
from typing import Any


class RuleShares:
    """Shares of a rule set's indices, each closed under the references its rules make."""

    @staticmethod
    def words(node: Any) -> Iterator[str]:
        """Every string a condition carries, at any depth: rule names among them."""
        stack = [node]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                yield item
            elif isinstance(item, (list, tuple)):
                stack.extend(item)
            elif dataclasses.is_dataclass(item) and not isinstance(item, type):
                stack.extend(getattr(item, f.name) for f in dataclasses.fields(item))

    @staticmethod
    def groups(rules: Sequence[Any]) -> list[list[int]]:
        """The rule indices in groups no rule outside a group reads, each in index order."""
        parent = list(range(len(rules)))

        def root(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def join(a: int, b: int) -> None:
            ra, rb = root(a), root(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

        index = {rule.name: i for i, rule in enumerate(rules)}
        names = sorted(index)
        for i, rule in enumerate(rules):
            for word in set(RuleShares.words(rule.condition)):
                if word.endswith("*"):
                    prefix = word[:-1]
                    for name in names:  # names that could fall under the set, read anywhere
                        if name.startswith(prefix):
                            join(i, index[name])
                elif word in index:
                    join(i, index[word])
        grouped: dict[int, list[int]] = {}
        for i in range(len(rules)):
            grouped.setdefault(root(i), []).append(i)
        return sorted(grouped.values(), key=lambda g: g[0])

    @staticmethod
    def of(rules: Sequence[Any], count: int) -> list[frozenset[int]]:
        """At most `count` shares, balanced by the strings each holds; every group that holds a
        global rule is in every share. One share (or none to split) means the whole set."""
        groups = RuleShares.groups(rules)
        shared = [g for g in groups if any(rules[i].is_global for i in g)]
        apart = [g for g in groups if not any(rules[i].is_global for i in g)]
        if count <= 1 or len(apart) <= 1:
            return [frozenset(range(len(rules)))]
        everywhere = {i for g in shared for i in g}
        loads = [0] * count
        shares: list[set[int]] = [set(everywhere) for _ in range(count)]

        def cost(group: list[int]) -> int:
            return sum(1 + len(rules[i].strings) for i in group)

        for group in sorted(apart, key=lambda g: (-cost(g), g[0])):  # largest first, steadily
            least = min(range(count), key=lambda k: (loads[k], k))
            shares[least].update(group)
            loads[least] += cost(group)
        return [frozenset(s) for s in shares if s - everywhere or not apart]


__all__ = ["RuleShares"]
