r"""A provider pattern tried only where its leading literal starts.

A provider credential has a fixed prefix (`SK`, `sk-`, `key-`, `pat`), and most provider patterns
are `\b` then that prefix. Such a pattern can match only where the prefix starts, so it needs no
regex run over the whole file: its matches are exactly `finditer`'s, found by trying the pattern at
each occurrence of the prefix in order and resuming past each match, as `finditer` resumes.
`pattern.match(raw, i)` reads the byte before `i`, so the leading `\b` decides as it does in a
search. Four prefixes (`SK`, `sk-`, `key-`, `pat`) are in most large files; on awscli's ec2 API
definition (4 MB) their whole-file regexes were most of the secrets detector's time, 0.53 s against
0.17 s this way.

Only a pattern of exactly that shape is searched this way (`leading`): one plain prefilter
literal, case-sensitive, with no quantifier on its last byte. Anything else is searched as written.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar


class LiteralSearch:
    #: The bytes a literal may hold to stand for itself in a pattern unescaped.
    PLAIN: ClassVar[frozenset[int]] = frozenset(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    )

    @staticmethod
    def leading(source: bytes, flags: int, prefilter: tuple[bytes, ...]) -> bytes | None:
        r"""The literal every match of the pattern starts with, when the pattern is `\b` then its
        one plain prefilter literal, case-sensitive, with no quantifier on the literal's last
        byte; else None."""
        if len(prefilter) != 1 or flags & re.IGNORECASE:
            return None
        (lead,) = prefilter
        if not lead or not all(c in LiteralSearch.PLAIN for c in lead):
            return None
        head = rb"\b" + lead
        if not source.startswith(head):
            return None
        if source[len(head) : len(head) + 1] in (b"*", b"+", b"?", b"{"):
            return None
        return lead

    @staticmethod
    def matches(
        pattern: re.Pattern[bytes], prefilter: tuple[bytes, ...], raw: bytes
    ) -> Iterator[re.Match[bytes]]:
        """`pattern`'s matches in `raw`, exactly as `pattern.finditer(raw)` gives them."""
        lead = LiteralSearch.leading(pattern.pattern, pattern.flags, prefilter)
        if lead is None:
            yield from pattern.finditer(raw)
            return
        find, match = raw.find, pattern.match
        at = find(lead)
        while at >= 0:
            found = match(raw, at)
            if found is None:
                at = find(lead, at + 1)
                continue
            yield found
            at = find(lead, found.end())


__all__ = ["LiteralSearch"]
