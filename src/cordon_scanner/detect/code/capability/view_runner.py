"""A raw-text rule run on the file as written and, where it differs, on its decoded view
(reviews/pypi-98/18-DECODED-VIEW.md §2-§4).

A raw-text rule reads the bytes; the language reads them decoded, so an attacker picks the spelling
(`"\\x63hild_process"`, `\\u0066etch(`, `"cr" "ontab"`, a fullwidth name). `ViewRunner.run` runs the rule
on the raw text, then -- only when `DecodedView` re-spells something -- on the view, and returns the
union:

- a view hit cites the raw text: its span is the raw span of every re-spelt piece it touches, its
  line is counted in the raw text, so evidence and SARIF regions quote the file's own bytes;
- a view hit whose rule already hit an overlapping raw span is the same finding, and the raw one is
  kept;
- a view only adds readings, so no raw finding can be lost (§4).

A file past the view's budget raises `ViewOverBudget` out of the detector, which the engine reports
as the file's gap: the scan is INCOMPLETE, never quietly raw-only (§2, Budget).

An excuse is not run here: one granted on a match reads the raw text only, one granted on an absence
asks every reading (`ViewRunner.readings`), so a decoded spelling only ever withholds one (§6).
"""

from __future__ import annotations

import dataclasses
import functools
from collections.abc import Callable
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.decoded_view import DecodedView, ViewOverBudget
from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.content import FileContent

if TYPE_CHECKING:
    from cordon_scanner.detect.code.capability.hits import CapabilityHit

Rule = Callable[[FileContent], list["CapabilityHit"]]


class ViewRunner:
    #: The languages `DecodedView` reads; every other file is its own view.
    LANGUAGES: frozenset[str] = frozenset({"python", "javascript", "typescript", "go"})

    @classmethod
    def view(cls, content: FileContent, language: str | None) -> DecodedView | None:
        """The file's decoded view when it differs from the text, else None. Raises
        `ViewOverBudget` for a file past the view's budget."""
        viewed = cls._viewed(content, language)
        return None if viewed is None else viewed[0]

    @classmethod
    def _viewed(
        cls, content: FileContent, language: str | None
    ) -> tuple[DecodedView, FileContent] | None:
        if language not in cls.LANGUAGES:
            return None
        read = cls._read(content.path, content.text, language)
        if isinstance(read, ViewOverBudget):
            raise read
        view, view_content = read
        return None if view_content is None else (view, view_content)

    @classmethod
    def readings(cls, content: FileContent, language: str | None) -> tuple[str, ...]:
        """The raw text, and the view's text where it differs: what an excuse granted on an
        absence must find nothing in."""
        view = cls.view(content, language)
        return (content.text,) if view is None else (content.text, view.text)

    @classmethod
    def run(cls, rule: Rule, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """`rule` on the raw text and, where it differs, on the view: the union, in raw spans."""
        hits = rule(content)
        viewed = cls._viewed(content, language)
        if viewed is None:
            return hits
        view, view_content = viewed
        held = list(hits)
        for hit in rule(view_content):
            raw_hit = cls._to_raw(hit, view, content)
            if not any(cls._same(raw_hit, h) for h in held):
                held.append(raw_hit)
        return held

    @classmethod
    def bound(
        cls, content: FileContent, language: str | None
    ) -> Callable[[Callable[[FileContent, str | None], list[CapabilityHit]]], list[CapabilityHit]]:
        """`run` for one file: a rule written `rule(content, language)` handed in by name."""
        return lambda rule: cls.run(lambda c: rule(c, language), content, language)

    @staticmethod
    def _same(a: CapabilityHit, b: CapabilityHit) -> bool:
        """One finding: the same rule over overlapping raw spans (an empty span counts as one byte)."""
        return (
            a.rule_id == b.rule_id
            and a.byte_start < max(b.byte_end, b.byte_start + 1)
            and b.byte_start < max(a.byte_end, a.byte_start + 1)
        )

    @staticmethod
    def _to_raw(hit: CapabilityHit, view: DecodedView, content: FileContent) -> CapabilityHit:
        """A hit made on the view, its byte span and line moved to the raw text it reads."""
        data = view.text.encode("utf-8")
        start = len(data[: hit.byte_start].decode("utf-8", "ignore"))
        end = len(data[: hit.byte_end].decode("utf-8", "ignore"))
        raw_start, raw_end = view.to_raw(start, max(end, start + 1))
        raw = content.text
        byte_start = len(raw[:raw_start].encode("utf-8"))
        byte_end = byte_start + len(raw[raw_start:raw_end].encode("utf-8"))
        return dataclasses.replace(
            hit, byte_start=byte_start, byte_end=byte_end, line=raw.count("\n", 0, raw_start) + 1
        )

    @staticmethod
    @ScanCaches.register  # holds files' texts: emptied after each scan (foundation/collector)
    @functools.lru_cache(maxsize=8)
    def _read(
        path: str, text: str, language: str
    ) -> tuple[DecodedView, FileContent | None] | ViewOverBudget:
        """The view of one file, and the content a rule reads it through (same path), made once for
        all of the file's rules; a refusal is kept too, so it is not rebuilt per rule."""
        try:
            view = DecodedView.of(text, language)
        except ViewOverBudget as refused:
            return refused
        if not view.differs:
            return view, None
        return view, FileContent.from_bytes(path, view.text.encode("utf-8"))


__all__ = ["ViewOverBudget", "ViewRunner"]
