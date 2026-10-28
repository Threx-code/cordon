"""The capability detector's record of what a file can do: one hit per capability seen, with where.

A hit is an observation, not an accusation (see `capability.detector`). Every part of the detector
reads and writes these: the labelling makes them, the text-position and load-path questions drop the
ones that do not run, and the composite reasoning combines them into findings.
"""

from __future__ import annotations

from dataclasses import dataclass

from cordon_scanner.foundation.models import Capability


class LineRanges:
    """Lines and the ranges that contain them."""

    @staticmethod
    def cls_in(line: int, spans: frozenset[tuple[int, int]]) -> bool:
        """Whether a line falls inside any of these ranges."""
        return any(first <= line <= last for first, last in spans)


@dataclass(frozen=True, slots=True)
class CapabilityHit:
    """One capability observed in a file, with where it was seen."""

    capability: Capability
    rule_id: str
    byte_start: int
    byte_end: int
    line: int
    fixed: bool = False
    """Whether this is a spawn whose entire argv was written out in the source.

    Set only by the Python AST tier, which is the only tier that can answer it.
    See `_evaluate_over`, which is the one place it is read."""

    variants: int = 1
    """How many distinct operations of this capability the rule matched.

    A decode rule covering base64, hex and decompression matches all three
    with one pattern, so the number of rules that fired cannot express how many
    decoding steps a file performs. This can: one call site repeated ten times
    is still one operation, and base64 followed by decompression is two."""

    resolved: bool = False
    """Whether this hit came from parsing the source rather than scanning it.

    A parsed hit is a SECOND VIEW of a call the byte tier usually saw too --
    `base64.b64decode(blob)` is one decoding step whether one tier reports it or
    three do. So these are excluded from the depth counts in `_evaluate_over`,
    or every parsed Python file would appear to decode twice and satisfy rules
    that ask for a chain of encodings.

    This used to be inferred from the rule id beginning `AST.`, which held only
    while the single internal tier was the only thing producing such hits.
    Adding `kind: ast` to the rule vocabulary broke that silently: rules named
    `CAP.PY.AST.*` are the same second view, do not begin with `AST.`, and so
    were counted -- which turned one `base64.b64decode` into a two-step decode
    chain and fired `SUSPECT.DECODE_CHAIN.001` on a file that decodes once.
    Carried explicitly now, because the property is about where a hit came from
    and never was about how it was named."""


__all__ = ["CapabilityHit", "LineRanges"]
