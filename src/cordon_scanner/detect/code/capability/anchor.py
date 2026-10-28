"""Where a composite finding points, and what it folds on.

A composite is satisfied by several hits; the finding has to point at one. The most specific
contributing hit is where a reader should look, and the least specific is the mirror of it. A second
hash carried in the evidence groups the same idiom across files, so a pattern repeated through a
package is reported as one thing to review."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import Evidence

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class FindingAnchor:
    """The hit a composite finding points at, and its idiom key."""

    #: How much of the finding each capability carries, most specific first.
    #: A compound primitive names the whole act by itself -- `fetch_exec` IS
    #: "the download is the interpreter's input" -- while `egress` and `spawn`
    #: are the two that appear in ordinary code constantly.
    ANCHOR_SPECIFICITY: ClassVar[tuple[Capability, ...]] = (
        Capability.FETCH_EXEC,
        Capability.DESERIALIZE,
        Capability.EXECUTE,
        Capability.DYNAMIC_DISPATCH,
        Capability.WALLET,
        Capability.MINE,
        Capability.CREDENTIAL,
        Capability.PERSIST,
        Capability.DESTROY,
        Capability.ANTI_ANALYSIS,
        Capability.TARGETING,
        Capability.DECODE,
        Capability.DECOMPRESS,
        Capability.RECONNAISSANCE,
        Capability.DELAY,
        Capability.SPAWN,
        Capability.EGRESS,
    )

    @staticmethod
    def anchor(
        matched: tuple[Capability, ...],
        by_capability: dict[Capability, CapabilityHit],
        hits: list[CapabilityHit],
    ) -> CapabilityHit:
        """Where to point the finding.

        The hit that carries the most of the claim, and the earliest of those.

        This was the earliest hit of any named capability, on the reasoning that
        the first contributing line puts the reader at the start of the
        construct. That holds when the capabilities ARE one construct, and
        `curl ... | bash` -- where every capability is on the one line -- still
        anchors exactly where it did. It fails at the proximity a composite
        allows: `SUSPECT.DROPPER.001` pairs hits up to two hundred lines apart,
        so the earliest is routinely nowhere near the evidence.

        Of sixteen DROPPER findings sampled from the corpus, eight pointed
        somewhere misleading. milvus showed `PWD := $(shell pwd)` on line 13 for
        a `curl | sh` on 143; hiddify showed `ifeq ($(shell uname),Darwin)` on
        34 for one on 162; community-scripts showed twelve lines of figlet ASCII
        ART for a `source <(curl ...)` ten lines below it. Every one of those
        findings was CORRECT, and every one of them reads as a tool that does
        not know what it is looking at -- which is the more expensive failure,
        because a false positive is argued with and this is simply disbelieved.
        """
        relevant = [by_capability[c] for c in matched if c in by_capability]
        order = FindingAnchor.ANCHOR_SPECIFICITY

        def rank(hit: CapabilityHit) -> int:
            try:
                return order.index(hit.capability)
            except ValueError:
                # A primitive nobody has graded yet sorts between the compound
                # ones and the two broad ones, rather than winning by accident.
                return len(order) - 2

        return min(relevant or hits, key=lambda h: (rank(h), h.byte_start))

    MIN_IDIOM_BYTES = 40

    @classmethod
    def with_idiom_key(
        cls,
        evidence: Evidence,
        content: FileContent,
        matched: tuple[Capability, ...],
        hits: list[CapabilityHit],
    ) -> Evidence:
        """Carry a second hash: the one `ResultFolding.idiom` groups on.

        Those two questions had one answer and they are not the same question.
        The evidence should point at the hit that carries the claim -- that is
        what `_anchor` is for, and why `community-scripts/ProxmoxVE` stopped
        being shown twelve lines of figlet ASCII art. The COLLAPSE has to group
        on the part that is shared, which is the generic half: six hundred of
        that repository's container scripts open with a byte-identical
        `source <(curl -fsSL .../build.func)`, and that line is what makes them
        one decision applied six hundred times rather than six hundred findings.

        Keying the collapse on the evidence meant moving the anchor silently
        switched the collapse off: its persistence findings went from one to
        twenty-seven in a single pass, which is how this was noticed at all.

        So the anchor stays the most specific hit and this is the broadest one.
        Absent when the shared construct is too short to be specific, which is
        the same condition the collapse applies to a snippet.
        """
        broadest = cls._broadest(matched, hits)
        if broadest is None:
            return evidence
        raw = content.raw[broadest.byte_start : broadest.byte_end]
        if len(raw) < cls.MIN_IDIOM_BYTES:
            return evidence
        metadata = dict(evidence.metadata)
        metadata["idiom_hash"] = Evidence.hash_bytes(raw)
        return replace(evidence, metadata=tuple(sorted(metadata.items())))

    @classmethod
    def _broadest(
        cls, matched: tuple[Capability, ...], hits: list[CapabilityHit]
    ) -> CapabilityHit | None:
        """The least specific contributing hit -- the mirror of `_anchor`."""
        order = cls.ANCHOR_SPECIFICITY
        wanted = set(matched)
        relevant = [h for h in hits if h.capability in wanted] or hits
        if not relevant:
            return None

        def rank(hit: CapabilityHit) -> tuple[int, int]:
            try:
                index = order.index(hit.capability)
            except ValueError:
                index = len(order) - 2
            return (-index, hit.byte_start)

        return min(relevant, key=rank)


__all__ = ["FindingAnchor"]
