"""The starts whose bytes follow a pattern part's single starting path (`Along`), for a part with
no anchor: each step's bytes become a 0/1 mask, the masks are shifted into line and ANDed as
integers (in C), and what survives is every position the path runs on from. Worked a window of
`Along.WINDOW` starts at a time, each window reading the path's length past its end, so the masks
are bounded whatever the file's size (a whole 100 MB file's masks were about 450 MB a call) and
every start is tested as it was over the whole file."""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places


class Along:
    #: The starts one window holds: its masks are this long, plus the path.
    WINDOW: ClassVar[int] = 1 << 20

    @staticmethod
    def listed(
        steps: list[bytes], data: bytes, segments: int | None, budget: list[int] | None
    ) -> list[int]:
        """Every start, bounded as `Places.occurrences` bounds them, spending `budget`."""
        most = Places.MOST if budget is None else min(Places.MOST, budget[0])
        out: list[int] = []
        for at in Along.lazy(steps, data, segments):
            if len(out) >= most:
                raise Places.too_many()
            out.append(at)
        if budget is not None:
            budget[0] -= len(out)
        return out

    @staticmethod
    def lazy(steps: list[bytes], data: bytes, segments: int | None) -> Iterator[int]:
        """Every start, one at a time, one window's masks held at once."""
        n, width = len(data), Along.WINDOW
        for base in range(0, n, width):
            window = data[base : base + width + len(steps) - 1]
            alive = Along.alive(steps, window, segments)
            if not alive:
                continue
            found = alive.to_bytes(len(window), "little")[: min(width, n - base)]
            at = found.find(b"\x01")
            while at >= 0:
                yield base + at
                at = found.find(b"\x01", at + 1)

    @staticmethod
    def alive(steps: list[bytes], window: bytes, segments: int | None) -> int:
        """The window's survivors as an integer, one bit set per surviving byte's lowest."""
        masks: dict[bytes, int] = {}

        def mask(table: bytes) -> int:
            m = masks.get(table)
            if m is None:
                m = masks[table] = int.from_bytes(window.translate(table), "little")
            return m

        alive = mask(steps[0])
        i, used = 1, 1
        while i < len(steps) and alive:
            if segments is not None and used >= segments:
                break
            used += 1
            same = 1  # how many steps from i ask for the same bytes
            while i + same < len(steps) and steps[i + same] == steps[i]:
                same += 1
            if same >= 4:
                # one byte class `same` times over: AND windows that double in length until one
                # covers half the run, then close it with one more, overlapping
                run, covered = mask(steps[i]), 1
                while covered * 2 <= same:
                    run &= run >> (8 * covered)
                    covered *= 2
                if covered < same:
                    run &= run >> (8 * (same - covered))
                alive &= run >> (8 * i)
                i += same
            else:
                alive &= mask(steps[i]) >> (8 * i)
                i += 1
        return alive


__all__ = ["Along"]
