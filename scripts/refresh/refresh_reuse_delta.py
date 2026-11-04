#!/usr/bin/env python3
"""The code-reuse index's daily delta section (item 3B, notes/73-crix-daily-delta.md).

A MAINTENANCE script, like `refresh_package_intel.py`: what it writes is data the feed publishes. It
reads two CRIX files and writes the `reuse` section that turns the first into the second:

    PYTHONPATH=src python3 scripts/refresh/refresh_reuse_delta.py --current reuse-index.bin [--overlay reuse-overlay.bin] \\
        --new reuse-index-new.bin --new-hooks reuse-index-new.hooks --built 20395 --out reuse-section.json

- `--current` is the index clients hold (the release's, or the last full bundle's), and `--overlay`
  the deltas published since (a client's CRXD file built from them). Together they are the state
  clients have today.
- `--new` is today's full build by the data team's builder, deterministic from every unit to date: its
  MIN_PRIOR rule, its benign filter and its genuine-version rule are the builder's, so a delta and a
  full build can never disagree. `--new-hooks` lists the builder's hook-shape keys, one hex per line:
  CRIX keeps both key spaces in one table, and the delta tags each entry (the outer layer's review,
  condition 2).
- Group ids are stable: the first 4 bytes of sha256 over the group's name (`ReuseGroups.id_of`). The
  builder writes the same ids, so a delta's group id names the same campaign as the base's.

Only 16-byte digests and campaign names are written. Nothing of the malware itself is read here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

from cordon_scanner.intel.malware.reuse_delta import ReuseDelta, ReuseOverlay
from cordon_scanner.intel.malware.reuse_index import ReuseIndex
from cordon_scanner.intel.malware.reuse_types import SPACES, ReuseGroup


class ReuseGroups:
    @staticmethod
    def id_of(name: str) -> int:
        """A campaign's stable group id: the same name is the same id in every build."""
        return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "little")


class ReuseDiff:
    """The section turning the clients' state into today's build."""

    @staticmethod
    def entries(data: bytes) -> tuple[dict[bytes, ReuseGroup], int]:
        index, problem = ReuseIndex.parse(data, max_age_days=0)
        if index is None:
            raise SystemExit(f"not a usable index: {problem}")
        out = {}
        for i in range(index.count):
            digest, group = struct.unpack_from("<16sI", index._records, i * 20)
            out[digest] = index.groups[group]
        return out, index.built

    @staticmethod
    def state(
        current: bytes, overlay: bytes | None, hooks: set[bytes]
    ) -> dict[tuple[int, bytes], str]:
        """(space, digest) -> group name, as clients hold it today."""
        base, _ = ReuseDiff.entries(current)
        state = {(ReuseDiff.space(d, hooks), d): g.name for d, g in base.items()}
        if overlay:
            o = ReuseOverlay(overlay)
            for (space, digest), group in o._adds():
                state[(space, digest)] = o.groups[group].name
            for key in o._withdrawals():
                state.pop(key, None)
        return state

    @staticmethod
    def space(digest: bytes, hooks: set[bytes]) -> int:
        return SPACES["hook"] if digest in hooks else SPACES["code"]

    @staticmethod
    def section(
        old: dict[tuple[int, bytes], str], new_data: bytes, hooks: set[bytes], built: int
    ) -> dict[str, Any]:
        new, _ = ReuseDiff.entries(new_data)
        target = {(ReuseDiff.space(d, hooks), d): g for d, g in new.items()}
        add = {k: ReuseGroups.id_of(g.name) for k, g in target.items() if old.get(k) != g.name}
        withdraw = [k for k in old if k not in target]
        used = {g.name: g for k, g in target.items() if k in add}
        groups = [
            ReuseGroup(ReuseGroups.id_of(n), g.packages, g.earliest, n) for n, g in used.items()
        ]
        return ReuseDelta.section(built, add, withdraw, groups)


class ReuseDeltaCli:
    @staticmethod
    def keys(path: Path | None) -> set[bytes]:
        """A .hooks sidecar's keys, one hex per line."""
        if path is None:
            return set()
        return {bytes.fromhex(x) for x in path.read_text(encoding="utf-8").split()}

    @staticmethod
    def main() -> None:
        ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
        ap.add_argument("--current", type=Path, required=True)
        ap.add_argument("--overlay", type=Path)
        ap.add_argument(
            "--current-hooks", type=Path, help="hook keys of --current, one hex per line"
        )
        ap.add_argument("--new", type=Path, required=True)
        ap.add_argument("--new-hooks", type=Path, required=True)
        ap.add_argument("--built", type=int, required=True, help="days since 1970-01-01")
        ap.add_argument("--out", type=Path, required=True)
        a = ap.parse_args()
        old = ReuseDiff.state(
            a.current.read_bytes(),
            a.overlay.read_bytes() if a.overlay else None,
            ReuseDeltaCli.keys(a.current_hooks),
        )
        section = ReuseDiff.section(
            old, a.new.read_bytes(), ReuseDeltaCli.keys(a.new_hooks), a.built
        )
        ReuseDelta.parse(section)  # the client's own check, before anything is published
        a.out.write_text(
            json.dumps(section, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        print(
            f"{a.out}: add {len(section['add'])}, withdraw {len(section['withdraw'])}, groups {len(section['groups'])}"
        )


if __name__ == "__main__":
    ReuseDeltaCli.main()
