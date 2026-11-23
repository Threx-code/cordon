"""The per-area dataset export: one run writes the train, eval and fresh manifests of an area, split by family and by time, and never changes an eval list once it is written.

    export(units, out_dir, area, fresh_after) -> {"train": n, "eval": n, "fresh": n, "excluded": n}

A unit is `{"digest", "family", "first_seen"}` (first_seen an ISO date). The split:
  fresh     first seen on or after `fresh_after`: the units the model cannot have been fitted or tuned on. Every family may appear here.
  eval      the units of the families that fall in the eval bucket of the family hash (`sha256(family)`, one family in `EVAL_EVERY`), seen before `fresh_after`.
  train     every other unit seen before `fresh_after`.
  excluded  a unit that would break the freeze (below), listed so a report can say how many were kept out; it is never let into train.

Family-disjoint: a family is wholly in eval or wholly in train, so a reworded release of an eval family is never trained on. Frozen: once `eval.json` exists its artifacts are the eval list for good, and
so are its families (the file records them, so a family whose units have left the catalogue stays closed). A later run adds no unit to the eval list and removes none; a new unit of an eval family, or of a
family that hashes to the eval bucket, is `excluded`, and the others go to train or fresh as above.
Each file is a dataset manifest (`manifests.py`): `{"dataset", "split", "artifacts": [sorted digests]}`; the eval file also lists its `families`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final

EVAL_EVERY: Final = 10
SPLITS: Final = ("train", "eval", "fresh", "excluded")


class DatasetExport:
    @staticmethod
    def eval_family(family: str) -> bool:
        """Whether a family is in the eval bucket (a fixed function of the family, so a family never moves between runs)."""
        return int(hashlib.sha256(family.encode("utf-8")).hexdigest(), 16) % EVAL_EVERY == 0

    @staticmethod
    def export(
        units: list[dict[str, Any]], out_dir: Path, area: str, fresh_after: str
    ) -> dict[str, int]:
        out_dir.mkdir(parents=True, exist_ok=True)
        frozen = DatasetExport.frozen(out_dir)
        closed = frozen is not None
        artifacts, families = frozen if frozen is not None else (set(), set())
        lists: dict[str, set[str]] = {name: set() for name in SPLITS}
        lists["eval"] |= artifacts
        eval_families = set(families)
        for unit in sorted(units, key=lambda u: u["digest"]):
            digest, family = unit["digest"], unit["family"]
            if digest in artifacts:
                continue
            if str(unit["first_seen"]) >= fresh_after:
                lists["fresh"].add(digest)
            elif family in families or DatasetExport.eval_family(family):
                # Before the freeze this is an eval unit; after it, the list is closed and a newcomer of an eval family is kept out of train as well.
                lists["excluded" if closed else "eval"].add(digest)
                if not closed:
                    eval_families.add(family)
            else:
                lists["train"].add(digest)
        for name in SPLITS:
            manifest: dict[str, Any] = {
                "dataset": f"{area}-{name}",
                "split": name,
                "artifacts": sorted(lists[name]),
            }
            if name == "eval":
                manifest["families"] = sorted(eval_families)
            (out_dir / f"{name}.json").write_text(
                json.dumps(manifest, indent=1) + "\n", encoding="utf-8"
            )
        return {name: len(lists[name]) for name in SPLITS}

    @staticmethod
    def frozen(out_dir: Path) -> tuple[set[str], set[str]] | None:
        """The artifacts and families of an eval list already written (even an empty one), None when no eval list has been written."""
        path = out_dir / "eval.json"
        if not path.exists():
            return None
        document = json.loads(path.read_text(encoding="utf-8"))
        return {str(d) for d in document["artifacts"]}, {
            str(f) for f in document.get("families", ())
        }
