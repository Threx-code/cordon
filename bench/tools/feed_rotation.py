"""Rotate a feed's root with test keys, for the R2 acceptance suite (platform plan, R2; `feed_conformance.py`).

The suite's rotation scenarios need an export whose root was rotated, and its refusals need keys that sign what an
attacker would. A publisher's real keys are never available to a test, so this tool builds the rotated sample itself:
it copies an export's data files, draws throwaway Ed25519 seeds at random (in the run, never from a file of real keys;
the seeds are written to `keys.json` beside the sample and have no value anywhere else), and re-signs the three
metadata files under a rotated root.

    python bench/tools/feed_rotation.py --from DIR [--older DIR] --out DIR

writes `OUT/current/` (and `OUT/older/` for `--older`) and `OUT/keys.json`. A sample holds:

```
  1.root.json   version 1: root role = two keys, both required; one key for each other role; signed by both root keys
  2.root.json   version 2: all new keys, signed by BOTH of version 1's root keys and BOTH of version 2's
  root.json     version 2, the current root
  timestamp.json, snapshot.json, targets.json     the export's own bodies, signed by version 2's keys, every pin recomputed
  everything else (deltas/, full/, rules/)        copied byte for byte
```
Version 3 (`Rotation.third`) is never written to a sample: the suite builds it from `keys.json` to try a skipped
root version. Only the keys file lets a scenario sign; a suite run without it skips those scenarios.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from cordon_scanner.intel.malware.feed import FeedRoles
from kits.feedkit import FeedKit, Key

ROLES = ("root", "timestamp", "snapshot", "targets")
METADATA = ("timestamp.json", "snapshot.json", "targets.json")
ROOT_KEYS = 2
EXPIRES = "2099-01-01T00:00:00Z"
VERSIONS = (1, 2, 3)


class RotationKeys:
    """Throwaway test keys for root versions 1, 2 and 3: a version holds a list of seeds for each role."""

    def __init__(self, seeds: Mapping[str, Mapping[str, list[str]]]) -> None:
        self.seeds = {
            version: {role: list(items) for role, items in roles.items()}
            for version, roles in seeds.items()
        }

    @classmethod
    def generate(cls) -> RotationKeys:
        """Seeds drawn from the operating system's randomness, in this run."""
        return cls.drawn(lambda _label: os.urandom(32))

    @classmethod
    def derived(cls, label: str) -> RotationKeys:
        """Seeds derived from a label: for tests, which must give the same keys on every run."""
        return cls.drawn(lambda name: hashlib.sha256(f"{label}/{name}".encode()).digest())

    @classmethod
    def drawn(cls, seed: Callable[[str], bytes]) -> RotationKeys:
        return cls(
            {
                f"v{version}": {
                    role: [
                        seed(f"v{version}/{role}/{index}").hex()
                        for index in range(ROOT_KEYS if role == "root" else 1)
                    ]
                    for role in ROLES
                }
                for version in VERSIONS
            }
        )

    @classmethod
    def read(cls, path: Path) -> RotationKeys:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(self.seeds, indent=1, sort_keys=True), encoding="utf-8")

    def keys(self, version: int, role: str) -> list[Key]:
        return [Key(bytes.fromhex(seed)) for seed in self.seeds[f"v{version}"][role]]

    def roles(self, version: int) -> dict[str, tuple[list[Key], int]]:
        """A version's roles: every key of the root role must sign, and one key of each other role."""
        return {
            role: (keys, len(keys) if role == "root" else 1)
            for role in ROLES
            for keys in (self.keys(version, role),)
        }


class Rotation:
    """The roots and the signed metadata of a rotated sample, built from a keys file."""

    def __init__(self, keys: RotationKeys) -> None:
        self.keys = keys

    def _root(self, version: int, *signers: list[Key]) -> dict[str, Any]:
        signing = [key for group in signers for key in group]
        return FeedKit.signed(
            FeedKit.root_body(version, self.keys.roles(version), EXPIRES), *signing
        )

    def first(self) -> dict[str, Any]:
        """Version 1, signed by its own root keys."""
        return self._root(1, self.keys.keys(1, "root"))

    def second(self) -> dict[str, Any]:
        """Version 2, signed by version 1's root keys (the old threshold) and by its own."""
        return self._root(2, self.keys.keys(1, "root"), self.keys.keys(2, "root"))

    def third(self) -> dict[str, Any]:
        """Version 3, signed by version 1's root keys and its own: a root a client can only reach by skipping version 2."""
        return self._root(3, self.keys.keys(1, "root"), self.keys.keys(3, "root"))

    @staticmethod
    def _pinned(meta: Mapping[str, Any], body: bytes) -> dict[str, Any]:
        return {**meta, "length": len(body), "sha256": hashlib.sha256(body).hexdigest()}

    def resign(
        self,
        files: Mapping[str, bytes],
        version: int,
        *,
        use: Mapping[str, list[Key]] | None = None,
    ) -> dict[str, bytes]:
        """The export's timestamp, snapshot and targets signed by root `version`'s keys (or by `use`, role by role),
        each body kept as it is and each pin on the file below recomputed, so the only thing that differs is who signed."""
        signers = {role: self.keys.keys(version, role) for role in ROLES[1:]}
        signers.update(use or {})
        targets_body = json.loads(files["targets.json"])["signed"]
        targets = FeedRoles.canonical(FeedKit.signed(targets_body, *signers["targets"]))
        snapshot_body = json.loads(files["snapshot.json"])["signed"]
        snapshot_body["targets"] = self._pinned(snapshot_body["targets"], targets)
        snapshot = FeedRoles.canonical(FeedKit.signed(snapshot_body, *signers["snapshot"]))
        timestamp_body = json.loads(files["timestamp.json"])["signed"]
        timestamp_body["snapshot"] = self._pinned(timestamp_body["snapshot"], snapshot)
        timestamp = FeedRoles.canonical(FeedKit.signed(timestamp_body, *signers["timestamp"]))
        return {"targets.json": targets, "snapshot.json": snapshot, "timestamp.json": timestamp}

    def rotate(self, files: Mapping[str, bytes]) -> dict[str, bytes]:
        """The export with its roots replaced by versions 1 and 2 and its metadata signed under version 2."""
        rotated = {
            name: body
            for name, body in files.items()
            if name not in METADATA and name != "root.json" and not name.endswith(".root.json")
        }
        rotated.update(self.resign(files, 2))
        second = FeedRoles.canonical(self.second())
        rotated["1.root.json"] = FeedRoles.canonical(self.first())
        rotated["2.root.json"] = second
        rotated["root.json"] = second
        return rotated


class Command:
    @staticmethod
    def write(files: Mapping[str, bytes], directory: Path) -> int:
        for name, body in files.items():
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return len(files)

    @staticmethod
    def read(directory: Path) -> dict[str, bytes]:
        return {
            path.relative_to(directory).as_posix(): path.read_bytes()
            for path in sorted(directory.rglob("*"))
            if path.is_file()
        }

    @staticmethod
    def main(argv: list[str]) -> int:
        parser = argparse.ArgumentParser(
            description="Copy a feed export and rotate its root with throwaway test keys."
        )
        parser.add_argument("--from", dest="source", type=Path, required=True)
        parser.add_argument("--older", type=Path)
        parser.add_argument("--out", type=Path, required=True)
        arguments = parser.parse_args(argv)
        keys = RotationKeys.generate()
        rotation = Rotation(keys)
        arguments.out.mkdir(parents=True, exist_ok=True)
        keys.write(arguments.out / "keys.json")
        sys.stdout.write("test keys: 3 root versions, seeds drawn at random in this run\n")
        for label, source in (("current", arguments.source), ("older", arguments.older)):
            if source is None:
                continue
            files = Command.read(source)
            rotated = rotation.rotate(files)
            written = Command.write(rotated, arguments.out / label)
            copied = sum(rotated[name] == body for name, body in files.items() if name in rotated)
            sys.stdout.write(
                f"{label}: {len(files)} file(s) read, {written} written, {copied} copied byte for byte\n"
            )
        return 0


if __name__ == "__main__":
    raise SystemExit(Command.main(sys.argv[1:]))
