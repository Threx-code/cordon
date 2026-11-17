"""Does a signed feed pass the scanner's own client? The R2 acceptance suite (platform plan, R2).

Runs `cordon_scanner.intel.malware.feed.Feed` -- the client every scanner ships -- against a directory of feed
files and a clock. No server: the client's `fetch` reads the directory, and scenario variants are built in
memory from the files, so a publisher only has to write its output (root, timestamp, snapshot, targets, deltas,
full bundle) to a folder. With test keys the same suite runs against the backend's own export.

    python bench/tools/feed_conformance.py --feed DIR [--older DIR] [--root FILE] [--clock 2027-01-15T12:00:00Z]

`--feed` is the current export; `--older` is an earlier export of the same feed (a lower version, validly signed)
for the rollback and mix-and-match scenarios; `--root` is the pinned root (default `DIR/root.json`); `--clock` is the
time the client runs at (default: now). Prints one line per scenario and exits non-zero if any fails.

```
  accepts                        a clean client takes the feed: serial, versions and freshness are the feed's
  accepts_again                  a second update of the same feed changes nothing
  accepts_just_before_expiry     the client at the instant before the earliest expiry takes the feed
  refuses_freeze                 the client past the timestamp's expiry refuses it, changing no state
  refuses_rollback               a client that has taken the feed refuses the older export, changing no state
  refuses_mixed_timestamp        the new timestamp with the older snapshot is refused (the hash pin)
  refuses_mixed_snapshot         the new snapshot with the older targets is refused
  refuses_swapped_data_file      a data file replaced by the older export's file of the same name is refused
  refuses_altered_data_file      every data file the client fetches, one byte flipped, is refused
  refuses_truncated_data_file    every data file the client fetches, cut short, is refused
  refuses_altered_metadata       timestamp, snapshot and targets, signed body changed, are refused
  refuses_unsigned_metadata      the same three with their signatures removed are refused
  follows_root_rotation          pinned to `1.root.json`, the client follows `<n>.root.json` to the current root
  refuses_unsigned_rotated_root  a rotated root without its signatures is refused, changing no state
```
A scenario that needs something the directory lacks (an older export; two files of one name; rotated roots) is reported as `skip`.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cordon_scanner.intel.base import FeedError
from cordon_scanner.intel.malware.feed import Feed, FeedRoles, FeedState

METADATA = ("timestamp.json", "snapshot.json", "targets.json")
BASE_URL = "https://feed.test/v1"


@dataclass(frozen=True)
class Outcome:
    name: str
    status: str  # pass | fail | skip
    detail: str = ""


class FeedFiles:
    """The files of one export, read into memory by their path inside the directory."""

    def __init__(self, files: Mapping[str, bytes]) -> None:
        self.files = dict(files)

    @classmethod
    def read(cls, directory: Path) -> FeedFiles:
        return cls(
            {
                path.relative_to(directory).as_posix(): path.read_bytes()
                for path in sorted(directory.rglob("*"))
                if path.is_file()
            }
        )

    def signed(self, name: str) -> dict[str, Any]:
        document: dict[str, Any] = json.loads(self.files[name])
        return document

    def replaced(self, name: str, body: bytes) -> FeedFiles:
        return FeedFiles({**self.files, name: body})


class Served:
    """What a client fetches: the files, and a record of which it asked for."""

    def __init__(self, files: FeedFiles) -> None:
        self.files = files
        self.asked: list[str] = []

    def fetch(self, url: str, timeout: float, limit: int) -> bytes:
        name = url.split("/v1/", 1)[1]
        self.asked.append(name)
        if name not in self.files.files:
            raise FeedError(f"HTTP 404 from the feed ({name})")
        body = self.files.files[name]
        if len(body) > limit:
            raise FeedError("a feed file exceeded its size limit")
        return body


class Conformance:
    def __init__(
        self, feed: FeedFiles, older: FeedFiles | None, root: dict[str, Any], clock: datetime
    ) -> None:
        self.feed, self.older, self.root, self.clock = feed, older, root, clock
        self.fetched: list[str] = []

    # -- plumbing ----------------------------------------------------------------------------------

    def _client(
        self,
        files: FeedFiles,
        state: Path,
        clock: datetime | None = None,
        root: dict[str, Any] | None = None,
    ) -> tuple[Feed, Served]:
        served = Served(files)
        moment = (clock or self.clock).timestamp()
        return Feed(
            base_url=BASE_URL,
            root=copy.deepcopy(root or self.root),
            fetch=served.fetch,
            directory=state,
            clock=lambda: moment,
        ), served

    @staticmethod
    def _position(state: Path) -> tuple[int, int, int, int]:
        loaded = FeedState.load(state)
        return (
            loaded.timestamp_version,
            loaded.snapshot_version,
            loaded.targets_version,
            loaded.serial,
        )

    def _fresh(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        scratch = tempfile.TemporaryDirectory()
        os.environ["CORDON_CACHE_DIR"] = str(Path(scratch.name) / "cache")
        return scratch, Path(scratch.name) / "state"

    def _try(
        self,
        files: FeedFiles,
        *,
        clock: datetime | None = None,
        prime: FeedFiles | None = None,
        root: dict[str, Any] | None = None,
    ) -> tuple[bool, str, bool]:
        """(the client refused, what it said, whether its state is unchanged by the attempt)."""
        scratch, state = self._fresh()
        with scratch:
            if prime is not None:
                self._client(prime, state)[0].update()
            before = self._position(state)
            client, _ = self._client(files, state, clock, root)
            try:
                client.update()
            except FeedError as problem:
                return True, str(problem), self._position(state) == before
            except Exception as crash:  # noqa: BLE001
                # Anything but a refusal is a failure of the client, not a refusal: it must say no, not fall over.
                return False, f"the client crashed: {type(crash).__name__}", True
            return False, "", True

    def _refusal(self, name: str, files: FeedFiles, needle: str = "", **kw: Any) -> Outcome:
        refused, message, unchanged = self._try(files, **kw)
        if not refused:
            return Outcome(name, "fail", message or "the client took it")
        if needle and needle not in message:
            return Outcome(name, "fail", f"refused, but not as {needle}: {message}")
        if not unchanged:
            return Outcome(name, "fail", "refused, but its state changed")
        return Outcome(name, "pass", message)

    # -- the scenarios -----------------------------------------------------------------------------

    def accepts(self) -> Outcome:
        scratch, state = self._fresh()
        with scratch:
            client, served = self._client(self.feed, state)
            try:
                result = client.update()
            except FeedError as problem:
                return Outcome("accepts", "fail", f"the client refused the feed: {problem}")
            stamp = self.feed.signed("timestamp.json")["signed"]
            targets = self.feed.signed("targets.json")["signed"]
            if result.timestamp_version != int(stamp["version"]) or result.serial != int(
                targets["serial"]
            ):
                return Outcome("accepts", "fail", "the state is not the feed's versions and serial")
            if not result.fresh_at:
                return Outcome("accepts", "fail", "no freshness time was recorded")
            self.fetched = [
                name
                for name in served.asked
                if name not in METADATA and not name.endswith("root.json")
            ]
            return Outcome(
                "accepts",
                "pass",
                f"serial {result.serial}; data files fetched: {', '.join(self.fetched) or 'none'}",
            )

    def accepts_again(self) -> Outcome:
        scratch, state = self._fresh()
        with scratch:
            try:
                self._client(self.feed, state)[0].update()
                first = self._position(state)
                self._client(self.feed, state)[0].update()
            except FeedError as problem:
                return Outcome("accepts_again", "fail", str(problem))
            return (
                Outcome("accepts_again", "pass")
                if self._position(state) == first
                else Outcome("accepts_again", "fail", "a second update moved the state")
            )

    def _expiries(self) -> dict[str, float]:
        return {name: FeedRoles._expires(self.feed.signed(name)["signed"]) for name in METADATA}

    def accepts_just_before_expiry(self) -> Outcome:
        earliest = min([*self._expiries().values(), FeedRoles._expires(self.root["signed"])])
        moment = datetime.fromtimestamp(earliest - 1, tz=UTC)
        refused, message, _ = self._try(self.feed, clock=moment)
        return (
            Outcome("accepts_just_before_expiry", "fail", message)
            if refused
            else Outcome("accepts_just_before_expiry", "pass")
        )

    def refuses_freeze(self) -> Outcome:
        moment = datetime.fromtimestamp(self._expiries()["timestamp.json"] + 1, tz=UTC)
        return self._refusal("refuses_freeze", self.feed, "freeze", clock=moment)

    def _older_or_skip(self, name: str) -> FeedFiles | Outcome:
        """The older export when it exists and is older; otherwise the skip to report."""
        if self.older is None:
            return Outcome(name, "skip", "no older export given")
        newer = int(self.feed.signed("timestamp.json")["signed"]["version"])
        if int(self.older.signed("timestamp.json")["signed"]["version"]) >= newer:
            return Outcome(
                name, "skip", "the older export is not older (its timestamp version is not lower)"
            )
        return self.older

    def refuses_rollback(self) -> Outcome:
        older = self._older_or_skip("refuses_rollback")
        if isinstance(older, Outcome):
            return older
        return self._refusal("refuses_rollback", older, "rollback", prime=self.feed)

    def refuses_mixed_timestamp(self) -> Outcome:
        older = self._older_or_skip("refuses_mixed_timestamp")
        if isinstance(older, Outcome):
            return older
        return self._refusal(
            "refuses_mixed_timestamp",
            self.feed.replaced("snapshot.json", older.files["snapshot.json"]),
        )

    def refuses_mixed_snapshot(self) -> Outcome:
        older = self._older_or_skip("refuses_mixed_snapshot")
        if isinstance(older, Outcome):
            return older
        return self._refusal(
            "refuses_mixed_snapshot",
            self.feed.replaced("targets.json", older.files["targets.json"]),
        )

    def _fetched(self) -> list[str]:
        """The data files a clean client fetches (found by running it)."""
        if not self.fetched:
            self.accepts()
        return list(self.fetched)

    DATA_DIRECTORIES = ("full/", "deltas/", "rules/")

    def refuses_swapped_data_file(self) -> Outcome:
        """Each data file the client fetches, replaced by a different validly signed file: the same name from the
        older export when there is one, and another data file of this export (an immutable feed never rewrites a
        path, so the swap an attacker has is another file of the same feed)."""
        swaps: list[tuple[str, bytes]] = []
        for name in self._fetched():
            older = self.older.files.get(name) if self.older is not None else None
            if older is not None and older != self.feed.files[name]:
                swaps.append((name, older))
                continue
            others = sorted(
                other
                for other in self.feed.files
                if other != name
                and other.startswith(self.DATA_DIRECTORIES)
                and self.feed.files[other] != self.feed.files[name]
            )
            if others:
                swaps.append((name, self.feed.files[others[0]]))
        if not swaps:
            return Outcome("refuses_swapped_data_file", "skip", "no other data file to swap in")
        bad = [name for name, body in swaps if not self._try(self.feed.replaced(name, body))[0]]
        if bad:
            return Outcome(
                "refuses_swapped_data_file",
                "fail",
                f"{len(bad)} of {len(swaps)} swapped file(s) were taken",
            )
        return Outcome("refuses_swapped_data_file", "pass", f"{len(swaps)} file(s)")

    def _tampered(self, name: str, how: Callable[[bytes], bytes]) -> Outcome:
        files = self._fetched()
        if not files:
            return Outcome(name, "skip", "the client fetched no data file")
        bad = [
            path
            for path in files
            if not self._try(self.feed.replaced(path, how(self.feed.files[path])))[0]
        ]
        return (
            Outcome(name, "fail", f"{len(bad)} of {len(files)} data file(s) were taken")
            if bad
            else Outcome(name, "pass", f"{len(files)} file(s)")
        )

    def refuses_altered_data_file(self) -> Outcome:
        return self._tampered(
            "refuses_altered_data_file", lambda body: body[:-1] + bytes([body[-1] ^ 1])
        )

    def refuses_truncated_data_file(self) -> Outcome:
        return self._tampered("refuses_truncated_data_file", lambda body: body[: len(body) // 2])

    def _metadata_variants(self, name: str, alter: Callable[[dict[str, Any]], None]) -> Outcome:
        bad = []
        for item in METADATA:
            document = copy.deepcopy(self.feed.signed(item))
            alter(document)
            if not self._try(self.feed.replaced(item, json.dumps(document).encode()))[0]:
                bad.append(item)
        return (
            Outcome(name, "fail", f"taken: {', '.join(bad)}")
            if bad
            else Outcome(name, "pass", "timestamp, snapshot, targets")
        )

    def refuses_altered_metadata(self) -> Outcome:
        def alter(document: dict[str, Any]) -> None:
            document["signed"]["version"] = int(document["signed"].get("version", 0)) + 1

        return self._metadata_variants("refuses_altered_metadata", alter)

    def refuses_unsigned_metadata(self) -> Outcome:
        def strip(document: dict[str, Any]) -> None:
            document["signatures"] = []

        return self._metadata_variants("refuses_unsigned_metadata", strip)

    def _rotation(self, name: str) -> dict[str, Any] | Outcome:
        """The first root, when the export carries rotated roots (`1.root.json` and `2.root.json`)."""
        if "1.root.json" not in self.feed.files or "2.root.json" not in self.feed.files:
            return Outcome(
                name, "skip", "the export carries no rotated roots (1.root.json and 2.root.json)"
            )
        first: dict[str, Any] = self.feed.signed("1.root.json")
        return first

    def follows_root_rotation(self) -> Outcome:
        first = self._rotation("follows_root_rotation")
        if isinstance(first, Outcome):
            return first
        refused, message, _ = self._try(self.feed, root=first)
        if refused:
            return Outcome(
                "follows_root_rotation",
                "fail",
                f"the client pinned to the first root refused the feed: {message}",
            )
        return Outcome("follows_root_rotation", "pass")

    def refuses_unsigned_rotated_root(self) -> Outcome:
        first = self._rotation("refuses_unsigned_rotated_root")
        if isinstance(first, Outcome):
            return first
        rotated = self.feed.signed("2.root.json")
        rotated["signatures"] = []
        changed = self.feed.replaced("2.root.json", json.dumps(rotated).encode())
        refused, message, unchanged = self._try(changed, root=first)
        if not refused:
            return Outcome(
                "refuses_unsigned_rotated_root",
                "fail",
                message or "the client followed an unsigned root",
            )
        if not unchanged:
            return Outcome(
                "refuses_unsigned_rotated_root", "fail", "refused, but its state changed"
            )
        return Outcome("refuses_unsigned_rotated_root", "pass")

    def run(self) -> list[Outcome]:
        scenarios = (
            self.accepts,
            self.accepts_again,
            self.accepts_just_before_expiry,
            self.refuses_freeze,
            self.refuses_rollback,
            self.refuses_mixed_timestamp,
            self.refuses_mixed_snapshot,
            self.refuses_swapped_data_file,
            self.refuses_altered_data_file,
            self.refuses_truncated_data_file,
            self.refuses_altered_metadata,
            self.refuses_unsigned_metadata,
            self.follows_root_rotation,
            self.refuses_unsigned_rotated_root,
        )
        saved = os.environ.get("CORDON_CACHE_DIR")
        try:
            return [scenario() for scenario in scenarios]
        finally:
            if saved is None:
                os.environ.pop("CORDON_CACHE_DIR", None)
            else:
                os.environ["CORDON_CACHE_DIR"] = saved


class Command:
    @staticmethod
    def main(argv: list[str]) -> int:
        parser = argparse.ArgumentParser(
            description="Run the scanner's own feed client against a directory of feed files."
        )
        parser.add_argument("--feed", type=Path, required=True)
        parser.add_argument("--older", type=Path)
        parser.add_argument("--root", type=Path)
        parser.add_argument("--clock", default=None)
        arguments = parser.parse_args(argv)
        feed = FeedFiles.read(arguments.feed)
        older = FeedFiles.read(arguments.older) if arguments.older else None
        root_path = arguments.root or arguments.feed / "root.json"
        root = json.loads(root_path.read_text(encoding="utf-8"))
        clock = (
            datetime.fromisoformat(arguments.clock.replace("Z", "+00:00"))
            if arguments.clock
            else datetime.now(UTC)
        )
        outcomes = Conformance(feed, older, root, clock).run()
        for item in outcomes:
            sys.stdout.write(
                f"{item.status:5} {item.name}{(' - ' + item.detail) if item.detail else ''}\n"
            )
        failed = sum(item.status == "fail" for item in outcomes)
        sys.stdout.write(
            f"{len(outcomes)} scenarios: {sum(i.status == 'pass' for i in outcomes)} pass, {failed} fail, {sum(i.status == 'skip' for i in outcomes)} skip\n"
        )
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(Command.main(sys.argv[1:]))
