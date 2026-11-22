#!/usr/bin/env python3
"""The MCP description model's development set, rebuilt from its sources with every row placed.

The model ships trained (`detect/data/mcp-descriptions.json.gz`) and its devset was never kept,
so no held-out figure it reports can be re-derived. This rebuilds the set from what is on the
benchmark volumes and records, for every text, the four things a held-out split needs:

```
  source     mcptox | mcptox-legit | mcpsafetybench | msb-legit | corpus   (+ "-return" for results)
  dataset    which benchmark it came from ("corpus" for the long tail's real servers)
  group      the server: what a split must keep on one side, so no server is in both halves
  domain     MCP-SafetyBench's task family (browser_automation, financial_analysis, ...); the
             benchmark builds every attack on that family's own servers, so a model trained on
             a family and tested on the same family is tested on vocabulary it has seen
  label      1 = written against the agent, 0 = an ordinary description or result
  channel    description | return
  half       work | holdout by a hash of (dataset, group), for the trainer's default split
```

    docker run --rm --network none -v cordon-bench-public:/p:ro -v cordon-corpus-q:/c:ro \\
      -v "$PWD:/s:ro" -v OUT:/o -e PYTHONPATH=/s/src python:3.12-slim \\
      python /s/bench/model/mcp_devset.py --public /p --corpus /c/mcp --out /o/devset.jsonl

Nothing in a dataset is run. Descriptions and returned strings are read as text by the scanner's
own extractors (`McpServerSource`), so a row is exactly what the scanner would score.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import itertools
import json
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suites"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_poisoning import McpSafetyBench, McpTox

from cordon_scanner.detect.agents.mcp_servers.source import (
    MCP_SDK,
    SERVER_SOURCE_SUFFIXES,
    McpServerSource,
)
from cordon_scanner.detect.agents.semantics import TRAILER

MEMBER_LIMIT = 1_500_000


class McpDevset:
    @staticmethod
    def half(dataset: str, group: str) -> str:
        digest = hashlib.sha256(f"{dataset}:{group}".encode()).digest()
        return "holdout" if digest[0] % 2 else "work"

    @staticmethod
    def row(
        source: str,
        dataset: str,
        group: str,
        domain: str,
        label: int,
        channel: str,
        text: str,
        half_of: str | None = None,
    ) -> dict:
        return {
            "source": source,
            "dataset": dataset,
            "group": group,
            "domain": domain,
            "label": label,
            "channel": channel,
            "half": McpDevset.half(dataset, half_of or group),
            "text": text,
        }

    @staticmethod
    def texts(code: str, path: str | None = None) -> Iterator[tuple[str, str]]:
        """The texts of one file. With a `path`, as the scanner reads them: a JavaScript,
        TypeScript or Python file only from its tool registrations. Without, every quoted
        description of a file that names the SDK, which is how the training set was first built."""
        for description in dict.fromkeys(McpServerSource._tool_descriptions(code, path)):
            if description.strip():
                yield "description", description
        for returned in dict.fromkeys(McpServerSource._tool_returns(code, path)):
            yield "return", returned

    @classmethod
    def mcptox(cls, public: Path) -> Iterator[dict]:
        root = public / McpTox.DIRECTORY
        for case in McpTox.poisoned(root):
            # The benchmark renders each poisoned tool with an `Arguments:` list its legitimate
            # tools lack: a format a word model would learn instead of the attack.
            text = TRAILER.sub("", case["description"])
            yield cls.row("mcptox", "mcptox", case["server"], "", 1, "description", text)
        for case in McpTox.legitimate(root):
            yield cls.row(
                "mcptox-legit", "mcptox", case["server"], "", 0, "description", case["description"]
            )

    @classmethod
    def mcpsafetybench(cls, public: Path) -> Iterator[dict]:
        loaded = McpSafetyBench.load(public / McpSafetyBench.DIRECTORY)
        for r in loaded.rows:
            if r["malicious"]:
                # `test/<domain>/<server>_task_<n>.json`: the domain is the task family.
                parts = r["server"].split("/")
                domain = parts[1] if len(parts) > 2 else ""
                for channel, text in cls.texts(r["code"]):
                    source = (
                        "mcpsafetybench" if channel == "description" else "mcpsafetybench-return"
                    )
                    yield cls.row(source, "mcpsafetybench", r["server"], domain, 1, channel, text)
            else:
                for path in sorted(Path(r["path"]).rglob("*.py")):
                    code = path.read_text(encoding="utf-8", errors="replace")
                    for channel, text in cls.texts(code):
                        source = "msb-legit" if channel == "description" else "msb-legit-return"
                        yield cls.row(
                            source, "mcpsafetybench", r["server"], r["server"], 0, channel, text
                        )

    @classmethod
    def archive(
        cls, path: Path, source: str, dataset: str, group: str, as_scanned: bool = False
    ) -> Iterator[dict]:
        for name, data in cls._members(path):
            if "/node_modules/" in name:
                continue
            text = data.decode("utf-8", "replace")
            if not MCP_SDK.search(text):
                continue
            for channel, piece in cls.texts(text, name if as_scanned else None):
                yield cls.row(
                    source if channel == "description" else f"{source}-return",
                    dataset,
                    group,
                    "",
                    0,
                    channel,
                    piece,
                    path.name,
                )

    @classmethod
    def corpus(cls, root: Path, as_scanned: bool = False) -> Iterator[dict]:
        for archive in sorted(root.iterdir()):
            yield from cls.archive(archive, "corpus", "corpus", archive.name, as_scanned)

    @classmethod
    def listed(
        cls, source: str, names: list[str], root: Path, as_scanned: bool = False
    ) -> Iterator[dict]:
        """The real servers of a list of archive names under `root`, one source of legitimate
        texts. The group is the listed name, so two archives that share a file name stay two; the
        half is the archive's own file name, as `corpus` has it, so a server falls on the same side."""
        for name in names:
            yield from cls.archive(root / name, source, source, name, as_scanned)

    @staticmethod
    def _members(path: Path) -> Iterator[tuple[str, bytes]]:
        try:
            if path.name.endswith((".whl", ".zip")):
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if info.file_size < MEMBER_LIMIT and info.filename.endswith(
                            SERVER_SOURCE_SUFFIXES
                        ):
                            yield info.filename, archive.read(info)
            else:
                with tarfile.open(path) as archive:
                    for member in archive:
                        if (
                            member.isfile()
                            and member.size < MEMBER_LIMIT
                            and member.name.endswith(SERVER_SOURCE_SUFFIXES)
                        ):
                            handle = archive.extractfile(member)
                            if handle is not None:
                                yield member.name, handle.read()
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, io.UnsupportedOperation):
            return

    @staticmethod
    def unique(rows: Iterator[dict], per_server: bool = False) -> Iterator[dict]:
        """Each text once: across the whole set for training, once per server when the texts are
        the ones a server is scored on (`--as-scanned`)."""
        seen: set[tuple[str, str, int, str]] = set()
        for row in rows:
            key = (row["group"] if per_server else "", row["channel"], row["label"], row["text"])
            if key not in seen:
                seen.add(key)
                yield row

    @classmethod
    def main(cls) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--public", type=Path, required=True)
        parser.add_argument("--corpus", type=Path, required=True)
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument(
            "--listed",
            action="append",
            default=[],
            metavar="SOURCE=LIST",
            help="a source of legitimate texts: the archive names in LIST, read under --listed-root",
        )
        parser.add_argument("--listed-root", type=Path, default=Path())
        parser.add_argument(
            "--as-scanned",
            action="store_true",
            help="the texts a server would be scored on: read from its tool registrations as the"
            " scanner reads them, and a repeated text dropped within its server only. The lines are"
            " set on this; training drops repeats across servers and reads every quoted description.",
        )
        args = parser.parse_args()
        counts: dict[str, int] = {}
        sets = [cls.mcptox(args.public), cls.mcpsafetybench(args.public)]
        sets.append(cls.corpus(args.corpus, args.as_scanned))
        for spec in args.listed:
            source, _, listing = spec.partition("=")
            names = [n for n in Path(listing).read_text(encoding="utf-8").split("\n") if n]
            sets.append(cls.listed(source, names, args.listed_root, args.as_scanned))
        with args.out.open("w", encoding="utf-8") as out:
            for row in cls.unique(itertools.chain(*sets), args.as_scanned):
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                counts[row["source"]] = counts.get(row["source"], 0) + 1
        print(json.dumps(counts, indent=2, sort_keys=True))


if __name__ == "__main__":
    McpDevset.main()
