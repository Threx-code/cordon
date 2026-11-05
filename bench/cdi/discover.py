"""Discovery: turn a cluster of confirmed misses into an indicator rule pack, without a person writing it.

The rapid-response lane of CDI (§3F): when new malware the scanner misses shares concrete text --
a C2 address, a planted step, a dropper's command line -- a pack that matches that text can reach every
scanner through the feed within the hour, while a general rule waits for a release. Written by hand
once (the GhostAction indicator pack, 2026-10-23); this does it from the samples:

1. Read every text file of each miss (only dev-split, factory-eligible misses: never held-out data).
2. Candidate anchors are normalised lines (whitespace collapsed, 24 to 300 bytes) that recur across
   misses: in at least ``min_support`` of them.
3. An anchor that appears in ANY benign file is discarded. The benign search is exhaustive over the
   corpus given, not a sample: an indicator that matches one benign file blocks it.
4. A greedy cover keeps at most ``max_rules`` anchors, each adding misses the others do not reach.
5. Each anchor becomes a regex rule (literal text, whitespace-flexible) in a pack with a positive
   sample (the anchor) and a negative sample (a benign line from the corpus), so the loader's sample
   check and the pack-rules detector both hold.

The pack is a CANDIDATE: it goes through `bench/cdi/gate.py` on full sets like any other, and a pass earns
shadow only. Nothing here decides that it is right.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

TEXT_SUFFIXES = (
    ".yml",
    ".yaml",
    ".json",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".py",
    ".rb",
    ".sh",
    ".ps1",
    ".php",
    ".go",
    ".rs",
    ".cs",
    ".java",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
    ".md",
    ".gemspec",
    ".rake",
)
MAX_FILE_BYTES = 2_000_000
_SPACE = re.compile(rb"\s+")


class UnitText:
    """Every text file in one unit: a directory, or an archive (tar, gem, zip, wheel, vsix, nupkg)."""

    @staticmethod
    def files(path: str) -> Iterator[tuple[str, bytes]]:
        base = Path(path)
        if base.is_dir():
            for full in sorted(base.rglob("*")):
                if (
                    full.is_file()
                    and UnitText.texty(full.name)
                    and full.stat().st_size <= MAX_FILE_BYTES
                ):
                    yield full.relative_to(base).as_posix(), full.read_bytes()
            return
        yield from UnitText._archive(path)

    @staticmethod
    def _archive(path: str) -> Iterator[tuple[str, bytes]]:
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if UnitText.texty(info.filename) and info.file_size <= MAX_FILE_BYTES:
                            yield info.filename, archive.read(info)
                return
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    if not member.isfile() or member.size > 50 * MAX_FILE_BYTES:
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    if member.name.endswith(".tar.gz") or member.name == "data.tar.gz":
                        with tarfile.open(fileobj=io.BytesIO(handle.read())) as inner:
                            for sub in inner.getmembers():
                                if sub.isfile() and UnitText.texty(sub.name):
                                    data = inner.extractfile(sub)
                                    if data is not None and sub.size <= MAX_FILE_BYTES:
                                        yield sub.name, data.read()
                    elif UnitText.texty(member.name) and member.size <= MAX_FILE_BYTES:
                        yield member.name, handle.read()
        except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError):
            return

    @staticmethod
    def texty(name: str) -> bool:
        base = name.rsplit("/", 1)[-1]
        return base.lower().endswith(TEXT_SUFFIXES) or base in (
            "Rakefile",
            "Dockerfile",
            "Makefile",
        )


class Discovery:
    """From misses and a benign corpus, the anchors an indicator pack would match."""

    MIN_LEN, MAX_LEN = 24, 300

    @staticmethod
    def lines(blob: bytes) -> set[bytes]:
        out = set()
        for raw in blob.splitlines():
            line = _SPACE.sub(b" ", raw).strip()
            if Discovery.MIN_LEN <= len(line) <= Discovery.MAX_LEN and re.search(
                rb"[A-Za-z]", line
            ):
                out.add(line)
        return out

    @staticmethod
    def unit_lines(path: str) -> dict[bytes, str]:
        """Each distinct normalised line of the unit, with the file it came from."""
        found: dict[bytes, str] = {}
        for name, blob in UnitText.files(path):
            for line in Discovery.lines(blob):
                found.setdefault(line, name)
        return found

    @staticmethod
    def benign_lines(units: Iterable[str]) -> set[bytes]:
        seen: set[bytes] = set()
        for unit in units:
            for _, blob in UnitText.files(unit):
                seen |= Discovery.lines(blob)
        return seen

    @staticmethod
    def candidates(
        misses: dict[str, dict[bytes, str]], benign: set[bytes], min_support: int
    ) -> dict[bytes, set[str]]:
        support: dict[bytes, set[str]] = {}
        for unit, lines in misses.items():
            for line in lines:
                support.setdefault(line, set()).add(unit)
        return {
            line: units
            for line, units in support.items()
            if len(units) >= min_support and line not in benign
        }

    @staticmethod
    def cover(candidates: dict[bytes, set[str]], max_rules: int) -> list[tuple[bytes, set[str]]]:
        chosen: list[tuple[bytes, set[str]]] = []
        reached: set[str] = set()
        pool = dict(candidates)
        while pool and len(chosen) < max_rules:
            # Most new misses first; ties to the longer (more specific) line, then bytewise, so the
            # same input always gives the same pack.
            line = max(pool, key=lambda k: (len(pool[k] - reached), len(k), k))
            gain = pool.pop(line) - reached
            if not gain:
                break
            chosen.append((line, gain | (candidates[line] & reached)))
            reached |= gain
        return chosen

    @staticmethod
    def pattern(line: bytes) -> str:
        """The anchor as a regex: literal text, any run of whitespace where it had some."""
        text = line.decode("utf-8", "replace")
        return r"[ \t]{1,16}".join(re.escape(part) for part in text.split(" "))

    @staticmethod
    def pack(
        chosen: list[tuple[bytes, set[str]]],
        *,
        pack_id: str,
        reference: str,
        negative: str,
        paths: list[str],
    ) -> str:
        rules = []
        for index, (line, units) in enumerate(chosen, 1):
            sample = line.decode("utf-8", "replace")
            rules.append(
                {
                    "id": f"CDI.DISCOVERED.{hashlib.sha256(line).hexdigest()[:12].upper()}.001",
                    "version": "1.0.0",
                    "category": "malicious",
                    "severity": "high",
                    "confidence": "medium",
                    "title": f"Indicator {index} shared by a cluster of confirmed malware",
                    "message": (
                        f"This file contains text found in {len(units)} confirmed malicious samples "
                        "that the scanner missed, and in no benign file of the reference corpus."
                    ),
                    "remediation": "Do not install it; report it to the registry.",
                    "provenance": {"kind": "incident", "reference": reference},
                    "evidence_policy": "masked",
                    **({"paths": {"include": paths}} if paths else {}),
                    "match": {"kind": "regex", "patterns": [Discovery.pattern(line)]},
                    "tests": {"positive": [sample], "negative": [negative]},
                }
            )
        document = {
            "pack": {
                "id": pack_id,
                "version": "1.0.0",
                "license": "Apache-2.0",
                "description": "Generated by bench/cdi/discover.py; a candidate for the gate.",
            },
            "rules": rules,
        }
        return Discovery.yaml(document)

    @staticmethod
    def _scalar(value: Any) -> str:
        if isinstance(value, int):
            return str(value)
        return "'" + str(value).replace("'", "''") + "'"

    @staticmethod
    def yaml(value: Any, indent: int = 0) -> str:
        """Block YAML in the subset the rule loader reads: mappings, lists, single-quoted scalars."""
        pad = " " * indent
        out = []
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, (dict, list)):
                    out.append(f"{pad}{key}:\n" + Discovery.yaml(item, indent + 2))
                else:
                    out.append(f"{pad}{key}: {Discovery._scalar(item)}\n")
        else:
            for item in value:
                if isinstance(item, dict):
                    body = Discovery.yaml(item, indent + 2)
                    out.append(f"{pad}- " + body[indent + 2 :])
                else:
                    out.append(f"{pad}- {Discovery._scalar(item)}\n")
        return "".join(out)

    @staticmethod
    def run(
        miss_units: list[str],
        benign_units: list[str],
        *,
        min_support: int,
        max_rules: int,
        pack_id: str,
        reference: str,
        paths: list[str],
    ) -> tuple[str | None, dict[str, Any]]:
        misses = {unit: Discovery.unit_lines(unit) for unit in miss_units}
        benign = Discovery.benign_lines(benign_units)
        found = Discovery.candidates(misses, benign, min_support)
        chosen = Discovery.cover(found, max_rules)
        covered = set().union(*(units for _, units in chosen)) if chosen else set()
        report = {
            "kind": "DiscoveryReport",
            "misses": len(misses),
            "benign_units": len(benign_units),
            "benign_lines": len(benign),
            "candidates": len(found),
            "rules": len(chosen),
            "misses_covered": len(covered),
            "uncovered": sorted(set(misses) - covered),
        }
        if not chosen:
            return None, report  # nothing generalisable: reported, not forced
        negative = next(iter(sorted(benign)), b"benign line").decode("utf-8", "replace")
        return (
            Discovery.pack(
                chosen, pack_id=pack_id, reference=reference, negative=negative, paths=paths
            ),
            report,
        )

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument(
            "--misses", required=True, help="file listing miss units (dev split only)"
        )
        parser.add_argument(
            "--benign", required=True, help="file listing benign units, searched in full"
        )
        parser.add_argument("--root", default=".", help="directory the unit paths are relative to")
        parser.add_argument("--min-support", type=int, default=3)
        parser.add_argument("--max-rules", type=int, default=5)
        parser.add_argument("--pack-id", required=True)
        parser.add_argument("--reference", required=True)
        parser.add_argument("--paths", action="append", default=[])
        parser.add_argument("--out", required=True)
        args = parser.parse_args(argv)

        def listed(name: str) -> list[str]:
            text = Path(name).read_text(encoding="utf-8")
            return [
                str(Path(args.root) / line.strip()) for line in text.splitlines() if line.strip()
            ]

        pack, report = Discovery.run(
            listed(args.misses),
            listed(args.benign),
            min_support=args.min_support,
            max_rules=args.max_rules,
            pack_id=args.pack_id,
            reference=args.reference,
            paths=args.paths,
        )
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "discovery_report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
        if pack is not None:
            (out / f"rulepack-{args.pack_id.replace('.', '-')}.yaml").write_text(
                pack, encoding="utf-8"
            )
        print(json.dumps({k: v for k, v in report.items() if k != "uncovered"}))
        return 0 if pack is not None else 1


if __name__ == "__main__":
    sys.exit(Discovery.main())
