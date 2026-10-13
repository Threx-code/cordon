#!/usr/bin/env python3
"""Show what a reviewer needs to adjudicate a content block: re-fetch the archive by its manifest
URL and digest, read it in memory, print the install scripts and the head of each flagged file.
Nothing is extracted to disk or run. Text is printed truncated, with control and bidi characters
escaped so nothing in a package can rewrite the reviewer's terminal.

Record each reading as one line of `adjudication.jsonl`: {"file", "rules", "verdict": "TP"|"FP",
"class", "reason", "reviewer"}. Two different reviewers per block; a third on disagreement.

    python3 bench/adjudicate.py tally bench/longtail/adjudication.jsonl

    docker run --rm -v "$PWD:/r:ro" python:3.12-slim \
      python -I /r/bench/adjudicate.py show /r/bench/longtail npm/<file> [npm/<file> ...]

`show` refuses files in the holdout half (`longtail_levels.Split`) unless `--release` is given:
holdout blocks are read only for the release-time adjudication, never while tuning.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

UA = {"User-Agent": "cordon-benign-corpus-study (research)"}


class Adjudicate:
    @staticmethod
    def safe(text: str, width: int = 220) -> str:
        out = []
        for ch in text:
            o = ord(ch)
            if ch == "\t":
                out.append("  ")
            elif (
                o < 32
                or 0x7F <= o < 0xA0
                or 0x200B <= o <= 0x200F
                or 0x202A <= o <= 0x202E
                or 0x2066 <= o <= 0x2069
                or 0xFE00 <= o <= 0xFE0F
                or 0xE0000 <= o <= 0xE007F
            ):
                out.append(f"\\u{o:04x}")
            else:
                out.append(ch)
        s = "".join(out)
        return s if len(s) <= width else s[:width] + f" …(+{len(s) - width})"

    @staticmethod
    def members(body: bytes, name: str):
        if name.endswith((".zip", ".whl", ".nupkg", ".vsix", ".jar")):
            with zipfile.ZipFile(io.BytesIO(body)) as z:
                for i in z.infolist():
                    if not i.is_dir() and i.file_size < 4 << 20:
                        yield i.filename, z.read(i)
        else:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as t:
                for m in t.getmembers():
                    if m.isfile() and m.size < 4 << 20:
                        yield m.name, t.extractfile(m).read()

    @staticmethod
    def holdout_refused(manifest: dict, files: list[str]) -> list[str]:
        """Files in the holdout half. Reading one while rules are being tuned leaks it into the
        tuning, so `show` refuses them unless the reading is the release-time adjudication."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from longtail_levels import Split

        return [
            f
            for f in files
            if f in manifest
            and Split.of(manifest[f]["ecosystem"], manifest[f]["name"]) == "holdout"
        ]

    @staticmethod
    def show(data: Path, files: list[str], release: bool = False) -> None:
        manifest = {
            json.loads(x)["file"]: json.loads(x)
            for x in (data / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
        }
        refused = [] if release else Adjudicate.holdout_refused(manifest, files)
        if refused:
            raise SystemExit(
                f"refusing {len(refused)} holdout file(s) (e.g. {refused[0]}): the holdout half is "
                "read only at release. Pass --release for the release-time adjudication."
            )
        scans = {
            json.loads(x)["file"]: json.loads(x)
            for x in (data / "scans.jsonl").read_text(encoding="utf-8").splitlines()
        }
        for f in files:
            m, s = manifest.get(f), scans.get(f)
            print("=" * 100)
            print(f, "|", (m or {}).get("name"), (m or {}).get("version"))
            if not m or not s:
                print("  not in manifest/scans")
                continue
            hits = [
                x
                for x in s.get("findings", [])
                if not x[0].startswith("OPERATIONAL.") and x[1] in ("high", "critical", "medium")
            ]
            for rule, sev, conf, cat, path in hits[:12]:
                print(f"  {sev}/{conf} {cat} {rule}  @ {path}")
            body = urllib.request.urlopen(
                urllib.request.Request(m["url"], headers=UA), timeout=90
            ).read()
            algo, want = m["digest"].split(":", 1)
            if want and hashlib.new(algo, body).hexdigest() != want:
                print("  DIGEST MISMATCH -- not shown")
                continue
            flagged = {p for *_, p in hits}
            for name, data_ in Adjudicate.members(body, m["url"].split("?")[0]):
                short = name.split("/", 1)[-1] if "/" in name else name
                if name.endswith("package.json") and name.count("/") <= 1:
                    try:
                        pj = json.loads(data_)
                        print(
                            "  package.json scripts:",
                            Adjudicate.safe(json.dumps(pj.get("scripts", {})), 600),
                        )
                        print(
                            "  description:",
                            Adjudicate.safe(str(pj.get("description", "")), 200),
                            "| repo:",
                            Adjudicate.safe(str(pj.get("repository", "")), 120),
                        )
                    except ValueError:
                        pass
                if any(name.endswith(p) or p.endswith(short) for p in flagged):
                    if b"\x00" in data_[:4096]:
                        print(
                            f"  --- {Adjudicate.safe(name, 160)} ({len(data_)} bytes, binary: not shown)"
                        )
                        continue
                    text = data_.decode("utf-8", "replace")
                    lines = text.splitlines()
                    print(
                        f"  --- {Adjudicate.safe(name, 160)} ({len(data_)} bytes, {len(lines)} lines)"
                    )
                    for i, line in enumerate(
                        lines[: int(__import__("os").environ.get("LINES_SHOWN", "25"))], 1
                    ):
                        print(f"    {i:3} {Adjudicate.safe(line)}")

    @staticmethod
    def tally(records: Path) -> dict[str, object]:
        """Settle each block from independent readings: a verdict counts once TWO different
        reviewers agree on it; a disagreement waits for a third. Block precision is reported over
        settled blocks only, with its interval -- an unsettled block is not quietly counted."""
        from collections import defaultdict

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from run import Wilson

        readings: dict[str, dict[str, str]] = defaultdict(dict)
        for line in records.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                readings[row["file"]][row.get("reviewer", "unnamed")] = row["verdict"]
        settled: dict[str, str] = {}
        waiting: list[str] = []
        for file, by_reviewer in readings.items():
            votes = list(by_reviewer.values())
            winner = max(set(votes), key=votes.count)
            if (
                len(by_reviewer) >= 2
                and votes.count(winner) >= 2
                and votes.count(winner) > len(votes) / 2
            ):
                settled[file] = winner
            else:
                waiting.append(file)
        true = sum(1 for v in settled.values() if v == "TP")
        return {
            "settled": len(settled),
            "waiting_for_a_reviewer": len(waiting),
            "true_positive": true,
            "false_positive": sum(1 for v in settled.values() if v == "FP"),
            "block_precision": round(true / max(len(settled), 1), 4),
            "block_precision_95": list(Wilson.interval(true, len(settled))),
        }


if __name__ == "__main__":
    if sys.argv[1:2] == ["tally"]:
        print(json.dumps(Adjudicate.tally(Path(sys.argv[2])), indent=1))
    else:
        rest = [a for a in sys.argv[3:] if a != "--release"]
        Adjudicate.show(Path(sys.argv[2]), rest, release="--release" in sys.argv[3:])
