#!/usr/bin/env python3
"""Content recall that no shape of sample can flatter (MEAS-4).

```
  run.py malware results ──► per sample: caught by content? (not by an intel lookup)
        │
        ├── shape (structure only, read in memory): placeholder, empty, tiny code without network
        │   or process use  ──►  "no payload" row: nothing in it for content analysis to find
        │
        └── campaign (bench/model's MinHash groups)  ──►  recall averaged per campaign, so 3,000
            copies of one payload count once
```

Reported: content recall on all samples, on payload-bearing samples (with a 95% Wilson interval),
per campaign, and the no-payload row with its count. Structural features only -- names, sizes,
whether network or process primitives appear -- never a sample's content.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-results:/results:ro \\
      -v cordon-model-work:/work:ro -v "$PWD:/s:ro" python:3.12-slim \\
      python -I /s/bench/shapes.py /results/results.json /work/manifest.jsonl
"""

from __future__ import annotations

import io
import json
import re
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run import Wilson

DATA = Path("/data")
MAX = 4 << 20
CODE = (
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".py",
    ".rb",
    ".php",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".go",
    ".rs",
)
BINARY = (".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".pyd", ".jar", ".wasm", ".msi", ".scr")
NETWORK = re.compile(
    rb"https?://|\brequire\(['\"](https?|net|dns|child_process)['\"]\)|\bfetch\(|XMLHttpRequest|urllib"
    rb"|requests\.|socket\.|discord(app)?\.com/api/webhooks|ngrok|pipedream|burpcollaborator|oast\.|interact\.sh"
)
PROCESS = re.compile(
    rb"child_process|exec(Sync)?\(|spawn\(|subprocess|os\.system|eval\(|new Function|Function\(|exec\("
)
NO_PAYLOAD = ("A ", "E ", "E2 ")
"""Shapes with nothing for content analysis to find: a registry's security placeholder, no code
at all, or under 400 bytes of code with no network or process primitive."""


class Shapes:
    """Each sample's structure, after review 98's `tools/miss_shape.py`."""

    @staticmethod
    def members(path: Path, password: bytes | None) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        try:
            if path.name.endswith((".zip", ".whl", ".vsix", ".egg")):
                with zipfile.ZipFile(path) as bundle:
                    for info in bundle.infolist()[:5000]:
                        if info.is_dir() or info.file_size > MAX:
                            continue
                        data = bundle.read(info, pwd=password)
                        if info.filename.endswith(
                            (".tgz", ".tar.gz", ".whl", ".zip", ".vsix", ".gz")
                        ):
                            out.extend(Shapes.nested(info.filename, data))
                        else:
                            out.append((info.filename, data))
            else:
                with tarfile.open(path, "r:*") as bundle:
                    for member in bundle.getmembers()[:5000]:
                        if member.isfile() and member.size <= MAX:
                            handle = bundle.extractfile(member)
                            if handle:
                                out.append((member.name, handle.read()))
        except (
            OSError,
            zipfile.BadZipFile,
            tarfile.TarError,
            RuntimeError,
            NotImplementedError,
            EOFError,
        ):
            return out
        return out

    @staticmethod
    def nested(name: str, data: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        try:
            if name.endswith((".whl", ".zip", ".vsix")):
                with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                    out.extend(
                        (i.filename, bundle.read(i))
                        for i in bundle.infolist()[:5000]
                        if not i.is_dir() and i.file_size <= MAX
                    )
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as bundle:
                    for member in bundle.getmembers()[:5000]:
                        if member.isfile() and member.size <= MAX:
                            handle = bundle.extractfile(member)
                            if handle:
                                out.append((member.name, handle.read()))
        except (
            OSError,
            zipfile.BadZipFile,
            tarfile.TarError,
            RuntimeError,
            NotImplementedError,
            EOFError,
        ):
            out.append((name + "#unreadable-nested", b""))
        return out

    @staticmethod
    def kind(files: list[tuple[str, bytes]]) -> str:
        if not files:
            return "U unreadable"
        names = [n.lower() for n, _ in files]
        code = [d for n, d in files if n.lower().endswith(CODE)]
        size = sum(len(d) for d in code)
        manifest = sorted(
            (
                (n.count("/"), d)
                for n, d in files
                if n.lower().endswith("package.json") and "node_modules" not in n
            ),
            key=lambda pair: pair[0],
        )
        hook = placeholder = remote = False
        dependencies = 0
        if manifest:
            try:
                package = json.loads(manifest[0][1])
                scripts = package.get("scripts") or {}
                hook = any(
                    k in scripts
                    for k in ("preinstall", "install", "postinstall", "prepare", "preuninstall")
                )
                version = str(package.get("version", ""))
                placeholder = (
                    version.endswith("-security")
                    or "security holding" in str(package.get("description", "")).lower()
                )
                wanted = {
                    **(package.get("dependencies") or {}),
                    **(package.get("optionalDependencies") or {}),
                }
                dependencies = len(wanted)
                remote = any(
                    re.match(r"(https?:|git\+|github:|[\w-]+/[\w.-]+$)", str(v))
                    for v in wanted.values()
                )
            except (ValueError, AttributeError, TypeError):
                pass
        blob = b"\n".join(code)
        if placeholder:
            return "A placeholder"
        if any(n.endswith("skill.md") for n in names):
            return "S skill"
        if size == 0 and any(n.endswith(BINARY) for n in names):
            return "B binary only"
        if size == 0 and remote:
            return "D manifest only, remote dependency"
        if size == 0 and hook:
            return "H manifest only, install hook"
        if size == 0 and dependencies:
            return "D2 manifest only, registry dependencies"
        if size == 0:
            return "E empty, no code"
        if size < 400 and not (NETWORK.search(blob) or PROCESS.search(blob)):
            return "E2 tiny code, no network or process use"
        return "C code"


class RecallViews:
    @staticmethod
    def archive(sample: str) -> tuple[Path, bytes | None]:
        source, _, rest = sample.partition("/")
        if source == "datadog":
            return DATA / "datadog" / "samples" / rest, b"infected"
        return DATA / "malregistry" / rest, None

    @staticmethod
    def campaigns(manifest: Path) -> dict[str, str]:
        """Sample id (as run.py names it) -> campaign, from bench/model's manifest."""
        out: dict[str, str] = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            path = str(row.get("path", ""))
            sample = (
                "datadog/" + path.removeprefix("datadog/samples/")
                if path.startswith("datadog/samples/")
                else path
            )
            out[sample] = str(row.get("campaign"))
        return out

    @classmethod
    def report(cls, results: Path, manifest: Path) -> dict[str, object]:
        document = json.loads(results.read_text(encoding="utf-8"))
        verdicts = [
            v
            for v in document["malware"]["verdicts"]
            if v["tool"] == "cordon" and v["blocked"] is not None
        ]
        campaign_of = cls.campaigns(manifest)
        by_kind: Counter[str] = Counter()
        caught_by_kind: Counter[str] = Counter()
        per_campaign: dict[str, list[bool]] = defaultdict(list)
        for verdict in verdicts:
            content = bool(verdict["blocked"]) and verdict.get("detail") != "identity-only"
            path, password = cls.archive(verdict["sample"])
            kind = Shapes.kind(Shapes.members(path, password)) if path.exists() else "M missing"
            by_kind[kind] += 1
            caught_by_kind[kind] += content
            per_campaign[campaign_of.get(verdict["sample"], verdict["sample"])].append(content)
        no_payload = sum(n for k, n in by_kind.items() if k.startswith(NO_PAYLOAD))
        bearing = sum(by_kind.values()) - no_payload
        caught_bearing = sum(n for k, n in caught_by_kind.items() if not k.startswith(NO_PAYLOAD))
        campaign_rates = [sum(c) / len(c) for c in per_campaign.values()]
        return {
            "samples": sum(by_kind.values()),
            "content_recall_all": round(
                sum(caught_by_kind.values()) / max(sum(by_kind.values()), 1), 4
            ),
            "no_payload": no_payload,
            "payload_bearing": bearing,
            "content_recall_payload_bearing": round(caught_bearing / max(bearing, 1), 4),
            "content_recall_payload_bearing_95": list(Wilson.interval(caught_bearing, bearing)),
            "campaigns": len(per_campaign),
            "content_recall_per_campaign": round(
                sum(campaign_rates) / max(len(campaign_rates), 1), 4
            ),
            "by_shape": {
                k: {"samples": n, "caught": caught_by_kind[k]} for k, n in by_kind.most_common()
            },
        }


if __name__ == "__main__":
    print(json.dumps(RecallViews.report(Path(sys.argv[1]), Path(sys.argv[2])), indent=1))
