#!/usr/bin/env python3
"""The content-malware misses, grouped by shape (advanced gap P2).

`run.py malware` records a verdict per sample. This reopens every sample Cordon passed -- read in
memory, never extracted to disk, never run, inside a container with no network -- and describes
each by structural features only: what kinds of files it holds, whether it declares install-time
code, whether it ships a binary, how much code there is, whether that code is minified or packed
onto very long lines. Samples with the same features form a cluster, and the clusters, largest
first, are the taxonomy of what content analysis does not catch. Nothing a sample contains is
printed: feature names and counts only.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v "$PWD/bench:/bench2:ro" \\
      -v "$PWD/bench/results/full-2026-10-07:/results" --entrypoint python cordon-bench:dev \\
      /bench2/miss_clusters.py
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

MAX_MEMBER = 4 << 20
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
    ".go",
    ".rs",
    ".java",
    ".cs",
)
BINARY = (".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".pyd", ".jar", ".wasm")


class Features:
    """A sample's shape, from its member names and sizes and a look at its code's line lengths."""

    @staticmethod
    def members(archive: Path, password: bytes | None) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        try:
            if archive.suffix in (".zip", ".whl", ".vsix"):
                with zipfile.ZipFile(archive) as outer:
                    for info in outer.infolist()[:5000]:
                        if info.is_dir() or info.file_size > MAX_MEMBER:
                            continue
                        data = outer.read(info, pwd=password)
                        if info.filename.endswith((".tgz", ".tar.gz", ".whl", ".zip")):
                            out += Features.nested(info.filename, data)
                        else:
                            out.append((info.filename, data))
            else:
                with tarfile.open(archive, "r:*") as outer:
                    for member in outer.getmembers()[:5000]:
                        if member.isfile() and member.size <= MAX_MEMBER:
                            handle = outer.extractfile(member)
                            if handle is not None:
                                out.append((member.name, handle.read()))
        except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError, ValueError, EOFError):
            return out
        return out

    @staticmethod
    def nested(name: str, data: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        try:
            if name.endswith((".whl", ".zip")):
                with zipfile.ZipFile(io.BytesIO(data)) as inner:
                    out += [
                        (i.filename, inner.read(i))
                        for i in inner.infolist()[:5000]
                        if not i.is_dir() and i.file_size <= MAX_MEMBER
                    ]
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as inner:
                    for member in inner.getmembers()[:5000]:
                        if member.isfile() and member.size <= MAX_MEMBER:
                            handle = inner.extractfile(member)
                            if handle is not None:
                                out.append((member.name, handle.read()))
        except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError, ValueError, EOFError):
            return out
        return out

    @staticmethod
    def of(members: list[tuple[str, bytes]]) -> tuple[str, ...]:
        names = [n.lower() for n, _ in members]
        code = [(n, d) for n, d in members if n.lower().endswith(CODE)]
        code_bytes = sum(len(d) for _, d in code)
        features: list[str] = []
        if not members:
            return ("unreadable",)
        if not code:
            features.append("no-code")
        elif code_bytes < 400:
            features.append("tiny-code")
        elif code_bytes > 2 << 20:
            features.append("large-code")
        if any(n.endswith(BINARY) for n in names):
            features.append("binary")
        manifest = next((d for n, d in members if n.lower().endswith("package.json")), None)
        if manifest is not None:
            try:
                scripts = json.loads(manifest).get("scripts") or {}
            except (ValueError, AttributeError):
                scripts = {}
            if any(k in scripts for k in ("preinstall", "install", "postinstall", "prepare")):
                features.append("npm-install-hook")
        if any(n.endswith("setup.py") for n in names):
            features.append("setup.py")
        if any(n.endswith(".pth") for n in names):
            features.append("pth")
        longest = max(
            (max((len(line) for line in d.split(b"\n")), default=0) for _, d in code), default=0
        )
        if longest > 5000:
            features.append("very-long-lines")
        languages = sorted({n.rsplit(".", 1)[-1] for n, _ in code})[:3]
        features.append("lang:" + "+".join(languages) if languages else "lang:none")
        return tuple(features)


if __name__ == "__main__":
    import run as harness

    results = Path("/results/results.json")
    collected: dict[str, Any] = json.loads(results.read_text(encoding="utf-8"))
    verdicts = collected.get("malware", {}).get("verdicts") or collected.get("verdicts") or []
    missed = {
        v["sample"] for v in verdicts if v.get("tool") == "cordon" and v.get("blocked") is False
    }
    samples = {
        name: (path, ecosystem)
        for name, path, ecosystem in harness.Harness.malware_samples(Path("/data"))
    }
    clusters: Counter[tuple[str, ...]] = Counter()
    by_source: Counter[str] = Counter()
    for name in sorted(missed):
        if name not in samples:
            continue
        path, _ = samples[name]
        password = b"infected" if name.startswith("datadog/") else None
        clusters[Features.of(Features.members(path, password))] += 1
        by_source[name.split("/", 1)[0]] += 1
    report = {
        "missed": len(missed),
        "by_source": dict(by_source),
        "clusters": [{"features": list(k), "samples": n} for k, n in clusters.most_common()],
    }
    Path("/results/miss-clusters.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps({"missed": report["missed"], "by_source": report["by_source"]}))
    for row in report["clusters"][:30]:
        print(f"{row['samples']:6}  {' '.join(row['features'])}")
