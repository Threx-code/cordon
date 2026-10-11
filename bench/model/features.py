#!/usr/bin/env python3
"""Features of each package in the manifest, read in memory: never extracted to disk, never run.

Two kinds, from the package's own files:

    dense   structure and capability counts: how much code, how long its lines, how random its
            strings, encoded blobs, obfuscator markers, dynamic execution, process spawning,
            network, environment and sensitive-file reads, install hooks, binaries, and
            destinations with no business in a library (chat webhooks, paste sites, raw IPs)
    tokens  the identifiers and API names the code uses, hashed into a fixed-width sparse row

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-random:/random:ro \\
      -v "$PWD/bench/model:/model" -v cordon-model-work:/work cordon-model:dev python features.py
"""

from __future__ import annotations

import argparse
import io
import json
import math
import re
import sys
import tarfile
import zipfile
import zlib
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from scipy import sparse

MAX_FILES = 3000
MAX_FILE = 2 << 20
MAX_TOTAL = 40 << 20
TOKEN_DIM = 1 << 18
CODE = (
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".jsx",
    ".tsx",
    ".py",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".rb",
    ".php",
    ".vbs",
    ".pl",
)
BINARY = (".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".pyd", ".pyc", ".jar", ".scr", ".msi")
#: What each pattern feature counts, in feature order. A data file, as the scanner keeps its own rule
#: patterns: the vocabulary of attacks named in code is what Cordon reports in code.
PATTERNS: dict[str, re.Pattern[bytes]] = {
    name: re.compile(p.encode())
    for name, p in json.loads(
        (Path(__file__).parent / "patterns.json").read_text(encoding="utf-8")
    ).items()
}
DENSE = [
    "n_files", "n_code", "n_binary", "log_code_bytes", "log_max_line", "frac_long_lines", "mean_entropy",
    "max_entropy", "n_dirs_depth", "has_install_hook", "log_hook_len", "hook_runs_node", "hook_runs_shell",
    "has_setup_py", "pkg_no_repo", "pkg_no_description", "version_weird", "n_scripts", *PATTERNS.keys(),
]  # fmt: skip
TOKEN = re.compile(rb"[A-Za-z_][A-Za-z0-9_.]{2,40}")


class Archive:
    """The files of a package, from whatever it was published as."""

    @staticmethod
    def members(data: bytes, depth: int = 0) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        total = 0
        if data[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.setpassword(b"infected")
                for info in z.infolist()[:MAX_FILES]:
                    if info.is_dir() or info.file_size > MAX_FILE or total > MAX_TOTAL:
                        continue
                    try:
                        body = z.read(info)
                    except (
                        RuntimeError,
                        zipfile.BadZipFile,
                        NotImplementedError,
                        zlib.error,
                        EOFError,
                    ):
                        continue
                    total += len(body)
                    out.append((info.filename, body))
        else:
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
                    for member in t:
                        if len(out) >= MAX_FILES or total > MAX_TOTAL:
                            break
                        if not member.isfile() or member.size > MAX_FILE:
                            continue
                        handle = t.extractfile(member)
                        if handle is None:
                            continue
                        body = handle.read()
                        total += len(body)
                        out.append((member.name, body))
            except (tarfile.TarError, EOFError, OSError, zlib.error):
                return []
        # A DataDog sample holding exactly one package archive (and its package_info): that archive.
        if depth < 2:
            inner = [(n, b) for n, b in out if n.endswith((".tgz", ".tar.gz", ".whl", ".zip"))]
            rest = [
                n
                for n, _ in out
                if not n.endswith((".tgz", ".tar.gz", ".whl", ".zip")) and "package_info" not in n
            ]
            if len(inner) == 1 and not rest:
                return Archive.members(inner[0][1], depth + 1)
        return [(n, b) for n, b in out if "package_info" not in n.rsplit("/", 1)[-1]]


class Features:
    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data[:65536])
        n = sum(counts.values())
        return -sum(c / n * math.log2(c / n) for c in counts.values())

    @staticmethod
    def of(files: list[tuple[str, bytes]]) -> tuple[np.ndarray, dict[int, float]]:
        dense = dict.fromkeys(DENSE, 0.0)
        tokens: Counter[int] = Counter()
        entropies: list[float] = []
        long_lines = lines = 0
        code_bytes = 0
        max_line = 0
        dense["n_files"] = len(files)
        for name, body in files:
            lower = name.lower()
            dense["n_dirs_depth"] = max(dense["n_dirs_depth"], name.count("/"))
            if lower.endswith(BINARY):
                dense["n_binary"] += 1
            if lower.endswith("setup.py"):
                dense["has_setup_py"] = 1
            if lower.endswith("package.json") and lower.count("/") <= 1:
                Features.package_json(body, dense)
            if not lower.endswith(CODE) and not lower.endswith(
                ("setup.py", "package.json", ".json")
            ):
                continue
            if lower.endswith(CODE):
                dense["n_code"] += 1
                code_bytes += len(body)
                entropies.append(Features.entropy(body))
                for line in body.split(b"\n")[:20000]:
                    lines += 1
                    max_line = max(max_line, len(line))
                    long_lines += len(line) > 1000
                for match in TOKEN.finditer(body[:262144]):
                    tokens[zlib.crc32(match.group(0)) % TOKEN_DIM] = 1
            for key, pattern in PATTERNS.items():
                dense[key] += len(pattern.findall(body[:MAX_FILE]))
        dense["log_code_bytes"] = math.log1p(code_bytes)
        dense["log_max_line"] = math.log1p(max_line)
        dense["frac_long_lines"] = long_lines / max(lines, 1)
        dense["mean_entropy"] = sum(entropies) / len(entropies) if entropies else 0.0
        dense["max_entropy"] = max(entropies, default=0.0)
        for key in PATTERNS:
            dense[key] = math.log1p(dense[key])
        return np.array([dense[k] for k in DENSE], dtype=np.float32), dict(tokens)

    @staticmethod
    def package_json(body: bytes, dense: dict[str, float]) -> None:
        try:
            manifest = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(manifest, dict):
            return
        scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
        dense["n_scripts"] = len(scripts)
        hook = " ".join(
            str(scripts.get(k) or "") for k in ("preinstall", "install", "postinstall", "prepare")
        )
        if hook.strip():
            dense["has_install_hook"] = 1
            dense["log_hook_len"] = math.log1p(len(hook))
            dense["hook_runs_node"] = float(bool(re.search(r"\bnode\b", hook)))
            dense["hook_runs_shell"] = float(
                bool(re.search(r"\b(?:sh|bash|curl|wget|powershell)\b", hook))
            )
        dense["pkg_no_repo"] = float(not manifest.get("repository"))
        dense["pkg_no_description"] = float(not manifest.get("description"))
        version = str(manifest.get("version") or "")
        dense["version_weird"] = float(
            bool(re.match(r"^(?:0\.0\.\d+|\d{2,}\.\d+\.\d+|99\.)", version))
        )


class FeatureJob:
    @staticmethod
    def one(row: dict[str, str]) -> tuple[np.ndarray, dict[int, float], bool]:
        root = Path("/data") if row["volume"] == "data" else Path("/random")
        try:
            files = Archive.members((root / row["path"]).read_bytes())
        except (OSError, zipfile.BadZipFile, ValueError):
            files = []
        dense, tokens = Features.of(files)
        return dense, tokens, bool(files)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--manifest", type=Path, default=Path("/work/manifest.jsonl"))
        parser.add_argument("--out", type=Path, default=Path("/work/features"))
        parser.add_argument("--workers", type=int, default=8)
        args = parser.parse_args()
        rows = [
            json.loads(line)
            for line in args.manifest.read_text(encoding="utf-8").splitlines()
            if line
        ]
        with Pool(args.workers) as pool:
            results = pool.map(FeatureJob.one, rows, chunksize=64)
        dense = np.vstack([r[0] for r in results])
        data, indices, indptr = [], [], [0]
        for _, tokens, _ in results:
            indices += list(tokens.keys())
            data += list(tokens.values())
            indptr.append(len(indices))
        token_matrix = sparse.csr_matrix(
            (np.array(data, dtype=np.float32), indices, indptr), shape=(len(rows), TOKEN_DIM)
        )
        args.out.mkdir(parents=True, exist_ok=True)
        np.save(args.out / "dense.npy", dense)
        sparse.save_npz(args.out / "tokens.npz", token_matrix)
        (args.out / "read.json").write_text(json.dumps([r[2] for r in results]), encoding="utf-8")
        (args.out / "dense_names.json").write_text(json.dumps(DENSE), encoding="utf-8")
        print(
            f"{len(rows)} packages; {sum(r[2] for r in results)} read; dense {dense.shape}; tokens nnz {token_matrix.nnz}"
        )
        return 0


if __name__ == "__main__":
    sys.exit(FeatureJob.main())
