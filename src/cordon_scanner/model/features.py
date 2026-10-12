"""What Cordon's detection model reads from a package: numbers, never its source.

Computed on the machine that runs the scan, in plain Python, so the model can run elsewhere -- in
Cordon Cloud, or a model server inside an organisation's network -- without any of the code
leaving. Two views of one package:

    package   structure and capability counts (`PACKAGE_DENSE`) and the identifiers its code
              uses, each hashed to one of `TOKEN_DIM` buckets (CRC-32): a bucket number says that
              some identifier hashing there appears, never which
    files     per code file, what it does and how it looks (`FILE_DENSE`): a compromised library
              is one bad file among hundreds of clean ones, and the worst file is what is scored

These are exactly the features the model was trained on (`bench/model/`, which imports this
module): a feature computed differently here than in training would be a model scoring inputs it
never saw. Archives are read in memory with hard limits on members, bytes per member and bytes in
all, whatever their headers declare.
"""

from __future__ import annotations

import io
import json
import math
import re
import tarfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from typing import Any, Final

MAX_FILES: Final = 3000
MAX_FILE: Final = 2 << 20
MAX_TOTAL: Final = 40 << 20
TOKEN_DIM: Final = 1 << 18
PER_PACKAGE_FILES: Final = 96
CODE: Final = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".sh", ".ps1", ".bat", ".cmd", ".rb", ".php", ".vbs", ".pl")  # fmt: skip
BINARY: Final = (".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".pyd", ".pyc", ".jar", ".scr", ".msi")  # fmt: skip
_ARCHIVES: Final = (".tgz", ".tar.gz", ".whl", ".zip")

#: What each pattern feature counts, in feature order, from a data file as the rule packs are.
PATTERNS: Final[dict[str, re.Pattern[bytes]]] = {
    name: re.compile(p.encode())
    for name, p in json.loads(
        (Path(__file__).parent / "data" / "patterns.json").read_text(encoding="utf-8")
    ).items()
}
PACKAGE_DENSE: Final[tuple[str, ...]] = (
    "n_files", "n_code", "n_binary", "log_code_bytes", "log_max_line", "frac_long_lines", "mean_entropy",
    "max_entropy", "n_dirs_depth", "has_install_hook", "log_hook_len", "hook_runs_node", "hook_runs_shell",
    "has_setup_py", "pkg_no_repo", "pkg_no_description", "version_weird", "n_scripts", *PATTERNS,
)  # fmt: skip
FILE_DENSE: Final[tuple[str, ...]] = (
    "log_bytes", "log_lines", "log_max_line", "frac_long_lines", "entropy", "depth", "is_hook_target",
    "is_entry", "is_setup", "is_init", "is_test", "is_minified_name", "is_js", "is_py", "is_shell",
    "is_powershell", "pkg_n_code", "pkg_has_hook", "pkg_log_bytes", *PATTERNS,
)  # fmt: skip
_TOKEN: Final = re.compile(rb"[A-Za-z_][A-Za-z0-9_.]{2,40}")
_HOOK_FILE: Final = re.compile(r"(?:node|python3?|sh|bash)\s+([\w./-]+\.(?:js|cjs|mjs|py|sh))")
_TEST_PATH: Final = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)(?:/|$)|\.test\.|\.spec\.")


class PackageArchive:
    """A package's files from what it was published as, read in memory and bounded."""

    @staticmethod
    def members(
        data: bytes, password: bytes | None = None, depth: int = 0
    ) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        total = 0
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    if password is not None:
                        archive.setpassword(password)
                    for info in archive.infolist()[:MAX_FILES]:
                        if info.is_dir() or info.file_size > MAX_FILE or total > MAX_TOTAL:
                            continue
                        try:
                            with archive.open(info) as handle:
                                body = handle.read(MAX_FILE + 1)
                        except (
                            RuntimeError,
                            zipfile.BadZipFile,
                            NotImplementedError,
                            zlib.error,
                            EOFError,
                            OSError,
                        ):
                            continue
                        if len(body) > MAX_FILE:
                            continue
                        total += len(body)
                        out.append((info.filename, body))
            except (zipfile.BadZipFile, OSError, ValueError):
                return []
        else:
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for member in archive:
                        if len(out) >= MAX_FILES or total > MAX_TOTAL:
                            break
                        if not member.isfile() or member.size > MAX_FILE:
                            continue
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            continue
                        body = extracted.read(MAX_FILE + 1)
                        if len(body) > MAX_FILE:
                            continue
                        total += len(body)
                        out.append((member.name, body))
            except (tarfile.TarError, EOFError, OSError, zlib.error, ValueError):
                return []
        # A sample holding exactly one package archive (and a metadata file): that archive.
        if depth < 2:
            inner = [(n, b) for n, b in out if n.endswith(_ARCHIVES)]
            rest = [n for n, _ in out if not n.endswith(_ARCHIVES) and "package_info" not in n]
            if len(inner) == 1 and not rest:
                return PackageArchive.members(inner[0][1], password, depth + 1)
        return [(n, b) for n, b in out if "package_info" not in n.rsplit("/", 1)[-1]]

    @staticmethod
    def directory(root: Path) -> list[tuple[str, bytes]]:
        """A package's files from a directory, symlinks never followed, under the same limits."""
        out: list[tuple[str, bytes]] = []
        total = 0
        for path in sorted(root.rglob("*")):
            if len(out) >= MAX_FILES or total > MAX_TOTAL:
                break
            if path.is_symlink() or not path.is_file():
                continue
            try:
                if path.stat().st_size > MAX_FILE:
                    continue
                body = path.read_bytes()
            except OSError:
                continue
            total += len(body)
            out.append((path.relative_to(root).as_posix(), body))
        return out


class PackageFeatures:
    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data[:65536])
        n = sum(counts.values())
        return -sum(c / n * math.log2(c / n) for c in counts.values())

    @staticmethod
    def extract(files: list[tuple[str, bytes]]) -> tuple[list[float], list[int]]:
        """(dense, token buckets) for a package's files."""
        dense = dict.fromkeys(PACKAGE_DENSE, 0.0)
        tokens: set[int] = set()
        entropies: list[float] = []
        long_lines = lines = code_bytes = max_line = 0
        dense["n_files"] = len(files)
        for name, body in files:
            lower = name.lower()
            dense["n_dirs_depth"] = max(dense["n_dirs_depth"], name.count("/"))
            if lower.endswith(BINARY):
                dense["n_binary"] += 1
            if lower.endswith("setup.py"):
                dense["has_setup_py"] = 1
            if lower.endswith("package.json") and lower.count("/") <= 1:
                PackageFeatures.package_json(body, dense)
            if not lower.endswith(CODE) and not lower.endswith(
                ("setup.py", "package.json", ".json")
            ):
                continue
            if lower.endswith(CODE):
                dense["n_code"] += 1
                code_bytes += len(body)
                entropies.append(PackageFeatures.entropy(body))
                for line in body.split(b"\n")[:20000]:
                    lines += 1
                    max_line = max(max_line, len(line))
                    long_lines += len(line) > 1000
                for match in _TOKEN.finditer(body[:262144]):
                    tokens.add(zlib.crc32(match.group(0)) % TOKEN_DIM)
            for key, pattern in PATTERNS.items():
                dense[key] += len(pattern.findall(body[:MAX_FILE]))
        dense["log_code_bytes"] = math.log1p(code_bytes)
        dense["log_max_line"] = math.log1p(max_line)
        dense["frac_long_lines"] = long_lines / max(lines, 1)
        dense["mean_entropy"] = sum(entropies) / len(entropies) if entropies else 0.0
        dense["max_entropy"] = max(entropies, default=0.0)
        for key in PATTERNS:
            dense[key] = math.log1p(dense[key])
        return [dense[k] for k in PACKAGE_DENSE], sorted(tokens)

    @staticmethod
    def package_json(body: bytes, dense: dict[str, float]) -> None:
        try:
            manifest = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(manifest, dict):
            return
        raw_scripts = manifest.get("scripts")
        scripts: dict[str, Any] = raw_scripts if isinstance(raw_scripts, dict) else {}
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


class FileFeatures:
    @staticmethod
    def hook_targets(files: list[tuple[str, bytes]]) -> tuple[set[str], set[str], bool]:
        """Files the package's install hooks and entry points name, by path tail."""
        hooks: set[str] = set()
        entries: set[str] = set()
        has_hook = False
        for name, body in files:
            lower = name.lower()
            if lower.endswith("package.json") and lower.count("/") <= 1:
                try:
                    manifest = json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(manifest, dict):
                    continue
                raw_scripts = manifest.get("scripts")
                scripts: dict[str, Any] = raw_scripts if isinstance(raw_scripts, dict) else {}
                for key in ("preinstall", "install", "postinstall", "prepare"):
                    command = str(scripts.get(key) or "")
                    if command:
                        has_hook = True
                        hooks.update(m.lstrip("./") for m in _HOOK_FILE.findall(command))
                for key in ("main", "module", "bin"):
                    value = manifest.get(key)
                    values = value.values() if isinstance(value, dict) else [value]
                    entries.update(str(v).lstrip("./") for v in values if isinstance(v, str))
            if lower.endswith("setup.py"):
                has_hook = has_hook or b"cmdclass" in body
        return hooks, entries, has_hook

    @staticmethod
    def rows(files: list[tuple[str, bytes]]) -> list[list[float]]:
        """One row per code file, at most `PER_PACKAGE_FILES`: every file a hook or entry point
        names, then those whose patterns count the most."""
        files = [(n, b) for n, b in files if not n.lower().endswith(BINARY)]
        hooks, entries, has_hook = FileFeatures.hook_targets(files)
        code = [(n, b) for n, b in files if n.lower().endswith((*CODE, "setup.py"))]
        package = {
            "pkg_n_code": math.log1p(len(code)),
            "pkg_has_hook": float(has_hook),
            "pkg_log_bytes": math.log1p(sum(len(b) for _, b in code)),
        }
        scored: list[tuple[float, bool, list[float]]] = []
        for name, body in code:
            lower = name.lower()
            tail = name.split("/", 1)[1] if "/" in name else name
            counts = {k: len(p.findall(body[:MAX_FILE])) for k, p in PATTERNS.items()}
            lines = body.split(b"\n")[:20000]
            longest = max((len(x) for x in lines), default=0)
            base = lower.rsplit("/", 1)[-1]
            hook_target = tail in hooks or any(tail.endswith(h) for h in hooks)
            values = {
                "log_bytes": math.log1p(len(body)),
                "log_lines": math.log1p(len(lines)),
                "log_max_line": math.log1p(longest),
                "frac_long_lines": sum(len(x) > 1000 for x in lines) / max(len(lines), 1),
                "entropy": PackageFeatures.entropy(body),
                "depth": float(name.count("/")),
                "is_hook_target": float(hook_target),
                "is_entry": float(tail in entries),
                "is_setup": float(base == "setup.py"),
                "is_init": float(base == "__init__.py"),
                "is_test": float(bool(_TEST_PATH.search(lower))),
                "is_minified_name": float(".min." in base),
                "is_js": float(base.endswith((".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx"))),
                "is_py": float(base.endswith(".py")),
                "is_shell": float(base.endswith((".sh", ".bat", ".cmd"))),
                "is_powershell": float(base.endswith(".ps1")),
                **package,
                **{k: math.log1p(v) for k, v in counts.items()},
            }
            scored.append(
                (
                    float(sum(counts.values())),
                    hook_target or tail in entries,
                    [values[k] for k in FILE_DENSE],
                )
            )
        named = [r for r in scored if r[1]]
        rest = sorted((r for r in scored if not r[1]), key=lambda r: -r[0])
        return [r[2] for r in named + rest[: max(0, PER_PACKAGE_FILES - len(named))]]
