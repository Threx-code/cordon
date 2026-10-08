"""Measures every fetched GuardDog rule on the benchmark datasets: how many benign PyPI packages it
fires on (noise) and how many known-malicious npm and PyPI packages (value). The result is written
beside the pack as MEASUREMENT.json, which `yara_select.py` chooses from.

Reads archives in memory only -- the malicious samples are password-protected zips, opened with
the dataset's published password and never written out or run. Every tenth package of each set,
Every package of every set, across every core. Run inside Docker only, with the benchmark volume
read-only:

    docker run --rm -v cordon-bench-data:/data:ro -v "$PWD:/pkg" -w /pkg python:3.12-slim sh -c \\
      "pip install -q yara-python==4.5.1 && python tests/conformance/generate/yara_evaluate.py"
"""

from __future__ import annotations

import fnmatch
import io
import json
import tarfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import ClassVar

import yara  # type: ignore[import-not-found]

PACK = Path("/pkg/src/cordon_scanner/rules/yara/cordon-builtin.yar")
UPSTREAM = PACK.parent / "upstream"
MEASUREMENT = PACK.parent / "MEASUREMENT.json"
DATA = Path("/data")
MAX_MEMBER = 2 << 20
SOURCE = (
    ".py",
    ".pyx",
    ".pyi",
    ".pth",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".sh",
    ".rb",
    ".go",
    ".gemspec",
    ".ps1",
    ".bat",
    ".cmd",
)


class Evaluation:
    """Members of an archive, matched; counted per rule and per package."""

    @staticmethod
    def members(path: Path, password: bytes | None) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        try:
            if path.suffix in (".zip", ".whl", ".vsix"):
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist()[:5000]:
                        if info.is_dir() or info.file_size > MAX_MEMBER:
                            continue
                        data = archive.read(info, pwd=password)
                        if info.filename.endswith((".tgz", ".tar.gz", ".zip", ".whl")):
                            out += Evaluation.nested(info.filename, data)
                        elif info.filename.lower().endswith(SOURCE):
                            out.append((info.filename, data))
            else:
                with tarfile.open(path, "r:*") as archive:
                    for member in archive.getmembers()[:5000]:
                        if (
                            member.isfile()
                            and member.size <= MAX_MEMBER
                            and member.name.lower().endswith(SOURCE)
                        ):
                            handle = archive.extractfile(member)
                            if handle is not None:
                                out.append((member.name, handle.read()))
        except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError, ValueError, EOFError):
            return out
        return out

    @staticmethod
    def nested(name: str, data: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        try:
            if name.endswith((".zip", ".whl")):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for info in archive.infolist()[:5000]:
                        if (
                            not info.is_dir()
                            and info.file_size <= MAX_MEMBER
                            and info.filename.lower().endswith(SOURCE)
                        ):
                            out.append((info.filename, archive.read(info)))
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for member in archive.getmembers()[:5000]:
                        if (
                            member.isfile()
                            and member.size <= MAX_MEMBER
                            and member.name.lower().endswith(SOURCE)
                        ):
                            handle = archive.extractfile(member)
                            if handle is not None:
                                out.append((member.name, handle.read()))
        except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError, ValueError, EOFError):
            return out
        return out

    SLOW: ClassVar[Counter[str]] = Counter()

    @staticmethod
    def slow_rules(data: bytes) -> list[str]:
        """Which rule a timed-out match spent its time in: each alone, with a short timeout."""
        out = []
        for source in sorted(PACK.parent.glob("upstream/threat-*.yar")):
            try:
                yara.compile(filepath=str(source), includes=False).match(data=data, timeout=2)
            except yara.TimeoutError:
                out.append(source.name)
            except yara.Error:
                continue
        return out

    @staticmethod
    def rules_hit(rules: yara.Rules, members: list[tuple[str, bytes]]) -> set[str]:
        hit: set[str] = set()
        for name, data in members:
            base = name.rpartition("/")[2].lower()
            try:
                matches = rules.match(data=data, timeout=10)
            except yara.TimeoutError:
                Evaluation.SLOW.update(Evaluation.slow_rules(data))
                continue
            for match in matches:
                wanted = match.meta.get("path_include")
                if (
                    isinstance(wanted, str)
                    and wanted.strip()
                    and not any(
                        fnmatch.fnmatchcase(base, g.strip().lower())
                        for g in wanted.split(",")
                        if g.strip()
                    )
                ):
                    continue
                hit.add(match.rule)
        return hit

    RULES: ClassVar[yara.Rules | None] = None

    @staticmethod
    def sources() -> dict[str, str]:
        found = {}
        for source in sorted(UPSTREAM.glob("threat-*.yar")):
            try:
                yara.compile(filepath=str(source), includes=False)
            except yara.Error:
                continue
            found[source.name] = str(source)
        return found

    @staticmethod
    def start() -> None:
        Evaluation.RULES = yara.compile(filepaths=Evaluation.sources(), includes=False)

    @staticmethod
    def one(task: tuple[str, str, str]) -> tuple[str, str, list[str], list[str]]:
        """One package: its set, the rules that fired, and any rule that ran out of time."""
        dataset, kind, path = task
        Evaluation.SLOW.clear()
        assert Evaluation.RULES is not None
        password = b"infected" if dataset == "datadog" else None
        hit = Evaluation.rules_hit(Evaluation.RULES, Evaluation.members(Path(path), password))
        return dataset, kind, sorted(hit), sorted(Evaluation.SLOW.elements())

    @staticmethod
    def tasks() -> list[tuple[str, str, str]]:
        """Every package in every set: benign PyPI (and benign npm where built), DataDog's samples
        and malregistry's packages."""
        out: list[tuple[str, str, str]] = []
        for ecosystem in ("pypi", "npm"):
            root = DATA / "benign" / ecosystem
            if root.is_dir():
                out += [
                    (f"benign-{ecosystem}", "benign", str(p))
                    for p in sorted(root.iterdir())
                    if p.is_file()
                ]
        out += [
            ("datadog", "malicious", str(p))
            for p in sorted((DATA / "datadog/samples").glob("**/*.zip"))
        ]
        out += [
            ("malregistry", "malicious", str(p))
            for p in sorted((DATA / "malregistry").glob("*/*/*"))
            if p.suffix in (".gz", ".whl", ".zip", ".tgz")
        ]
        return out

    @staticmethod
    def run() -> None:
        import multiprocessing

        tasks = Evaluation.tasks()
        noise: Counter[str] = Counter()
        value: Counter[str] = Counter()
        slow: Counter[str] = Counter()
        totals: Counter[str] = Counter()
        caught: Counter[str] = Counter()
        with multiprocessing.get_context("fork").Pool(initializer=Evaluation.start) as pool:
            for dataset, kind, hit, timed_out in pool.imap_unordered(
                Evaluation.one, tasks, chunksize=16
            ):
                totals[dataset] += 1
                slow.update(timed_out)
                if kind == "benign":
                    noise.update(hit)
                else:
                    value.update(hit)
                    caught[dataset] += bool(hit)
        names = sorted(
            set(noise)
            | set(value)
            | {r.identifier for r in yara.compile(filepaths=Evaluation.sources(), includes=False)}
        )
        report = {
            "datasets": dict(totals),
            "benign_packages": sum(n for d, n in totals.items() if d.startswith("benign")),
            "malicious_packages": sum(n for d, n in totals.items() if not d.startswith("benign")),
            "malicious_caught_by_any_rule": dict(caught),
            "rules": {n: {"benign_hits": noise[n], "malicious_hits": value[n]} for n in names},
            "timeouts_by_rule": dict(slow),
        }
        MEASUREMENT.write_text(
            json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            "datasets",
            json.dumps(report["datasets"]),
            "caught",
            json.dumps(report["malicious_caught_by_any_rule"]),
        )
        print("timeouts", json.dumps(report["timeouts_by_rule"]))
        for name, counts in sorted(
            report["rules"].items(),
            key=lambda kv: (-kv[1]["benign_hits"], -kv[1]["malicious_hits"]),
        ):
            print(
                f"{name:55} benign {counts['benign_hits']:5}  malicious {counts['malicious_hits']:5}"
            )


Evaluation.run()
