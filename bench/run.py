#!/usr/bin/env python3
"""Run the benchmark suites inside the bench image and write what was measured, losses included.

  malware   DataDog's samples: does each tool's default verdict block the package? Run with the
            container's network off. Samples are unzipped inside the container only.
  benign    Top npm and PyPI packages: does each tool's default verdict block a package people
            install every day? Network off.
  cve       Real lockfiles: Cordon's, OSV-Scanner's and Trivy's vulnerability findings, compared
            as (ecosystem, package, version, CVE) sets. OSV-Scanner and Trivy need the network for
            their databases, so this suite runs with it on.

Results go to /results/<suite>.json and /results/summary.md. A tool that is not installed, or that
fails on an input, is recorded as such for that input -- never silently counted as clean.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

TIMEOUT = 600
DATADOG_PASSWORD = b"infected"


@dataclass
class Verdict:
    tool: str
    sample: str
    blocked: bool | None
    """None when the tool could not give an answer for this input."""
    detail: str = ""
    seconds: float = 0.0


@dataclass
class SuiteResult:
    suite: str
    verdicts: list[Verdict] = field(default_factory=list)

    def rates(self) -> dict[str, dict[str, float | int]]:
        by_tool: dict[str, Counter[str]] = {}
        for verdict in self.verdicts:
            counts = by_tool.setdefault(verdict.tool, Counter())
            counts["total"] += 1
            counts[
                "blocked" if verdict.blocked else ("error" if verdict.blocked is None else "passed")
            ] += 1
        rates: dict[str, dict[str, float | int]] = {
            tool: {
                **dict(counts),
                "rate": round(counts["blocked"] / max(counts["total"] - counts["error"], 1), 4),
            }
            for tool, counts in sorted(by_tool.items())
        }
        identity_only = sum(
            1 for v in self.verdicts if v.tool == "cordon" and v.detail == "identity-only"
        )
        if identity_only and "cordon" in rates:
            counts = by_tool["cordon"]
            content = counts["blocked"] - identity_only
            rates["cordon, content only"] = {
                "total": counts["total"],
                "blocked": content,
                "error": counts["error"],
                "rate": round(content / max(counts["total"] - counts["error"], 1), 4),
            }
        # When another tool ran on a subset, Cordon's rate on exactly that subset as well: the
        # comparison is only fair on the same samples.
        cordon = {v.sample: v.blocked for v in self.verdicts if v.tool == "cordon"}
        for tool in [t for t in by_tool if t != "cordon"]:
            shared = [
                cordon[v.sample]
                for v in self.verdicts
                if v.tool == tool and v.blocked is not None and cordon.get(v.sample) is not None
            ]
            if shared and len(shared) < len(cordon):
                rates[f"cordon on {tool}'s sample"] = {
                    "total": len(shared),
                    "blocked": sum(1 for b in shared if b),
                    "rate": round(sum(1 for b in shared if b) / len(shared), 4),
                }
        return rates


class Harness:
    """The benchmark suites: malware, benign, CVE agreement and agent cases."""

    @staticmethod
    def run(command: list[str], *, cwd: Path | None = None) -> tuple[int, str, float]:
        """Exit code, stdout (where every tool here writes its JSON), seconds."""
        import time

        started = time.monotonic()
        try:
            done = subprocess.run(
                command, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            return -1, "timeout", time.monotonic() - started
        except FileNotFoundError:
            return -2, "not installed", time.monotonic() - started
        return done.returncode, done.stdout or done.stderr[-2000:], time.monotonic() - started

    @staticmethod
    def cordon(path: Path, sample: str) -> Verdict:
        code, out, seconds = Harness.run(
            [
                "cordon-scanner",
                "scan",
                str(path),
                "--offline",
                "--no-color",
                "--quiet",
                "--format",
                "json",
            ]
        )
        if code in (-1, -2) or code == 2:
            return Verdict("cordon", sample, None, out[:200], seconds)
        detail = f"exit {code}"
        if code == 1:
            # Whether anything other than the known-release lookup blocked: the content-only rate
            # is reported beside the full one, so neither can be mistaken for the other.
            try:
                report = json.loads(out[out.index("{") :])
                blocking = {
                    f["rule_id"]
                    for f in report.get("findings", [])
                    if f.get("severity") in ("high", "critical") or f.get("category") == "malicious"
                }
                if blocking and blocking <= {KNOWN_RELEASE_RULE}:
                    detail = "identity-only"
            except (ValueError, KeyError, TypeError):
                pass
        return Verdict("cordon", sample, code == 1, detail, seconds)

    @staticmethod
    def guarddog(path: Path, sample: str, ecosystem: str) -> Verdict:
        code, out, seconds = Harness.run(
            ["guarddog", ecosystem, "scan", str(path), "--output-format", "json"]
        )
        if code in (-1, -2):
            return Verdict("guarddog", sample, None, out[:200], seconds)
        try:
            document = json.loads(out[out.index("{") :])
        except (ValueError, TypeError):
            return Verdict("guarddog", sample, None, "unparseable output", seconds)
        # GuardDog 3 scores risk: capability matches alone are `no_risks_detected`; anything else is
        # its verdict that the package is risky, which is the comparable claim to a blocked gate.
        risk = document.get("risk_score") or {}
        label = str(risk.get("label", ""))
        if label:
            return Verdict(
                "guarddog",
                sample,
                label != "no_risks_detected",
                f"{label}, score {risk.get('score')}",
                seconds,
            )
        issues = int(document.get("issues", 0))
        return Verdict("guarddog", sample, issues > 0, f"{issues} issue(s)", seconds)

    @staticmethod
    def _unzip_datadog(archive: Path, into: Path) -> Path | None:
        with zipfile.ZipFile(archive) as bundle:
            bundle.setpassword(DATADOG_PASSWORD)
            names = [n for n in bundle.namelist() if not n.endswith("/")]
            if not names:
                return None
            bundle.extractall(into)
        files = [p for p in into.rglob("*") if p.is_file()]
        archives = [p for p in files if p.suffix in (".tgz", ".gz", ".whl", ".zip")]
        # The sample is an archive only when that is all it holds (beside DataDog's own
        # `package_info-*.json`). An unpacked package that ships a `.gz` test fixture is the package:
        # scanning the fixture instead handed both tools a few bytes of test data for litellm.
        others = [p for p in files if p not in archives and not p.name.startswith("package_info")]
        return archives[0] if len(archives) == 1 and not others else into

    @staticmethod
    def _release_key(name: str, version: str) -> tuple[str, str]:
        return re.sub(r"[-_.]+", "-", name).lower(), version.lower().removeprefix("v")

    @staticmethod
    def _datadog_key(path: Path) -> tuple[str, str] | None:
        """`pypi/malicious_intent/<name>/<version>/<date>-<name>-v<version>.zip`."""
        parts = path.parts
        if len(parts) >= 5 and parts[-2] != parts[-3]:
            return Harness._release_key(parts[-3], parts[-2])
        return None

    @staticmethod
    def _malregistry_key(path: Path) -> tuple[str, str] | None:
        """`<name>/<version>/<name>-<version>.tar.gz`, or the archive name alone."""
        stem = path.name
        for suffix in (".tar.gz", ".zip", ".whl", ".egg", ".tgz"):
            stem = stem.removesuffix(suffix)
        name, _, version = stem.rpartition("-")
        return Harness._release_key(name, version.split("-", 1)[0]) if name and version else None

    @staticmethod
    def malware_samples(data: Path) -> list[tuple[str, Path, str]]:
        """`(sample id, archive, ecosystem)` across both datasets, each release counted once."""
        samples: list[tuple[str, Path, str]] = []
        seen: set[tuple[str, str]] = set()
        datadog = data / "datadog" / "samples"
        for archive in sorted(datadog.rglob("*.zip")):
            relative = archive.relative_to(datadog)
            key = Harness._datadog_key(relative)
            if key is not None:
                seen.add(key)
            ecosystem = "npm" if relative.parts[0] == "npm" else "pypi"
            samples.append((f"datadog/{relative}", archive, ecosystem))
        registry = data / "malregistry"
        if registry.is_dir():
            for archive in sorted(
                p
                for p in registry.rglob("*")
                if p.is_file() and p.name.endswith((".tar.gz", ".zip", ".whl", ".egg", ".tgz"))
            ):
                key = Harness._malregistry_key(archive)
                if key is None or key in seen:
                    continue
                seen.add(key)
                samples.append((f"malregistry/{archive.relative_to(registry)}", archive, "pypi"))
        return samples

    @staticmethod
    def malware(
        data: Path, limit: int, workers: int, guarddog_sample: int | None = None
    ) -> SuiteResult:
        result = SuiteResult("malware")
        samples = Harness.malware_samples(data)[:limit]
        # A reproducible sample, not a secret: the seed is published so anyone draws the same one.
        draw = random.Random(GUARDDOG_SEED)  # noqa: S311
        compared = (
            {s[0] for s in draw.sample(samples, min(guarddog_sample, len(samples)))}
            if guarddog_sample is not None
            else {s[0] for s in samples}
        )

        def one(sample: tuple[str, Path, str]) -> list[Verdict]:
            name, archive, ecosystem = sample
            tools = ("cordon", "guarddog") if name in compared else ("cordon",)
            with tempfile.TemporaryDirectory(prefix="bench-") as work:
                if name.startswith("datadog/"):
                    try:
                        target = Harness._unzip_datadog(archive, Path(work))
                    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                        return [Verdict(tool, name, None, f"unzip: {exc}") for tool in tools]
                    if target is None:
                        return []
                else:
                    target = archive
                verdicts = [Harness.cordon(target, name)]
                if "guarddog" in tools:
                    verdicts.append(Harness.guarddog(target, name, ecosystem))
                return verdicts

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for verdicts in pool.map(one, samples):
                result.verdicts.extend(verdicts)
        return result

    @staticmethod
    def benign(data: Path, limit: int, workers: int) -> SuiteResult:
        result = SuiteResult("benign")
        manifest = json.loads((data / "benign" / "manifest.json").read_text())[:limit]

        def one(entry: dict[str, str]) -> list[Verdict]:
            path = data / entry["file"]
            name = f"{entry['ecosystem']}/{entry['name']}"
            return [Harness.cordon(path, name), Harness.guarddog(path, name, entry["ecosystem"])]

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for verdicts in pool.map(one, manifest):
                result.verdicts.extend(verdicts)
        return result

    @staticmethod
    def agents(repo: Path) -> dict[str, Any]:
        """The agent and MCP attack-shape suite. Cordon is scored on the rules each case expects; the
        other tools on whether they flag the case at all -- a generous reading for them."""
        suite = json.loads((repo / "bench" / "agent-suite.json").read_text())
        rows = []
        for case in suite["cases"]:
            path = repo / case["path"]
            row: dict[str, Any] = {"case": case["id"], "kind": case["kind"]}
            _, out, _ = Harness.run(
                [
                    "cordon-scanner",
                    "scan",
                    str(path),
                    "--offline",
                    "--quiet",
                    "--format",
                    "json",
                    "--severity",
                    "info",
                ]
            )
            found = (
                {f["rule_id"] for f in json.loads(out[out.index("{") :]).get("findings", [])}
                if "{" in out
                else set()
            )
            expected = set(case["expected"])
            actionable = {r for r in found if not r.startswith(("OPERATIONAL.", "POLICY.COVERAGE"))}
            row["cordon"] = (expected <= found) if case["kind"] == "malicious" else not actionable
            _, out, _ = Harness.run(
                [
                    "trivy",
                    "fs",
                    "--quiet",
                    "--scanners",
                    "secret,misconfig",
                    "--format",
                    "json",
                    str(path),
                ]
            )
            try:
                results = json.loads(out[out.index("{") :]).get("Results") or []
                flagged = any((r.get("Secrets") or r.get("Misconfigurations")) for r in results)
            except ValueError:
                flagged = None
            row["trivy"] = (
                None
                if flagged is None
                else (flagged if case["kind"] == "malicious" else not flagged)
            )
            verdict = Harness.guarddog(path, case["id"], "pypi")
            row["guarddog"] = (
                None
                if verdict.blocked is None
                else (verdict.blocked if case["kind"] == "malicious" else not verdict.blocked)
            )
            rows.append(row)
        score = {
            tool: f"{sum(1 for r in rows if r[tool])}/{len(rows)}"
            for tool in ("cordon", "trivy", "guarddog")
        }
        return {"suite": "agents", "cases": rows, "score": score}

    @staticmethod
    def _cordon_vulns(directory: Path) -> Groups:
        code, out, _ = Harness.run(
            [
                "cordon-scanner",
                "scan",
                str(directory),
                "--offline",
                "--quiet",
                "--format",
                "json",
                "--severity",
                "info",
            ]
        )
        if code not in (0, 1, 4):
            raise RuntimeError(out[:200])
        groups: Groups = []
        for finding in json.loads(out[out.index("{") :]).get("findings", []):
            if finding["rule_id"].startswith("VULNERABLE.DEPENDENCY."):
                version = finding["location"].get("package", "").rsplit("@", 1)[-1]
                ids = frozenset(
                    ADVISORY_ID.findall(
                        finding["message"] + " " + " ".join(finding.get("references", []))
                    )
                )
                if ids:
                    groups.append((version, ids))
        return groups

    @staticmethod
    def _osv_vulns(directory: Path) -> Groups:
        code, out, _ = Harness.run(
            ["osv-scanner", "scan", "source", "--format", "json", "-r", str(directory)]
        )
        if code not in (0, 1):
            raise RuntimeError(out[:200])
        groups: Groups = []
        for source in json.loads(out[out.index("{") :]).get("results", []):
            for package in source.get("packages", []):
                version = package.get("package", {}).get("version", "")
                for vulnerability in package.get("vulnerabilities", []):
                    groups.append(
                        (
                            version,
                            frozenset(
                                [vulnerability.get("id", ""), *vulnerability.get("aliases", [])]
                            )
                            - {""},
                        )
                    )
        return groups

    @staticmethod
    def _trivy_vulns(directory: Path) -> Groups:
        code, out, _ = Harness.run(
            ["trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json", str(directory)]
        )
        if code != 0:
            raise RuntimeError(out[:200])
        groups: Groups = []
        for target in json.loads(out[out.index("{") :]).get("Results", []) or []:
            for vulnerability in target.get("Vulnerabilities", []) or []:
                groups.append(
                    (
                        vulnerability.get("InstalledVersion", ""),
                        frozenset([vulnerability.get("VulnerabilityID", "")]) - {""},
                    )
                )
        return groups

    @staticmethod
    def _merge(*sources: Groups) -> Groups:
        """One group per vulnerability per version: groups sharing any identifier are the same one."""
        merged: Groups = []
        for raw_version, ids in (g for source in sources for g in source):
            # Trivy writes Go module versions `v0.37.0`, OSV-Scanner and Cordon `0.37.0`; the same
            # vulnerability at the same version must not count as two.
            version = raw_version[1:] if re.match(r"v\d", raw_version) else raw_version
            for index, (other_version, other_ids) in enumerate(merged):
                if other_version == version and other_ids & ids:
                    merged[index] = (version, other_ids | ids)
                    break
            else:
                merged.append((version, ids))
        return merged

    @staticmethod
    def cve(data: Path, limit: int, *, full_database: bool = False) -> dict[str, Any]:
        if full_database:
            # The unfiltered OSV set an operator gets from `advisories sync`, instead of the wheel's
            # high/critical subset; the other two tools report every severity.
            code, out, _ = Harness.run(["cordon-scanner", "advisories", "sync"])
            if code != 0:
                raise SystemExit(f"advisories sync failed: {out[:300]}")
        rows = []
        for directory in sorted(p for p in (data / "lockfiles").iterdir() if p.is_dir())[:limit]:
            row: dict[str, Any] = {"lockfile": directory.name}
            found: dict[str, Groups] = {}
            for tool, collect in (
                ("cordon", Harness._cordon_vulns),
                ("osv-scanner", Harness._osv_vulns),
                ("trivy", Harness._trivy_vulns),
            ):
                try:
                    found[tool] = Harness._merge(collect(directory))
                    row[tool] = len(found[tool])
                except (RuntimeError, ValueError) as exc:
                    row[tool] = f"error: {str(exc)[:120]}"
            reference = Harness._merge(found.get("osv-scanner", []), found.get("trivy", []))
            if "cordon" in found and reference:
                ours = found["cordon"]

                def matched(group: tuple[str, frozenset[str]], pool: Groups) -> bool:
                    return any(version == group[0] and ids & group[1] for version, ids in pool)

                agreed = [g for g in reference if matched(g, ours)]
                row["agreement"] = round(len(agreed) / len(reference), 4)
                row["cordon_missed"] = sorted(
                    min(ids) for v, ids in reference if not matched((v, ids), ours)
                )[:50]
                row["cordon_only"] = sorted(
                    min(ids) for v, ids in ours if not matched((v, ids), reference)
                )[:50]
            rows.append(row)
        scored = [r["agreement"] for r in rows if isinstance(r.get("agreement"), float)]
        return {
            "suite": "cve",
            "database": "full (advisories sync)"
            if full_database
            else "bundled (high/critical subset)",
            "lockfiles": rows,
            "mean_agreement": round(sum(scored) / len(scored), 4) if scored else None,
        }

    @staticmethod
    def summary(results: dict[str, Any]) -> str:
        lines = [
            "# Cordon benchmark",
            "",
            "Measured inside Docker by `bench/run.py`. Losses are listed, not hidden.",
            "",
        ]
        for suite in ("malware", "benign"):
            if suite not in results:
                continue
            title = (
                "Malware blocked (higher is better)"
                if suite == "malware"
                else "Benign packages blocked (lower is better)"
            )
            lines += [
                f"## {title}",
                "",
                "| tool | inputs | blocked | passed | no answer | rate |",
                "|---|---|---|---|---|---|",
            ]
            for tool, row in results[suite]["rates"].items():
                lines.append(
                    f"| {tool} | {row.get('total', 0)} | {row.get('blocked', 0)} | {row.get('passed', 0)} | {row.get('error', 0)} | {row['rate']:.1%} |"
                )
            lines.append("")
        if "agents" in results:
            suite = results["agents"]
            lines += [
                "## Agent and MCP attack-shape suite",
                "",
                f"Score (cases handled correctly): {suite['score']}",
                "",
            ]
            lines += ["| case | kind | cordon | trivy | guarddog |", "|---|---|---|---|---|"]
            mark = {True: "yes", False: "**no**", None: "-"}
            for row in suite["cases"]:
                lines.append(
                    f"| {row['case']} | {row['kind']} | {mark[row['cordon']]} | {mark[row['trivy']]} | {mark[row['guarddog']]} |"
                )
            lines += [
                "",
                "Snyk agent-scan is not run: it inspects an MCP server by starting it, which runs the "
                "package under test, and it sends tool descriptions to Snyk's API.",
                "",
            ]
        for key in ("cve", "cve-full"):
            if key not in results:
                continue
            suite = results[key]
            lines += [
                f"## CVE agreement with OSV-Scanner and Trivy -- Cordon database: {suite.get('database', 'bundled')}",
                "",
            ]
            lines += [f"Mean agreement: {suite['mean_agreement']}", ""]
            lines += [
                "| lockfile | cordon | osv-scanner | trivy | agreement |",
                "|---|---|---|---|---|",
            ]
            for row in suite["lockfiles"]:
                lines.append(
                    f"| {row['lockfile']} | {row.get('cordon')} | {row.get('osv-scanner')} | {row.get('trivy')} | {row.get('agreement', '-')} |"
                )
            lines.append("")
        return "\n".join(lines) + "\n"

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument("suites", nargs="+", choices=["malware", "benign", "cve", "agents"])
        parser.add_argument(
            "--repo",
            type=Path,
            default=Path("/repo"),
            help="agents: the checkout holding the suite",
        )
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--results", type=Path, default=Path("/results"))
        parser.add_argument("--limit", type=int, default=100_000)
        parser.add_argument("--workers", type=int, default=4)
        parser.add_argument(
            "--guarddog-sample",
            type=int,
            default=None,
            help="malware: run GuardDog on a fixed-seed random N only (Cordon runs on every sample)",
        )
        parser.add_argument(
            "--full-database", action="store_true", help="cve: sync the full advisory set first"
        )
        args = parser.parse_args()
        args.results.mkdir(parents=True, exist_ok=True)
        collected: dict[str, Any] = {}
        previous = args.results / "results.json"
        if previous.exists():
            collected = json.loads(previous.read_text())
        for suite in args.suites:
            if suite == "agents":
                collected["agents"] = Harness.agents(args.repo)
            elif suite == "cve":
                collected["cve-full" if args.full_database else "cve"] = Harness.cve(
                    args.data, args.limit, full_database=args.full_database
                )
            else:
                outcome = (
                    Harness.malware(args.data, args.limit, args.workers, args.guarddog_sample)
                    if suite == "malware"
                    else Harness.benign(args.data, args.limit, args.workers)
                )
                collected[suite] = {
                    "rates": outcome.rates(),
                    "verdicts": [asdict(v) for v in outcome.verdicts],
                }
            print(f"{suite}: done")
        previous.write_text(json.dumps(collected, indent=1))
        (args.results / "summary.md").write_text(Harness.summary(collected))
        print(Harness.summary(collected))
        return 0


KNOWN_RELEASE_RULE = "MALWARE.PACKAGE.KNOWN.001"
"""The scanned package's own name and version is a recorded malicious release."""

GUARDDOG_SEED = 20261001
"""Fixed so the GuardDog subset is the same sample on every run."""


ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b"
)

Groups = list[tuple[str, frozenset[str]]]
"""(installed version, every identifier the vulnerability is known by)."""


if __name__ == "__main__":
    if shutil.which("cordon-scanner") is None:
        raise SystemExit("cordon-scanner is not installed in this image")
    raise SystemExit(Harness.main())
