"""Conformance cases: a project on disk, the scan of it, and what the scan must say.

Each case is a directory under `tests/conformance/cases/<ecosystem>/<case>/` holding project
files and an `expect.yaml`:

```
  covers:        clauses this case proves (`UNI-07`, `npm.aliases`, `file:pnpm-lock.yaml`)
  kinds:         valid | edge | adversarial | regression | real-world | invalid
  advisories:    true -> scan with the case's own `advisories.json` (`--advisories`)
  args:          extra command-line arguments
  target:        a file in the case to scan instead of the directory (an image tarball)
  image:         fields the report's `image` block must hold (an image's digests, layers, base)
  dependencies:  partial dependency records; each must match one record in the report
  only:          true -> the report's dependency names are exactly the listed ones
  absent:        names that must not be in the inventory
  findings:      [{rule, package?, path?}] that must be reported
  no_findings:   rule ids that must not be reported (`"*"`: nothing above info that is not
                 operational)
  operational:   operational rule ids that must be reported
  side_effects:  paths that must NOT exist after the scan (scanner safety, UNI-27)
  never_disclosed: values (credentials in the case's files) no output format may contain
```

The scan runs through the real command line, offline, in a copy of the case directory, so the
case cannot be altered by the scan and nothing it names can be reached.
"""

from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cordon_scanner.core.datayaml import DataYaml

CASES = Path(__file__).parent / "conformance" / "cases"
EXPECT = "expect.yaml"
ADVISORIES = "advisories.json"
CONTROL_FILES = frozenset({EXPECT, ADVISORIES, "authoritative.json", "README.md"})


@dataclass
class ConformanceCase:
    ecosystem: str
    name: str
    path: Path
    expect: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.ecosystem}/{self.name}"

    @property
    def covers(self) -> list[str]:
        return [str(c) for c in self.expect.get("covers") or ()]

    @staticmethod
    def all() -> list[ConformanceCase]:
        out = []
        for ecosystem in sorted(p for p in CASES.iterdir() if p.is_dir()) if CASES.is_dir() else ():
            for case in sorted(p for p in ecosystem.iterdir() if (p / EXPECT).is_file()):
                expect = DataYaml.load((case / EXPECT).read_text(), source=str(case / EXPECT)) or {}
                out.append(ConformanceCase(ecosystem.name, case.name, case, expect))
        return out

    def project_files(self) -> list[Path]:
        return sorted(
            p
            for p in self.path.rglob("*")
            if p.is_file() and p.name not in CONTROL_FILES and "__pycache__" not in p.parts
        )

    def copy_to(self, root: Path) -> Path:
        target = root / "project"
        shutil.copytree(self.path, target, ignore=shutil.ignore_patterns(*CONTROL_FILES))
        if (self.path / ADVISORIES).is_file():
            shutil.copy(self.path / ADVISORIES, root / ADVISORIES)
        return target


class ConformanceRun:
    """Scan a case through the command line and return the parsed report."""

    @staticmethod
    def scan(project: Path, case: ConformanceCase, fmt: str = "json") -> tuple[int, str]:
        from cordon_scanner.cli.main import CommandLine

        output = project.parent / f"report.{fmt}"
        extra = [str(a) for a in case.expect.get("args") or ()]
        target = case.expect.get("target")
        args = [
            "scan",
            str(project / str(target)) if target else str(project),
            "--online" if "--online" in extra else "--offline",
            "--no-cache",
            "--no-color",
            "--quiet",
            "--format",
            fmt,
            "--output",
            str(output),
        ]
        advisories = project.parent / ADVISORIES
        if case.expect.get("advisories") and advisories.is_file():
            args += ["--advisories", str(advisories)]
        args += [a for a in extra if a != "--online"]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = CommandLine.run(args)
        if not output.is_file():
            return code, buffer.getvalue()
        return code, output.read_text(encoding="utf-8")

    @staticmethod
    def report(project: Path, case: ConformanceCase) -> dict[str, Any]:
        code, out = ConformanceRun.scan(project, case)
        if code == 2:
            raise AssertionError(f"{case.id}: the scan failed to run:\n{out[-2000:]}")
        return json.loads(out[out.index("{") :])


class ConformanceCheck:
    """Compare a report with a case's expectations; every difference is returned, not raised."""

    @staticmethod
    def problems(case: ConformanceCase, report: dict[str, Any], project: Path) -> list[str]:
        expect = case.expect
        records = [d["record"] for d in report.get("dependencies", [])]
        findings = report.get("findings", [])
        problems: list[str] = []

        for wanted in expect.get("dependencies") or ():
            matches = [r for r in records if ConformanceCheck._matches(r, wanted)]
            if not matches:
                near = [r for r in records if r.get("name") == wanted.get("name")]
                problems.append(
                    f"no dependency record matches {wanted}; "
                    + (
                        f"closest: {ConformanceCheck._diff(near[0], wanted)}"
                        if near
                        else "no record has that name"
                    )
                )
        if expect.get("only"):
            wanted_names = sorted({str(w["name"]) for w in expect.get("dependencies") or ()})
            got = sorted({r["name"] for r in records})
            if got != wanted_names:
                problems.append(f"dependency names {got} != expected {wanted_names}")
        for name in expect.get("absent") or ():
            if any(r["name"] == name for r in records):
                problems.append(f"{name!r} should not be in the inventory")
        wanted_image = expect.get("image")
        if wanted_image is not None:
            got_image = report.get("image")
            if not isinstance(got_image, dict):
                problems.append("the report has no image block")
            else:
                for key, value in wanted_image.items():
                    if not ConformanceCheck._equal(got_image.get(key), value):
                        problems.append(
                            f"image.{key} is {got_image.get(key)!r}, expected {value!r}"
                        )

        for wanted in expect.get("findings") or ():
            if not any(ConformanceCheck._finding_matches(f, wanted, records) for f in findings):
                rules = sorted({f["rule_id"] for f in findings})
                problems.append(f"no finding matches {wanted}; reported: {rules}")
        for rule in expect.get("operational") or ():
            if not any(f["rule_id"] == rule for f in findings):
                problems.append(f"operational finding {rule} was not reported")
        for rule in expect.get("no_findings") or ():
            if rule == "*":
                loud = [
                    f["rule_id"]
                    for f in findings
                    if f["category"] != "operational"
                    and f["severity"] != "info"
                    and not f.get("suppressed")
                ]
                if loud:
                    problems.append(f"expected no findings, got {sorted(set(loud))}")
            elif any(f["rule_id"] == rule and not f.get("suppressed") for f in findings):
                problems.append(f"{rule} must not be reported")

        hooks = (report.get("repository") or {}).get("hooks") or []
        for wanted_hook in expect.get("hooks") or ():
            if not any(ConformanceCheck._matches(h, wanted_hook) for h in hooks):
                problems.append(f"hook {wanted_hook} not reported; reported {hooks}")

        reported_sources = {s["source"] for s in report.get("sources", [])}
        for wanted_source in expect.get("sources") or ():
            if str(wanted_source) not in reported_sources:
                problems.append(
                    f"source {wanted_source!r} not reported; reported {sorted(reported_sources)}"
                )

        authoritative = case.path / "authoritative.json"
        if authoritative.is_file():
            # The package manager's own inventory of what it resolved: the scan must agree
            # exactly, for every package fetched (not the project's own workspace members).
            from cordon_scanner.ecosystems.registry import EcosystemRegistry

            def identity(name: str, version: str, ecosystem: str) -> str:
                implementation = EcosystemRegistry.get(ecosystem)
                normal = implementation.normalize_name(name) if implementation else name
                return f"{normal}@{version}"

            document = json.loads(authoritative.read_text())
            # Names the tool cannot report, each with the reason (`go list` has no module for the
            # standard library): excluded from both sides, never silently. Likewise whole kinds
            # the tool's listing omits, each with the reason (`exclude`).
            ignored = set(document.get("ignore") or {})
            excluded = document.get("exclude") or {}
            # A package manager's listing names packages, not the tool that wrote the lockfile
            # (`COCOAPODS:`, `BUNDLED WITH`) or build plugins: tool records are compared only when
            # the authoritative file says its tool lists them.
            excluded_types = set(excluded.get("dependency_type") or {}) | (
                set() if document.get("lists_tools") else {"tool"}
            )
            excluded_conditions = tuple(excluded.get("condition_prefix") or {})
            locked = any(r["lockfile_location"] is not None for r in records)
            truth = {
                identity(*entry.rsplit("@", 1), case.ecosystem)
                for entry in document["packages"]
                if entry.rsplit("@", 1)[0] not in ignored
            }
            # What the lockfile resolved: a manifest's exact pin the lockfile never included is
            # in the inventory (declared, absent from the lock) but not in the tool's resolution.
            # Packages of another ecosystem the case also holds (a conda environment's pip
            # packages) are compared with the tool's own list of them, ecosystem by ecosystem.
            others: dict[str, list[str]] = document.get("other_ecosystems") or {}
            for other, listed in others.items():
                other_truth = {identity(*entry.rsplit("@", 1), other) for entry in listed}
                other_seen = {
                    identity(r["name"], r["resolved_version"], other)
                    for r in records
                    if r["ecosystem"] == other
                    and r["resolved_version"]
                    and r["lockfile_location"] is not None
                }
                if other_truth != other_seen:
                    problems.append(
                        f"{other} packages differ from {document['tool']}: missing {sorted(other_truth - other_seen)}, extra {sorted(other_seen - other_truth)}"
                    )
            seen = {
                identity(r["name"], r["resolved_version"], r["ecosystem"])
                for r in records
                if r["resolved_version"]
                and r["ecosystem"] not in others
                and r["name"] not in ignored
                and r["source_type"] not in ("path",)
                and r["dependency_type"] != "platform"
                and r["dependency_type"] not in excluded_types
                and not any(c.startswith(excluded_conditions) for c in r["platform_constraints"])
                and (
                    not locked
                    or r["lockfile_location"] is not None
                    or r["manifest_location"] is None
                )
            }
            if truth != seen:
                problems.append(
                    f"differs from {json.loads(authoritative.read_text())['tool']}: "
                    f"missing {sorted(truth - seen)}, extra {sorted(seen - truth)}"
                )

        secrets = [str(s) for s in expect.get("never_disclosed") or ()]
        if secrets:
            # Every output format, not only the JSON report the rest of the checks read.
            outputs = {"json": json.dumps(report)}
            for fmt in ("sarif", "text"):
                outputs[fmt] = ConformanceRun.scan(project, case, fmt)[1]
            for fmt, text in outputs.items():
                leaked = [s for s in secrets if s in text]
                if leaked:
                    problems.append(
                        f"the {fmt} output discloses {len(leaked)} value(s) it must never contain"
                    )

        for relative in expect.get("side_effects") or ():
            if (project / relative).exists() or (
                Path(relative).is_absolute() and Path(relative).exists()
            ):
                problems.append(f"the scan created {relative}: project code was executed")
        return problems

    @staticmethod
    def _matches(record: dict[str, Any], wanted: dict[str, Any]) -> bool:
        return all(ConformanceCheck._equal(record.get(k), v) for k, v in wanted.items())

    @staticmethod
    def _equal(got: Any, want: Any) -> bool:
        if isinstance(want, dict) and isinstance(got, dict):
            return all(ConformanceCheck._equal(got.get(k), v) for k, v in want.items())
        if isinstance(want, list) and isinstance(got, list):
            return [str(x) for x in got] == [str(x) for x in want]
        if want is None:
            return got is None
        return str(got) == str(want)

    @staticmethod
    def _diff(record: dict[str, Any], wanted: dict[str, Any]) -> dict[str, Any]:
        return {
            k: record.get(k)
            for k in wanted
            if not ConformanceCheck._equal(record.get(k), wanted[k])
        }

    @staticmethod
    def _finding_matches(
        finding: dict[str, Any], wanted: dict[str, Any], records: list[dict[str, Any]]
    ) -> bool:
        if finding["rule_id"] != wanted["rule"]:
            return False
        if "package" in wanted:
            package = str(finding.get("location", {}).get("package") or "")
            name = str(wanted["package"])
            if (
                f"/{name}@" not in package
                and not package.endswith(f"/{name}")
                and name not in finding.get("message", "")
            ):
                return False
        if "path" in wanted and not str(finding.get("location", {}).get("path", "")).endswith(
            str(wanted["path"])
        ):
            return False
        if "message" in wanted and str(wanted["message"]) not in finding.get("message", ""):
            return False
        if "remediation" in wanted and str(wanted["remediation"]) not in (
            finding.get("remediation") or ""
        ):
            return False
        return not ("severity" in wanted and finding.get("severity") != wanted["severity"])


__all__ = ["CASES", "ConformanceCase", "ConformanceCheck", "ConformanceRun"]
