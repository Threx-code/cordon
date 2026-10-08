"""Every conformance case, and the checks that hold for every case of every ecosystem.

The per-case test proves the clauses a case lists in `covers:`. The classes after it run the same
case again under a different question -- truncated input, the three output formats, offline
honesty -- and so prove a universal clause for each ecosystem that has a case. See
`src/cordon_scanner/ecosystems/contract.py` and `test_contract.py`.
"""

from __future__ import annotations

import json
import re

import pytest

from conformancekit import ConformanceCase, ConformanceCheck, ConformanceRun
from cordon_scanner.ecosystems.contract import RECORD_FIELDS
from cordon_scanner.ecosystems.registry import EcosystemRegistry

CASES = ConformanceCase.all()
VALID = [
    c
    for c in CASES
    if "valid" in (c.expect.get("kinds") or ()) or "real-world" in (c.expect.get("kinds") or ())
]
PARSE_DIAGNOSTICS = frozenset(
    {"OPERATIONAL.MANIFEST.UNPARSED", "OPERATIONAL.LOCKFILE.UNPARSED", "OPERATIONAL.PARSER.FAILED"}
)
#: What a scan of a damaged target file says instead: the target is the archive or the document.
ARCHIVE_DIAGNOSTICS = frozenset(
    {
        "OPERATIONAL.ARCHIVE.REJECTED",
        "OPERATIONAL.IMAGE.UNREADABLE",
        "OPERATIONAL.IMAGE.PARTIAL",
        "OPERATIONAL.SBOM.INVALID",
    }
)
STATUS_VALUES = {
    "advisory_status": {
        "vulnerable",
        "no_matching_advisory",
        "unavailable_feed",
        "skipped",
        "not_applicable",
        "error",
    },
    "malware_status": {
        "malicious",
        "suspicious",
        "no_known_malicious_release",
        "unavailable_feed",
        "skipped",
        "not_applicable",
        "error",
    },
    "integrity_status": {"verified", "mismatched", "recorded", "unavailable", "not_applicable"},
    "provenance_status": {"verified", "invalid", "absent", "unsupported", "not_checked"},
    "licence_status": {
        "identified",
        "conflicting",
        "unknown",
        "policy_violation",
        "not_applicable",
    },
    "resolution_status": {"resolved", "partially_resolved", "unresolved", "unsupported"},
}


class TestEachCase:
    @pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
    def test_the_scan_says_what_the_case_expects(self, case, tmp_path) -> None:
        project = case.copy_to(tmp_path)
        report = ConformanceRun.report(project, case)
        problems = ConformanceCheck.problems(case, report, project)
        assert not problems, f"{case.id}:\n  " + "\n  ".join(problems)


class TestTruncatedAndCorruptInput:
    """UNI-03: a file cut short or corrupted gives a diagnostic or what it still holds -- never an
    empty dependency list that reads as "this project has no dependencies"."""

    @pytest.mark.parametrize("case", VALID, ids=lambda c: c.id)
    def test_every_dependency_file_damaged(self, case, tmp_path) -> None:
        # Every file that contributed dependencies to the undamaged scan. A companion (`go.sum`)
        # or a workspace file that declares nothing contributes none, and has none to lose.
        baseline = ConformanceRun.report(case.copy_to(tmp_path / "baseline"), case)
        contributing = {d.get("declared_in") for d in baseline["dependencies"]} | {
            (d["record"]["manifest_location"] or {}).get("path") for d in baseline["dependencies"]
        }
        # Files that contributed packages, not only a platform line: cut in half, a go.mod holding
        # nothing but `module` and `go` is a shorter valid go.mod, and nothing can tell it apart
        # from a real one. The corruption check below still applies to it.
        # Go's `stdlib` is derived from the `go`/`toolchain` directive the same way: a go.mod cut
        # before that line is still a valid go.mod.
        derived = [
            d
            for d in baseline["dependencies"]
            if d["record"]["dependency_type"] != "platform"
            and not (d["ecosystem"] == "gomod" and d["name"] == "stdlib")
        ]
        packaged = {d.get("declared_in") for d in derived} | {
            (d["record"]["manifest_location"] or {}).get("path") for d in derived
        }
        files = [
            p
            for p in case.project_files()
            if p.relative_to(case.path).as_posix() in contributing
            and (
                EcosystemRegistry.lockfile_ecosystem(p.relative_to(case.path).as_posix())
                or EcosystemRegistry.manifest_ecosystem(p.relative_to(case.path).as_posix())
            )
        ]
        if case.expect.get("target"):
            # An image scanned as a tarball: the archive is the one file there is to damage.
            files = [case.path / str(case.expect["target"])]
        assert files, f"{case.id}: no dependency file to damage"
        for index, original in enumerate(files):
            relative = original.relative_to(case.path)
            data = original.read_bytes()
            variants = [("corrupt", b"\x00\xff{[<" + data[len(data) // 3 :])]
            if relative.as_posix() in packaged:
                variants.insert(0, ("truncated", data[: max(1, len(data) // 2)]))
            for label, damaged in variants:
                root = tmp_path / f"{index}-{label}"
                project = case.copy_to(root)
                (project / relative).write_bytes(damaged)
                code, out = ConformanceRun.scan(project, case)
                assert code != 2, f"{case.id}: {relative} {label} crashed the scan"
                report = json.loads(out[out.index("{") :])
                from_file = [
                    d
                    for d in report["dependencies"]
                    if relative.as_posix()
                    in (
                        d.get("declared_in"),
                        d["record"].get("manifest_location")
                        and d["record"]["manifest_location"]["path"],
                    )
                ]
                diagnosed = [
                    f
                    for f in report["findings"]
                    if (
                        f["rule_id"] in PARSE_DIAGNOSTICS and f["location"]["path"] == relative.as_posix()
                    )
                    or (case.expect.get("target") and f["rule_id"] in ARCHIVE_DIAGNOSTICS)
                ]
                assert from_file or diagnosed, (
                    f"{case.id}: {relative} {label} produced no dependencies and no diagnostic"
                )


class TestRecordsAreComplete:
    """Section 3: every dependency carries every field, with a status from the stated vocabulary
    and never a bare boolean; UNI-06: every one says whether it is resolved, and why."""

    @pytest.mark.parametrize("case", VALID, ids=lambda c: c.id)
    def test_fields_and_statuses(self, case, tmp_path) -> None:
        report = ConformanceRun.report(case.copy_to(tmp_path), case)
        assert report["dependencies"], f"{case.id}: no dependencies"
        for dependency in report["dependencies"]:
            record = dependency["record"]
            missing = [f for f in RECORD_FIELDS if f not in record]
            assert not missing, f"{case.id}: {record['name']} lacks {missing}"
            for key, allowed in STATUS_VALUES.items():
                assert record[key] in allowed, f"{case.id}: {record['name']} {key}={record[key]!r}"
            assert record["resolution_reason"], (
                f"{case.id}: {record['name']} has no resolution reason"
            )
            if record["source_url"]:
                assert not re.search(r"://[^/@\s]+@", record["source_url"]), (
                    "credentials in a source URL"
                )


class TestOfflineIsExplicit:
    """UNI-21 and UNI-29: offline, a check that needs what is not there says so in the report."""

    @pytest.mark.parametrize("case", VALID, ids=lambda c: c.id)
    def test_missing_feeds_and_services_are_named(self, case, tmp_path) -> None:
        report = ConformanceRun.report(case.copy_to(tmp_path), case)
        rules = {f["rule_id"] for f in report["findings"]}
        records = [d["record"] for d in report["dependencies"]]
        if any(r["advisory_status"] == "unavailable_feed" for r in records):
            assert "OPERATIONAL.ADVISORY.NO_FEED.001" in rules, (
                f"{case.id}: an unavailable feed went unsaid"
            )
            assert report["complete"] is False, (
                f"{case.id}: a scan missing a feed called itself complete"
            )
        assert not any(r["provenance_status"] == "verified" for r in records), "verified offline?"
        assert not any(r["integrity_status"] == "verified" for r in records), "verified offline?"


class TestOutputsAgree:
    """UNI-25: JSON and SARIF report the same findings for the same input."""

    @pytest.mark.parametrize("case", VALID, ids=lambda c: c.id)
    def test_json_and_sarif(self, case, tmp_path) -> None:
        project = case.copy_to(tmp_path)
        report = ConformanceRun.report(project, case)
        _, sarif_out = ConformanceRun.scan(project, case, fmt="sarif")
        sarif = json.loads(sarif_out[sarif_out.index("{") :])
        # SARIF carries findings as results and the scan's own operational notes as tool
        # notifications, where a code-scanning platform shows them without raising alerts.
        active = [f for f in report["findings"] if not f.get("suppressed")]
        results = sorted(f["rule_id"] for f in active if f["category"] != "operational")
        notes = sorted(f["rule_id"] for f in report["findings"] if f["category"] == "operational")
        run = sarif["runs"][0]
        assert (
            sorted(r["ruleId"] for r in run["results"] if not r.get("suppressions")) == results
        ), f"{case.id}: results differ"
        notified = sorted(
            n["descriptor"]["id"]
            for i in run["invocations"]
            for n in i["toolExecutionNotifications"]
        )
        assert notified == notes, f"{case.id}: operational notes differ"
        assert run["invocations"][0]["executionSuccessful"] == report["complete"]


class TestFindingsExplainThemselves:
    """UNI-24: a stable rule id from the catalogue, a message, and either a remediation or an
    explanation, on every finding."""

    @pytest.mark.parametrize("case", VALID, ids=lambda c: c.id)
    def test_every_finding(self, case, tmp_path) -> None:
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        known = {r.id for r in RuleSet(RuleLoader.load_builtin())}
        for detector in Registry().detectors():
            declared = getattr(detector, "declared_rules", None)
            if declared is not None:
                known |= {r.id for r in declared()}
        report = ConformanceRun.report(case.copy_to(tmp_path), case)
        for finding in report["findings"]:
            assert finding["message"], finding["rule_id"]
            assert finding["remediation"] or finding["explanation"].get("summary"), finding[
                "rule_id"
            ]
            if not finding["rule_id"].startswith("OPERATIONAL."):
                assert finding["rule_id"] in known, f"{finding['rule_id']} is not a declared rule"
