"""Import reachability: does first-party code import the flagged package at all.

The behaviour under test is deliberately conservative. It annotates, never
suppresses; it lowers only a transitive dependency the code does not import; a
direct dependency not seen imported stays UNKNOWN rather than lowered; and a
known-malicious finding never moves regardless of imports. These are the rules
that keep a reachability heuristic from hiding a real finding.
"""

from __future__ import annotations

from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import (
    Category,
    Confidence,
    Dependency,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.detect import reachability
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.reachability import VULNERABLE_RULE, Reachability


def _unit(path: str, source: str, language: str) -> FileUnit:
    return FileUnit(
        content=FileContent.from_bytes(path, source.encode("utf-8")),
        language=language,
    )


def _dep(name: str, *, direct: bool, ecosystem: str = "pypi") -> Dependency:
    purl = f"pkg:{ecosystem}/{name}@1.0.0"
    return Dependency(
        purl=purl,
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        direct=direct,
    )


def _finding(purl: str, *, rule_id: str = VULNERABLE_RULE) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=Category.SUSPICIOUS,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        message="A known vulnerability affects this dependency.",
        location=Location(path="requirements.txt", package=purl),
        evidence=Evidence(
            kind=EvidenceKind.METADATA,
            match_hash="sha256:x",
            redaction=RedactionMode.NONE,
        ),
        remediation="Upgrade.",
        explanation=Explanation(summary="s", matched_rule=rule_id),
        risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
        detector="advisory",
    )


def _verdict_of(finding: Finding) -> str | None:
    for key, value in finding.evidence.metadata:
        if key == "reachability":
            return value
    return None


class TestCollectImports:
    def test_python_import_and_from_forms(self) -> None:
        units = [
            _unit("a.py", "import requests\nfrom flask import Flask\n", "python"),
            _unit("b.py", "import os.path\nfrom . import sibling\n", "python"),
        ]
        imports = reachability.collect_imports(units)
        assert {"requests", "flask", "os"} <= imports
        # A relative `from . import` contributes no top-level module name.
        assert "sibling" not in imports

    def test_javascript_require_and_import_forms(self) -> None:
        source = (
            "const a = require('lodash');\n"
            "import x from 'express';\n"
            "import { y } from '@scope/pkg/sub';\n"
            "const rel = require('./local');\n"
        )
        imports = reachability.collect_imports([_unit("a.js", source, "javascript")])
        assert {"lodash", "express", "@scope/pkg"} <= imports
        # A relative require is first-party, not a dependency name.
        assert "./local" not in imports
        assert "." not in imports

    def test_a_syntax_error_yields_no_imports_rather_than_raising(self) -> None:
        units = [_unit("broken.py", "def (:\n    import requests\n", "python")]
        assert reachability.collect_imports(units) == set()

    def test_a_non_source_language_is_ignored(self) -> None:
        units = [_unit("data.bin", "import requests", None)]
        assert reachability.collect_imports(units) == set()

    def test_a_non_file_unit_is_skipped(self) -> None:
        from cordon_scanner.detect.base import GraphUnit

        units = [
            GraphUnit(dependencies=()),
            _unit("app.py", "import flask\n", "python"),
        ]
        assert reachability.collect_imports(units) == {"flask"}


class TestAnnotate:
    def test_an_imported_direct_dependency_is_tagged_and_unchanged(self) -> None:
        dep = _dep("requests", direct=True)
        findings = [_finding(dep.purl)]
        units = [_unit("app.py", "import requests\n", "python")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL  # imported: never lowered
        assert _verdict_of(out) == Reachability.IMPORTED.value

    def test_an_unimported_transitive_dependency_is_lowered(self) -> None:
        dep = _dep("leftpad", direct=False)
        findings = [_finding(dep.purl)]
        units = [_unit("app.py", "import requests\n", "python")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.HIGH  # critical -> high
        assert _verdict_of(out) == Reachability.NOT_IMPORTED.value
        assert "not imported" in out.message.lower()

    def test_an_unimported_direct_dependency_stays_unknown(self) -> None:
        # A direct dependency may be imported dynamically or under a name import
        # reachability cannot see, so it is left UNKNOWN, not lowered.
        dep = _dep("requests", direct=True)
        findings = [_finding(dep.purl)]
        units = [_unit("app.py", "print('no imports here')\n", "python")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL
        assert _verdict_of(out) == Reachability.UNKNOWN.value

    def test_a_distribution_name_alias_counts_as_imported(self) -> None:
        # beautifulsoup4 is imported as bs4; the alias table must catch it so the
        # finding is not wrongly lowered.
        dep = _dep("beautifulsoup4", direct=False)
        findings = [_finding(dep.purl)]
        units = [_unit("app.py", "import bs4\n", "python")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL
        assert _verdict_of(out) == Reachability.IMPORTED.value

    def test_an_underscore_hyphen_name_normalizes(self) -> None:
        dep = _dep("python_dateutil", direct=False)
        findings = [_finding(dep.purl)]
        units = [_unit("app.py", "import dateutil\n", "python")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert _verdict_of(out) == Reachability.IMPORTED.value

    def test_a_malicious_finding_is_never_annotated_or_lowered(self) -> None:
        # A compromised release must not be installed whether or not it is called.
        dep = _dep("evil", direct=False)
        findings = [_finding(dep.purl, rule_id="MALWARE.DEPENDENCY.KNOWN.001")]
        units = [_unit("app.py", "print('x')\n", "python")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL
        assert _verdict_of(out) is None  # untouched

    def test_a_finding_for_a_package_not_in_the_graph_is_untouched(self) -> None:
        findings = [_finding("pkg:pypi/ghost@1.0.0")]
        units = [_unit("app.py", "import requests\n", "python")]

        (out,) = reachability.annotate(findings, units, ())

        assert _verdict_of(out) is None

    def test_a_scoped_npm_dependency_matches_its_import(self) -> None:
        dep = _dep("@scope/pkg", direct=False, ecosystem="npm")
        findings = [_finding(dep.purl)]
        units = [_unit("a.js", "import { y } from '@scope/pkg';\n", "javascript")]

        (out,) = reachability.annotate(findings, units, (dep,))

        assert _verdict_of(out) == Reachability.IMPORTED.value

    def test_the_lowering_never_drops_below_low(self) -> None:
        dep = _dep("leftpad", direct=False)
        finding = _finding(dep.purl)
        finding = reachability._annotated(finding, Reachability.NOT_IMPORTED)
        # A LOW finding lowered again stays LOW, never off the scale.
        low = reachability._SEVERITY_DOWN[Severity.LOW]
        assert low is Severity.LOW
