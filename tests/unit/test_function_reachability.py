"""G8: function-level reachability for PyPI and npm, from the functions an advisory's text names.

The PyPI and npm sources list no vulnerable symbols, so the names come from the advisory's prose
and carry a `text:` prefix. Tested in both directions that matter: a call to a named function is
promoted to the top, and the absence of one never lowers anything -- prose silence is not proof.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

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
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.reachability import VULNERABLE_RULE, ImportReachability, Reachability
from cordon_scanner.intel.advisory_text import AdvisoryTextSymbols


class FunctionKit:
    @staticmethod
    def unit(path: str, source: str, language: str) -> FileUnit:
        return FileUnit(content=FileContent.from_bytes(path, source.encode()), language=language)

    @staticmethod
    def dep(name: str, ecosystem: str, *, direct: bool = True) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/{name}@1.0.0",
            ecosystem=ecosystem,
            name=name,
            version="1.0.0",
            direct=direct,
        )

    @staticmethod
    def finding(dep: Dependency, symbols: tuple[str, ...]) -> Finding:
        metadata = (("vulnerable_symbols", ",".join(symbols)),) if symbols else ()
        return Finding(
            rule_id=VULNERABLE_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message="A known vulnerability affects this dependency.",
            location=Location(path="lockfile", package=dep.purl),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash="sha256:x",
                redaction=RedactionMode.NONE,
                metadata=metadata,
            ),
            remediation="Upgrade.",
            explanation=Explanation(summary="s", matched_rule=VULNERABLE_RULE),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector="advisory",
        )

    @classmethod
    def annotate(cls, dep: Dependency, symbols: tuple[str, ...], units: list[FileUnit]) -> Finding:
        (out,) = ImportReachability.annotate([cls.finding(dep, symbols)], units, (dep,))
        return out

    @staticmethod
    def verdict(finding: Finding) -> str:
        return dict(finding.evidence.metadata).get("reachability", "")


class TestExtraction:
    @pytest.mark.parametrize(
        "ecosystem, package, text, expected",
        [
            ("pypi", "PyYAML", "Unsafe `yaml.load()` and `yaml.full_load` allow code execution.", ("text:yaml.load", "text:yaml.full_load")),
            ("npm", "lodash", "Prototype pollution in the `merge`, `mergeWith`, and `defaultsDeep` functions.",
             ("text:lodash.merge", "text:lodash.mergeWith", "text:lodash.defaultsDeep")),
            ("npm", "lodash", "`_.template` evaluates its input.", ("text:lodash.template",)),
            ("pypi", "Pillow", "A crash in PIL.ImageFont.truetype(font) on crafted fonts.", ("text:PIL.ImageFont.truetype",)),
            ("npm", "minimist", "Calling `parse()` with crafted input pollutes Object.prototype.", ("text:minimist.parse",)),
        ],
    )  # fmt: skip
    def test_names_the_prose_gives(self, ecosystem, package, text, expected) -> None:
        assert AdvisoryTextSymbols.extract(ecosystem, package, text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "Use `yaml.safe_load` instead.",
            "Calling `jinja2.sandbox.SandboxedEnvironment.from_string` is safe.",
            "As a workaround, avoid `yaml.load` on untrusted input.",
            "Upgrade to 6.0; `yaml.load` is fixed in that release.",
        ],
    )
    def test_advice_names_the_fix_not_the_flaw(self, text) -> None:
        assert AdvisoryTextSymbols.extract("pypi", "PyYAML", text) == ()

    @pytest.mark.parametrize(
        "text",
        [
            "Axios is vulnerable to SSRF when a `baseURL` is set and `true` is passed.",
            "No function is named here.",
            "The `requests` package is affected.",
            "`os.system` is called by the installer.",
        ],
    )
    def test_names_that_are_not_this_packages_functions_are_ignored(self, text) -> None:
        assert AdvisoryTextSymbols.extract("npm", "axios", text) == ()

    def test_other_ecosystems_are_untouched(self) -> None:
        assert (
            AdvisoryTextSymbols.extract("gomod", "golang.org/x/net", "`html.Parse()` loops.") == ()
        )

    def test_output_is_bounded(self) -> None:
        text = " ".join(f"`yaml.f{i}()`" for i in range(100))
        assert len(AdvisoryTextSymbols.extract("pypi", "pyyaml", text)) == 20

    def test_matching_is_exact_after_normalising_subpaths(self) -> None:
        assert AdvisoryTextSymbols.matches("lodash/merge", "text:lodash.merge")
        assert AdvisoryTextSymbols.matches("yaml.load", "text:yaml.load")
        assert not AdvisoryTextSymbols.matches(
            "jinja2.Environment", "text:jinja2.Environment.from_string"
        )
        assert not AdvisoryTextSymbols.matches("yaml.safe_load", "text:yaml.load")


class TestFunctionReachability:
    def test_a_python_call_to_the_named_function_is_promoted(self) -> None:
        dep = FunctionKit.dep("pyyaml", "pypi")
        units = [
            FunctionKit.unit("app.py", "import yaml\nconfig = yaml.load(open('c'))\n", "python")
        ]
        out = FunctionKit.annotate(dep, ("text:yaml.load",), units)
        assert FunctionKit.verdict(out) == Reachability.VULNERABLE_CALLED.value
        assert out.severity is Severity.HIGH and "Fix this one first" in out.message

    def test_a_from_import_binding_is_followed(self) -> None:
        dep = FunctionKit.dep("pyyaml", "pypi")
        units = [FunctionKit.unit("app.py", "from yaml import load\nload(x)\n", "python")]
        assert (
            FunctionKit.verdict(FunctionKit.annotate(dep, ("text:yaml.load",), units))
            == "vulnerable_called"
        )

    def test_a_javascript_call_through_require_is_promoted(self) -> None:
        dep = FunctionKit.dep("lodash", "npm")
        units = [
            FunctionKit.unit("a.js", "const _ = require('lodash');\n_.merge(a, b);\n", "javascript")
        ]
        assert (
            FunctionKit.verdict(FunctionKit.annotate(dep, ("text:lodash.merge",), units))
            == "vulnerable_called"
        )

    def test_a_subpath_import_is_the_same_function(self) -> None:
        dep = FunctionKit.dep("lodash", "npm")
        units = [
            FunctionKit.unit(
                "a.js", "import merge from 'lodash/merge';\nmerge(a, b);\n", "javascript"
            )
        ]
        assert (
            FunctionKit.verdict(FunctionKit.annotate(dep, ("text:lodash.merge",), units))
            == "vulnerable_called"
        )

    def test_calling_only_other_functions_is_never_lowered(self) -> None:
        dep = FunctionKit.dep("pyyaml", "pypi")
        units = [
            FunctionKit.unit(
                "app.py", "import yaml\nconfig = yaml.safe_load(open('c'))\n", "python"
            )
        ]
        out = FunctionKit.annotate(dep, ("text:yaml.load",), units)
        assert FunctionKit.verdict(out) == Reachability.CALLED.value
        assert out.severity is Severity.HIGH

    def test_an_unimported_transitive_dependency_keeps_the_import_tier_verdict(self) -> None:
        dep = FunctionKit.dep("pyyaml", "pypi", direct=False)
        out = FunctionKit.annotate(
            dep, ("text:yaml.load",), [FunctionKit.unit("app.py", "print(1)\n", "python")]
        )
        assert FunctionKit.verdict(out) == Reachability.NOT_IMPORTED.value

    def test_go_symbol_lists_are_untouched(self) -> None:
        dep = FunctionKit.dep("golang.org/x/net", "gomod")
        go = FunctionKit.unit(
            "main.go",
            'package main\nimport "golang.org/x/net/html"\nfunc main() { html.Parse(nil) }\n',
            "go",
        )
        out = FunctionKit.annotate(dep, ("golang.org/x/net/html:Parse",), [go])
        assert FunctionKit.verdict(out) == Reachability.VULNERABLE_CALLED.value

    def test_a_mixed_list_is_not_treated_as_prose(self) -> None:
        assert not AdvisoryTextSymbols.is_text(["text:a.b", "golang.org/x/net/html:Parse"])
        assert AdvisoryTextSymbols.is_text(["text:a.b"])
        assert not AdvisoryTextSymbols.is_text([])

    def test_a_malicious_package_finding_is_never_touched(self) -> None:
        dep = FunctionKit.dep("evil", "npm")
        finding = replace(
            FunctionKit.finding(dep, ("text:evil.run",)),
            rule_id="MALWARE.DEPENDENCY.KNOWN.001",
            fingerprint="",
        )
        (out,) = ImportReachability.annotate([finding], [], (dep,))
        assert out == finding


class TestDatabaseMetadataAfterAPartialBuild:
    """`build_advisory_db.py --only pypi` rewrote the record count as PyPI's alone."""

    @staticmethod
    def advisory(ecosystem: str, name: str):
        from cordon_scanner.intel.advisories import Advisory

        return Advisory(
            ecosystem=ecosystem,
            name=name,
            versions=("1.0.0",),
            summary="s",
            identifier=f"GHSA-{name}",
        )

    def test_the_count_and_sources_describe_every_installed_ecosystem(self, tmp_path) -> None:
        import json

        from cordon_scanner.intel.advisories import DatabaseMeta
        from cordon_scanner.intel.osv_import import OsvImport, SyncResult

        full = SyncResult(
            per_ecosystem={
                "npm": (self.advisory("npm", "a"), self.advisory("npm", "b")),
                "cargo": (self.advisory("cargo", "c"),),
            },
            meta=DatabaseMeta(built_at="t1", sources=("osv:npm", "osv:cargo"), record_count=3),
        )
        OsvImport.write_output(full, tmp_path)
        partial = SyncResult(
            per_ecosystem={"pypi": (self.advisory("pypi", "d"),)},
            meta=DatabaseMeta(built_at="t2", sources=("osv:pypi",), record_count=1),
        )
        OsvImport.write_output(partial, tmp_path)
        meta = json.loads((tmp_path / "advisories-meta.json").read_text(encoding="utf-8"))
        assert meta["record_count"] == 4
        assert meta["sources"] == ["osv:cargo", "osv:npm", "osv:pypi"]

    def test_an_ecosystem_whose_file_is_gone_drops_its_source(self, tmp_path) -> None:
        import json

        from cordon_scanner.intel.advisories import DatabaseMeta
        from cordon_scanner.intel.osv_import import OsvImport, SyncResult

        OsvImport.write_output(
            SyncResult(
                per_ecosystem={"npm": (self.advisory("npm", "a"),)},
                meta=DatabaseMeta(sources=("osv:npm",), record_count=1),
            ),
            tmp_path,
        )
        (tmp_path / "advisories-npm.json.gz").unlink()
        OsvImport.write_output(
            SyncResult(
                per_ecosystem={"cargo": (self.advisory("cargo", "c"),)},
                meta=DatabaseMeta(sources=("osv:cargo",), record_count=1),
            ),
            tmp_path,
        )
        meta = json.loads((tmp_path / "advisories-meta.json").read_text(encoding="utf-8"))
        assert meta["record_count"] == 1 and meta["sources"] == ["osv:cargo"]
