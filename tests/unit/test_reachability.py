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


class ReachabilityHelpers:
    """Helpers for test_reachability.py."""

    @staticmethod
    def _unit(path: str, source: str, language: str) -> FileUnit:
        return FileUnit(
            content=FileContent.from_bytes(path, source.encode("utf-8")),
            language=language,
        )

    @staticmethod
    def _dep(name: str, *, direct: bool, ecosystem: str = "pypi") -> Dependency:
        purl = f"pkg:{ecosystem}/{name}@1.0.0"
        return Dependency(
            purl=purl,
            ecosystem=ecosystem,
            name=name,
            version="1.0.0",
            direct=direct,
        )

    @staticmethod
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

    @staticmethod
    def _verdict_of(finding: Finding) -> str | None:
        for key, value in finding.evidence.metadata:
            if key == "reachability":
                return value
        return None

    @staticmethod
    def _symbols_of(finding: Finding) -> str:
        return dict(finding.evidence.metadata).get("reachability_symbols", "")


class TestCollectImports:
    def test_python_import_and_from_forms(self) -> None:
        units = [
            ReachabilityHelpers._unit(
                "a.py", "import requests\nfrom flask import Flask\n", "python"
            ),
            ReachabilityHelpers._unit("b.py", "import os.path\nfrom . import sibling\n", "python"),
        ]
        imports = reachability.ImportReachability.collect_imports(units)
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
        imports = reachability.ImportReachability.collect_imports(
            [ReachabilityHelpers._unit("a.js", source, "javascript")]
        )
        assert {"lodash", "express", "@scope/pkg"} <= imports
        # A relative require is first-party, not a dependency name.
        assert "./local" not in imports
        assert "." not in imports

    def test_a_syntax_error_yields_no_imports_rather_than_raising(self) -> None:
        units = [ReachabilityHelpers._unit("broken.py", "def (:\n    import requests\n", "python")]
        assert reachability.ImportReachability.collect_imports(units) == set()

    def test_a_non_source_language_is_ignored(self) -> None:
        units = [ReachabilityHelpers._unit("data.bin", "import requests", None)]
        assert reachability.ImportReachability.collect_imports(units) == set()

    def test_a_non_file_unit_is_skipped(self) -> None:
        from cordon_scanner.detect.base import GraphUnit

        units = [
            GraphUnit(dependencies=()),
            ReachabilityHelpers._unit("app.py", "import flask\n", "python"),
        ]
        assert reachability.ImportReachability.collect_imports(units) == {"flask"}


class TestAnnotate:
    def test_an_imported_direct_dependency_is_tagged_and_unchanged(self) -> None:
        dep = ReachabilityHelpers._dep("requests", direct=True)
        findings = [ReachabilityHelpers._finding(dep.purl)]
        units = [ReachabilityHelpers._unit("app.py", "import requests\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL  # imported: never lowered
        assert ReachabilityHelpers._verdict_of(out) == Reachability.IMPORTED.value

    def test_an_unimported_transitive_dependency_is_lowered(self) -> None:
        dep = ReachabilityHelpers._dep("leftpad", direct=False)
        findings = [ReachabilityHelpers._finding(dep.purl)]
        units = [ReachabilityHelpers._unit("app.py", "import requests\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.HIGH  # critical -> high
        assert ReachabilityHelpers._verdict_of(out) == Reachability.NOT_IMPORTED.value
        assert "not imported" in out.message.lower()

    def test_an_unimported_direct_dependency_stays_unknown(self) -> None:
        # A direct dependency may be imported dynamically or under a name import
        # reachability cannot see, so it is left UNKNOWN, not lowered.
        dep = ReachabilityHelpers._dep("requests", direct=True)
        findings = [ReachabilityHelpers._finding(dep.purl)]
        units = [ReachabilityHelpers._unit("app.py", "print('no imports here')\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL
        assert ReachabilityHelpers._verdict_of(out) == Reachability.UNKNOWN.value

    def test_a_distribution_name_alias_counts_as_imported(self) -> None:
        # beautifulsoup4 is imported as bs4; the alias table must catch it so the
        # finding is not wrongly lowered.
        dep = ReachabilityHelpers._dep("beautifulsoup4", direct=False)
        findings = [ReachabilityHelpers._finding(dep.purl)]
        units = [ReachabilityHelpers._unit("app.py", "import bs4\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL
        assert ReachabilityHelpers._verdict_of(out) == Reachability.IMPORTED.value

    def test_an_underscore_hyphen_name_normalizes(self) -> None:
        dep = ReachabilityHelpers._dep("python_dateutil", direct=False)
        findings = [ReachabilityHelpers._finding(dep.purl)]
        units = [ReachabilityHelpers._unit("app.py", "import dateutil\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert ReachabilityHelpers._verdict_of(out) == Reachability.IMPORTED.value

    def test_a_malicious_finding_is_never_annotated_or_lowered(self) -> None:
        # A compromised release must not be installed whether or not it is called.
        dep = ReachabilityHelpers._dep("evil", direct=False)
        findings = [ReachabilityHelpers._finding(dep.purl, rule_id="MALWARE.DEPENDENCY.KNOWN.001")]
        units = [ReachabilityHelpers._unit("app.py", "print('x')\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert out.severity is Severity.CRITICAL
        assert ReachabilityHelpers._verdict_of(out) is None  # untouched

    def test_a_finding_for_a_package_not_in_the_graph_is_untouched(self) -> None:
        findings = [ReachabilityHelpers._finding("pkg:pypi/ghost@1.0.0")]
        units = [ReachabilityHelpers._unit("app.py", "import requests\n", "python")]

        (out,) = reachability.ImportReachability.annotate(findings, units, ())

        assert ReachabilityHelpers._verdict_of(out) is None

    def test_a_scoped_npm_dependency_matches_its_import(self) -> None:
        dep = ReachabilityHelpers._dep("@scope/pkg", direct=False, ecosystem="npm")
        findings = [ReachabilityHelpers._finding(dep.purl)]
        units = [
            ReachabilityHelpers._unit("a.js", "import { y } from '@scope/pkg';\n", "javascript")
        ]

        (out,) = reachability.ImportReachability.annotate(findings, units, (dep,))

        assert ReachabilityHelpers._verdict_of(out) == Reachability.IMPORTED.value

    def test_the_lowering_never_drops_below_low(self) -> None:
        dep = ReachabilityHelpers._dep("leftpad", direct=False)
        finding = ReachabilityHelpers._finding(dep.purl)
        finding = reachability.ImportReachability._annotated(finding, Reachability.NOT_IMPORTED)
        # A LOW finding lowered again stays LOW, never off the scale.
        low = reachability._SEVERITY_DOWN[Severity.LOW]
        assert low is Severity.LOW


class TestTheCallTier:
    """Beyond "is it imported": which of its functions first-party code actually calls."""

    def test_python_calls_through_every_binding_form(self) -> None:
        dep = ReachabilityHelpers._dep("pyyaml", direct=True)
        source = (
            "import yaml\n"
            "import yaml as y\n"
            "from yaml import safe_load as parse\n"
            "yaml.load(stream)\n"
            "y.dump(data)\n"
            "parse(text)\n"
            "handler = yaml.full_load\n"
        )
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("app.py", source, "python")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED.value
        assert (
            ReachabilityHelpers._symbols_of(out)
            == "yaml.dump,yaml.full_load,yaml.load,yaml.safe_load"
        )
        assert out.severity is Severity.CRITICAL, "a call is never a reason to lower"
        assert "compare those with the functions the advisory names" in out.message

    def test_python_type_checking_imports_are_type_only_and_lowered(self) -> None:
        dep = ReachabilityHelpers._dep("requests", direct=True)
        source = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import requests\n\ndef f(s: 'requests.Session') -> None: ...\n"
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("app.py", source, "python")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.TYPE_ONLY.value
        assert out.severity is Severity.HIGH

    def test_an_import_with_no_call_is_imported_and_unchanged(self) -> None:
        dep = ReachabilityHelpers._dep("requests", direct=True)
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("app.py", "import requests\n", "python")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.IMPORTED.value
        assert out.severity is Severity.CRITICAL

    def test_javascript_every_binding_form(self) -> None:
        dep = ReachabilityHelpers._dep("lodash", direct=True, ecosystem="npm")
        source = (
            "import _ from 'lodash';\n"
            "import { merge, template as tpl } from 'lodash';\n"
            "const { get } = require('lodash');\n"
            "_.zip(a, b);\nmerge(x, y);\ntpl(s);\nget(o, 'k');\n"
        )
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("a.js", source, "javascript")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED.value
        assert (
            ReachabilityHelpers._symbols_of(out)
            == "lodash.get,lodash.merge,lodash.template,lodash.zip"
        )

    def test_typescript_import_type_is_type_only(self) -> None:
        dep = ReachabilityHelpers._dep("express", direct=True, ecosystem="npm")
        source = "import type { Request } from 'express';\nexport function h(r: Request) {}\n"
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("a.ts", source, "typescript")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.TYPE_ONLY.value

    def test_a_side_effect_import_is_a_runtime_import(self) -> None:
        dep = ReachabilityHelpers._dep("core-js", direct=True, ecosystem="npm")
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("a.js", "import 'core-js';\n", "javascript")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.IMPORTED.value

    def test_the_exploited_rule_is_annotated_too(self) -> None:
        dep = ReachabilityHelpers._dep("pyyaml", direct=False)
        finding = ReachabilityHelpers._finding(
            dep.purl, rule_id="VULNERABLE.DEPENDENCY.EXPLOITED.001"
        )
        (out,) = reachability.ImportReachability.annotate(
            [finding], [ReachabilityHelpers._unit("app.py", "x = 1\n", "python")], (dep,)
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.NOT_IMPORTED.value


class TestThePythonCallGraph:
    def test_a_call_only_in_an_unreferenced_private_function_is_unreached(self) -> None:
        dep = ReachabilityHelpers._dep("pyyaml", direct=True)
        units = [
            ReachabilityHelpers._unit(
                "app.py",
                "import yaml\n\ndef _old_loader(s):\n    return yaml.load(s)\n\ndef main():\n    return 1\n",
                "python",
            ),
        ]
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)], units, (dep,)
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED_UNREACHED.value
        assert out.severity is Severity.HIGH, "lowered, never dropped"

    def test_a_reference_from_another_module_makes_it_reached(self) -> None:
        dep = ReachabilityHelpers._dep("pyyaml", direct=True)
        units = [
            ReachabilityHelpers._unit(
                "loader.py", "import yaml\n\ndef _load(s):\n    return yaml.load(s)\n", "python"
            ),
            ReachabilityHelpers._unit(
                "main.py", "from loader import _load\n_load('x')\n", "python"
            ),
        ]
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)], units, (dep,)
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED.value

    def test_public_and_decorated_functions_are_roots(self) -> None:
        dep = ReachabilityHelpers._dep("pyyaml", direct=True)
        for source in (
            "import yaml\n\ndef load_config(s):\n    return yaml.load(s)\n",
            "import yaml\n\n@app.route('/')\ndef _handler():\n    return yaml.load('x')\n",
            "import yaml\n\nclass Loader:\n    def _parse(self, s):\n        return yaml.load(s)\n    def run(self):\n        return self._parse('x')\n",
        ):
            (out,) = reachability.ImportReachability.annotate(
                [ReachabilityHelpers._finding(dep.purl)],
                [ReachabilityHelpers._unit("m.py", source, "python")],
                (dep,),
            )
            assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED.value, source

    def test_a_name_in_a_string_keeps_a_function_reached(self) -> None:
        dep = ReachabilityHelpers._dep("pyyaml", direct=True)
        source = "import yaml\n\ndef _load(s):\n    return yaml.load(s)\n\nhandler = getattr(module, '_load')\n"
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("m.py", source, "python")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED.value


class TestTheJavaScriptCallGraph:
    def test_a_call_only_in_an_unexported_never_named_function(self) -> None:
        dep = ReachabilityHelpers._dep("lodash", direct=True, ecosystem="npm")
        source = "const _ = require('lodash');\nfunction legacyMerge(a, b) {\n  return _.merge(a, b);\n}\nexport function run() { return 1; }\n"
        (out,) = reachability.ImportReachability.annotate(
            [ReachabilityHelpers._finding(dep.purl)],
            [ReachabilityHelpers._unit("a.js", source, "javascript")],
            (dep,),
        )
        assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED_UNREACHED.value

    def test_exported_or_named_elsewhere_is_reached(self) -> None:
        dep = ReachabilityHelpers._dep("lodash", direct=True, ecosystem="npm")
        for units in (
            [
                ReachabilityHelpers._unit(
                    "a.js",
                    "const _ = require('lodash');\nexport function merge2(a, b) {\n  return _.merge(a, b);\n}\n",
                    "javascript",
                )
            ],
            [
                ReachabilityHelpers._unit(
                    "a.js",
                    "const _ = require('lodash');\nconst merge2 = (a, b) => {\n  return _.merge(a, b);\n};\nmodule.exports = { merge2 };\n",
                    "javascript",
                ),
            ],
            [
                ReachabilityHelpers._unit(
                    "a.js",
                    "const _ = require('lodash');\nfunction merge2(a, b) {\n  return _.merge(a, b);\n}\n",
                    "javascript",
                ),
                ReachabilityHelpers._unit("b.js", "merge2(1, 2);\n", "javascript"),
            ],
        ):
            (out,) = reachability.ImportReachability.annotate(
                [ReachabilityHelpers._finding(dep.purl)], units, (dep,)
            )
            assert ReachabilityHelpers._verdict_of(out) == Reachability.CALLED.value


class TestBranchesOnACommandTypedByHand:
    SOURCE = (
        "import sys, socket\n"
        "def serve():\n    socket.gethostname()\n"
        "def build():\n    pass\n"
        "command = sys.argv[-1]\n"
        "if command == 'coverage':\n    serve()\n"
        "elif command == 'build':\n    build()\n"
    )

    def test_the_coverage_branch_is_not_install_time(self) -> None:
        from cordon_scanner.core.reachability import CallReachability

        deferred = CallReachability.deferred_lines(
            ["setup.py"], {"setup.py": self.SOURCE}, ["setup.py"]
        )
        assert ("setup.py", 3, 3) in deferred

    def test_an_install_command_branch_is(self) -> None:
        from cordon_scanner.core.reachability import CallReachability

        deferred = CallReachability.deferred_lines(
            ["setup.py"], {"setup.py": self.SOURCE}, ["setup.py"]
        )
        assert ("setup.py", 5, 5) not in deferred


class TestGoVulnerableFunctions:
    MAIN = (
        'package main\n\nimport (\n\t"fmt"\n\tnethttp "net/http"\n\t"golang.org/x/net/html"\n)\n\n'
        "func main() {\n\tdoc, _ := html.Parse(nil)\n\tfmt.Println(doc)\n\t_ = nethttp.StatusOK\n}\n"
    )

    def _usage(self, text: str):
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.detect.reachability import GoUsage

        return GoUsage.of([FileUnit(FileContent.from_bytes("cmd/main.go", text.encode()))])

    def test_a_called_vulnerable_function_is_named(self) -> None:
        from cordon_scanner.detect.reachability import Reachability

        verdict, names = self._usage(self.MAIN).verdict(["golang.org/x/net/html:Parse"])
        assert verdict is Reachability.VULNERABLE_CALLED and names == [
            "golang.org/x/net/html.Parse"
        ]

    def test_an_imported_package_whose_vulnerable_function_is_not_called(self) -> None:
        from cordon_scanner.detect.reachability import Reachability

        verdict, _ = self._usage(self.MAIN).verdict(["net/http:ReadRequest"])
        assert verdict is Reachability.VULNERABLE_NOT_CALLED

    def test_a_package_nobody_imports_is_unknown_here(self) -> None:
        from cordon_scanner.detect.reachability import Reachability

        verdict, _ = self._usage(self.MAIN).verdict(["golang.org/x/crypto/ssh:NewServerConn"])
        assert verdict is Reachability.UNKNOWN

    def test_a_method_is_matched_by_name(self) -> None:
        from cordon_scanner.detect.reachability import Reachability

        text = 'package main\n\nimport "net/http"\n\nfunc f(r *http.Request) { r.ParseMultipartForm(1) }\n'
        verdict, _ = self._usage(text).verdict(["net/http:Request.ParseMultipartForm"])
        assert verdict is Reachability.VULNERABLE_CALLED

    def test_the_importer_keeps_go_symbols(self) -> None:
        from cordon_scanner.intel.osv_import import OsvImport

        entry = {
            "ecosystem_specific": {
                "imports": [{"path": "net/http", "symbols": ["ReadRequest", "Request.ParseForm"]}]
            }
        }
        assert OsvImport._vulnerable_symbols(entry) == (
            "net/http:ReadRequest",
            "net/http:Request.ParseForm",
        )
