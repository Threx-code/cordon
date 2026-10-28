"""The intent layer (`core/intent.py`, review 98 `19-INTENT-ANALYSIS.md`): facts, reach, the
weights file's rules, the combiner, the engine's use of it, and the weights builder.

Fixtures are single calls with sensitive names split, as the rest of the suite writes them; no
sample, real or modified. Weights here are made up for the test, never measured ones.
"""

from __future__ import annotations

import gzip
import json
import math
from pathlib import Path
from typing import ClassVar
from unittest import mock

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.intent import (
    RULE,
    Intent,
    IntentFacts,
    IntentObserver,
    IntentScore,
    IntentWeights,
    Observation,
)
from cordon_scanner.decide.verdict import VerdictFeatures
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Category, Severity
from unit.foundation.test_npm_work_half_classes import Npm

CP = "child_" + "process"


class Kit:
    @staticmethod
    def row(fact: str, ratio: float, families: int = 9) -> dict[str, object]:
        cost, group = IntentFacts.classify(fact) or ("?", "?")
        return {
            "cost": cost,
            "group": group,
            "families": families,
            "ratio": ratio,
            "weight": math.log(min(IntentWeights.CAP, ratio)),
            "provenance": IntentFacts.provenance(fact),
            "kept": True,
        }

    @staticmethod
    def model(**rows: float) -> dict[str, object]:
        """A weights file that satisfies every rule of the loader; `rows` maps fact -> ratio."""
        facts = {
            "t:install:egress": 20.0,
            "hook": 3.0,
            "conceal:loader": 10.0,
            "has_readme": 2.0,
            "has_types": 2.0,
            "purpose_text": 2.0,
        }
        facts.update({k.replace("__", ":"): v for k, v in rows.items()})
        return {
            "format": IntentWeights.FORMAT,
            "facts_version": IntentFacts.VERSION,
            "version": "test",
            "scanner_commit": "0" * 40,
            "dataset": "made up for the unit tests",
            "date": "2026-10-19",
            "scope": ["npm"],
            "threshold": 3.5,
            "cheap_cap": math.log(2),
            "mismatch_limit": 0.01,
            "envelope_min_n": 50,
            "threshold_benign": {"k": 0, "n": 2000, "rate": 0.0, "upper": 0.0019},
            "envelopes": {"all": {"n": 1000, "zero": 0.0038, "upper": {}}},
            "rows": {f: Kit.row(f, r) for f, r in facts.items()},
        }

    @staticmethod
    def scan(target: Path, model: dict | None) -> object:
        with mock.patch.object(IntentWeights, "load", return_value=model):
            return Scanner(Config.default().with_overrides(use_cache=False)).scan(target)

    @staticmethod
    def facts(target: Path) -> set[str]:
        result = Kit.scan(target, None)
        return set(result.verdict["intent"]["facts"])


class TestTheFactModel:
    """Step 1: named, typed facts; only content facts enter (E6), never rule outcomes (M7)."""

    @pytest.mark.parametrize(
        "name",
        [
            "reg_age_days",
            "reg_known",
            "log_bytes",
            "log_bytes<=3",
            "deps_unknown",
            "deps_unused_unknown",
            "intel_hit",
            "publisher_new",
            "SUSPECT.X.001",
            "r:SUSPECT.X.001",
            "fam:MALWARE.EXFIL",
            "n_files<=7",
            "t:install:nothing",
            "t:someday:egress",
            "made_up",
        ],
    )
    def test_what_is_not_a_content_fact_is_refused(self, name: str) -> None:
        assert IntentFacts.classify(name) is None

    @pytest.mark.parametrize(
        ("name", "cost", "group"),
        [
            ("t:install:egress", "effect", "install:network"),
            ("m:import:spawn", "effect", "import:process"),
            ("install_can_egress", "effect", "install:network"),
            ("install_can_fetch_exec", "effect", "install:network"),
            ("conceal:loader", "structural", "conceal"),
            ("conceal:charcode:dense", "structural", "conceal"),
            ("gate:time", "structural", "gate"),
            ("purpose_ui", "claim", "claim:purpose"),
            ("has_readme", "cosmetic", "cosmetic:has_readme"),
            ("n_files<=3", "cosmetic", "cosmetic:n_files"),
            ("install_capabilities>=2", "effect", "install:breadth"),
            ("code_share>=0.5", "structural", "structure:share"),
        ],
    )
    def test_each_fact_has_its_cost_class_and_group(self, name, cost, group) -> None:
        assert IntentFacts.classify(name) == (cost, group)

    def test_the_same_effect_by_two_readings_is_one_group(self) -> None:
        """E1: the profile's `install_can_egress` and the trigger's `t:install:egress` say the
        same thing; the group lets only the stronger count."""
        assert (
            IntentFacts.classify("install_can_egress")[1]
            == IntentFacts.classify("t:install:egress")[1]
        )

    def test_package_facts_are_read_at_their_cuts_and_external_ones_dropped(self) -> None:
        package = {
            "hook": 1.0,
            "n_files": 2.0,
            "log_bytes": 3.0,
            "reg_age_days": 1.0,
            "deps_unknown": 4.0,
            "install_can_egress": 1.0,
            "install_capabilities": 3.0,
            "purpose_text": 0.0,
        }
        assert IntentFacts.base(package) == {
            "hook",
            "n_files<=3",
            "n_files<=10",
            "install_can_egress",
            "install_capabilities>=2",
        }

    def test_an_external_fact_cannot_enter_the_record(self, tmp_path) -> None:
        observation = Observation(facts={"t:install:egress", "reg_age_days", "SUSPECT.X.001"})
        review = Intent.review({"reg_known": 1.0, "hook": 1.0}, "npm", observation)
        assert review is not None
        assert set(review["facts"]) == {"t:install:egress", "hook"}

    def test_the_same_package_gives_the_same_facts(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-same",
            {"version": "1.0.0", "scripts": {"postinstall": "node s.js"}},
            {"s.js": "require('https').get('https://example.invalid/p');\n"},
        )
        first, second = Kit.scan(pkg, None), Kit.scan(pkg, None)
        assert first.verdict["intent"] == second.verdict["intent"]


class TestTriggers:
    """When each effect runs, read from a whole package."""

    def test_each_place_code_runs_is_its_own_trigger(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-triggers",
            {
                "version": "1.0.0",
                "main": "index.js",
                "bin": {"demo": "cli.js"},
                "scripts": {"postinstall": "node setup.js"},
            },
            {
                "setup.js": "require('https').get('https://example.invalid/p');\n",
                "index.js": "require('./lib/util');\n"
                f"module.exports = function run(c) {{ return require('{CP}').spawn(c); }};\n",
                "lib/util.js": "const dns = require('dns'); dns.lookup('example.invalid', () => {});\n",
                "cli.js": f"require('{CP}').spawn('ls');\n",
                "test/a.test.js": "require('https').get('https://example.invalid/t');\n",
            },
        )
        facts = Kit.facts(pkg)
        assert {
            "t:install:egress",
            "t:import:egress",
            "t:export:spawn",
            "t:bin:spawn",
            "t:test:egress",
        } <= facts
        assert "t:import:spawn" not in facts

    def test_a_library_whose_effects_wait_for_its_user_runs_nothing_unasked(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-client",
            {"version": "1.0.0", "main": "index.js"},
            {
                "index.js": "const https = require('https');\n"
                "exports.get = (u) => new Promise((ok) => https.get(u, ok));\n"
            },
        )
        facts = Kit.facts(pkg)
        assert not any(f.startswith(("t:import:", "t:install:")) for f in facts)

    def test_a_module_used_at_the_top_level_runs_on_import(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-used",
            {"version": "1.0.0", "main": "index.js"},
            {
                "index.js": "const https = require(\x27https\x27);\nhttps.get(\x27https://example.invalid/\x27);\n"
            },
        )
        assert "t:import:egress" in Kit.facts(pkg)

    def test_an_es_module_import_runs_where_its_binding_is_used(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-esm",
            {"version": "1.0.0", "main": "index.mjs", "type": "module"},
            {
                "index.mjs": "import https from \x27https\x27;\n"
                "export function get(u) { return https.get(u); }\n"
            },
        )
        facts = Kit.facts(pkg)
        assert not any(f.startswith("t:import:") for f in facts)

    def test_wrapping_the_top_level_in_a_function_does_not_defer_it(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-wrapped",
            {"version": "1.0.0", "main": "index.js"},
            {
                "index.js": "(function () { const dns = require('dns'); dns.lookup('example.invalid', () => {}); })();\n"
            },
        )
        assert "t:import:egress" in Kit.facts(pkg)

    def test_a_package_of_another_ecosystem_is_not_read(self, tmp_path) -> None:
        (tmp_path / "app.js").write_text(
            "require('https').get('https://example.invalid/');\n", encoding="utf-8"
        )
        result = Kit.scan(tmp_path, Kit.model())
        assert "intent" not in result.verdict


class TestConcealmentAndGates:
    """Steps 2.3 and 2.4."""

    LOAD = "module.constructor._" + "load"

    def run(self, tmp_path, name: str, text: str) -> set[str]:
        pkg = Npm.build(
            tmp_path,
            name,
            {"version": "1.0.0", "scripts": {"postinstall": "node s.js"}},
            {"s.js": text},
        )
        return Kit.facts(pkg)

    def test_a_module_loaded_through_the_loaders_internals(self, tmp_path) -> None:
        assert "conceal:loader" in self.run(tmp_path, "demo-l", f"{self.LOAD}('os');\n")

    def test_a_require_of_a_computed_name(self, tmp_path) -> None:
        facts = self.run(tmp_path, "demo-r", "const m = require(['o', 's'].join(''));\n")
        assert "conceal:computed_require" in facts

    def test_dense_character_codes(self, tmp_path) -> None:
        text = "const s = [" + ",".join(["String.fromCharCode(104)"] * 10) + "].join('');\n"
        assert "conceal:charcode:dense" in self.run(tmp_path, "demo-c", text)

    def test_plain_names_conceal_nothing(self, tmp_path) -> None:
        facts = self.run(tmp_path, "demo-p", "const os = require('os');\nconsole.log(os.EOL);\n")
        assert not any(f.startswith("conceal:") for f in facts)

    def test_an_effect_behind_an_environment_check(self, tmp_path) -> None:
        text = (
            "const h = require('https');\nif (process.env.CI) { process.exit(0); }\n"
            "h.get('https://example.invalid/p');\n"
        )
        assert "gate:env" in self.run(tmp_path, "demo-g", text)

    def test_an_effect_behind_the_clock(self, tmp_path) -> None:
        text = (
            "if (Date.now() > 1900000000000) {\n"
            "  require('https').get('https://example.invalid/p');\n}\n"
        )
        assert "gate:time" in self.run(tmp_path, "demo-t", text)

    def test_a_check_with_no_effect_is_no_gate(self, tmp_path) -> None:
        text = "if (process.env.CI) { process.exit(0); }\nconsole.log('thanks');\n"
        assert not any(f.startswith("gate:") for f in self.run(tmp_path, "demo-n", text))


class TestPurposeEnvelope:
    """Step 2.2: an effect is a mismatch only where benign packages of the claimed purpose rarely
    have it -- on the upper bound, so an unmeasured purpose explains everything."""

    ENVELOPES: ClassVar[dict[str, dict]] = {
        "all": {"n": 5000, "zero": 0.001, "upper": {"t:import:egress": 0.04}},
        "ui": {"n": 800, "zero": 0.005, "upper": {}},
        "http": {"n": 900, "zero": 0.004, "upper": {"t:import:egress": 0.3}},
        "time": {"n": 10, "zero": 0.3, "upper": {}},
    }

    def test_a_ui_package_reaching_the_network_on_import_is_a_mismatch(self) -> None:
        facts = {"purpose_ui", "t:import:egress"}
        assert IntentFacts.mismatched(facts, self.ENVELOPES, 0.01, 50) == {"m:import:egress"}

    def test_an_http_client_doing_so_is_explained(self) -> None:
        facts = {"purpose_ui", "purpose_http", "t:import:egress"}
        assert IntentFacts.mismatched(facts, self.ENVELOPES, 0.01, 50) == set()

    def test_a_purpose_measured_on_few_packages_falls_back_to_all(self) -> None:
        facts = {"purpose_time", "t:import:egress"}
        assert IntentFacts.mismatched(facts, self.ENVELOPES, 0.01, 50) == set()

    def test_test_code_is_never_a_mismatch(self) -> None:
        facts = {"purpose_ui", "t:test:spawn"}
        assert IntentFacts.mismatched(facts, self.ENVELOPES, 0.01, 50) == set()


class TestTheCombiner:
    """Step 4: strongest row per group (E1), cosmetic total capped (M6), deterministic."""

    def test_one_group_counts_once(self) -> None:
        model = Kit.model(install_can_egress=5.0)
        both = IntentScore.contributions({"t:install:egress", "install_can_egress"}, model)
        assert [c.fact for c in both] == ["t:install:egress"]

    def test_cosmetic_padding_never_crosses_alone(self) -> None:
        model = Kit.model(has_tests=2.0, has_changelog=2.0, has_license=2.0)
        facts = {"has_readme", "has_types", "has_tests", "has_changelog", "has_license"}
        score = IntentScore.score(IntentScore.contributions(facts, model), model)
        assert score == pytest.approx(math.log(2))
        assert not IntentScore.crosses(score, model)

    def test_cosmetic_facts_add_at_most_their_cap(self) -> None:
        model = Kit.model(has_tests=2.0, has_changelog=2.0)
        few = IntentScore.contributions({"hook", "has_readme"}, model)
        many = IntentScore.contributions(
            {"hook", "has_readme", "has_types", "has_tests", "has_changelog"}, model
        )
        expected = math.log(3.0) + math.log(2)
        assert IntentScore.score(few, model) == pytest.approx(expected)
        assert IntentScore.score(many, model) == pytest.approx(expected)

    def test_a_claim_is_not_cosmetic_and_is_not_capped_with_it(self) -> None:
        model = Kit.model()
        score = IntentScore.score(
            IntentScore.contributions({"has_readme", "has_types", "purpose_text"}, model), model
        )
        assert score == pytest.approx(math.log(2) + math.log(2))

    def test_the_result_does_not_depend_on_order(self) -> None:
        model = Kit.model()
        facts = ["hook", "t:install:egress", "conceal:loader", "has_readme"]
        a = IntentScore.contributions(facts, model)
        b = IntentScore.contributions(list(reversed(facts)), model)
        assert a == b

    def test_a_running_file_not_read_is_unknown_never_a_pass(self) -> None:
        with mock.patch.object(IntentWeights, "load", return_value=Kit.model()):
            review = Intent.review(
                {}, "npm", Observation(facts={"hook"}, unexamined=["index.js: binary"])
            )
        assert review["decision"] == "unknown"
        assert review["unexamined"] == ["index.js: binary"]

    def test_unknown_gives_way_to_a_block(self) -> None:
        observation = Observation(
            facts={"t:install:egress", "conceal:loader"}, unexamined=["x.js: binary"]
        )
        with mock.patch.object(IntentWeights, "load", return_value=Kit.model()):
            assert Intent.review({}, "npm", observation)["decision"] == "block"


class TestTheWeightsFile:
    """Step 3: the loader refuses any file a rule of the design does not hold for."""

    def test_a_file_that_keeps_every_rule_is_accepted(self, tmp_path) -> None:
        path = tmp_path / "intent.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(Kit.model(), handle)
        assert IntentWeights.problems(Kit.model()) == []
        assert IntentWeights.load(path) is not None

    def test_no_file_no_layer(self, tmp_path) -> None:
        assert IntentWeights.load(tmp_path / "absent.json.gz") is None

    @pytest.mark.parametrize(
        ("breakage", "complaint"),
        [
            (lambda m: m["rows"]["hook"].update(families=4), "families"),
            (lambda m: m["rows"]["hook"].update(weight=2.0), "log of its conservative ratio"),
            (lambda m: m["rows"]["hook"].update(kept=False), "M8"),
            (lambda m: m["rows"]["hook"].update(cost="cosmetic"), "cost class"),
            (lambda m: m["rows"].update(reg_age_days=Kit.row("hook", 3.0)), "E6"),
            (lambda m: m["rows"]["hook"].update(ratio=0.8, weight=math.log(0.8)), "weight"),
            (lambda m: m.update(cheap_cap=3.5), "M6"),
            (lambda m: m["rows"]["hook"].update(provenance="external"), "provenance"),
            (lambda m: m.update(facts_version=IntentFacts.VERSION + 1), "S3"),
            (lambda m: m.update(scanner_commit=""), "scanner_commit"),
            (lambda m: m["threshold_benign"].update(upper=0.006), "T5"),
            (lambda m: m.update(scope=[]), "M3"),
        ],
    )
    def test_a_file_breaking_a_rule_is_refused(self, breakage, complaint) -> None:
        model = Kit.model()
        breakage(model)
        problems = IntentWeights.problems(model)
        assert any(complaint in p for p in problems), problems

    def test_every_admitted_fact_is_content_and_nothing_else_is(self) -> None:
        assert IntentFacts.provenance("t:install:egress") == IntentFacts.CONTENT
        assert IntentFacts.provenance("reg_age_days") == "external"
        assert IntentFacts.provenance("SUSPECT.X.001") == "external"


class TestTheEngine:
    """Steps 0 and 6: after the rules, adds a high finding listing its facts, lowers nothing."""

    def package(self, tmp_path) -> Path:
        return Npm.build(
            tmp_path,
            "demo-css-helper",
            {
                "version": "1.0.0",
                "description": "tiny css color helper",
                "scripts": {"postinstall": "node s.js"},
            },
            {
                "s.js": f"const m = {TestConcealmentAndGates.LOAD}('ht' + 'tps');\n"
                "require('https').get('https://example.invalid/p');\n"
            },
        )

    def test_unexplained_effects_add_a_high_finding_listing_each_fact(self, tmp_path) -> None:
        result = Kit.scan(self.package(tmp_path), Kit.model())
        found = [f for f in result.findings if f.rule_id == RULE]
        assert len(found) == 1
        finding = found[0]
        assert finding.severity is Severity.HIGH
        assert finding.category is Category.SUSPICIOUS
        assert "t:install:egress (effect" in finding.message
        assert "conceal:loader (structural" in finding.message
        assert result.verdict["intent"]["decision"] == "block"

    def test_it_never_lowers_or_removes_a_finding_the_rules_made(self, tmp_path) -> None:
        pkg = self.package(tmp_path)
        without = Kit.scan(pkg, None)
        with_layer = Kit.scan(pkg, Kit.model())
        before = {(f.rule_id, f.severity, f.category, f.location.path) for f in without.findings}
        after = {(f.rule_id, f.severity, f.category, f.location.path) for f in with_layer.findings}
        assert before <= after
        assert {r for r, *_ in after - before} == {RULE}

    def test_without_weights_the_facts_are_reported_and_nothing_decided(self, tmp_path) -> None:
        result = Kit.scan(self.package(tmp_path), None)
        assert "t:install:egress" in result.verdict["intent"]["facts"]
        assert "decision" not in result.verdict["intent"]
        assert RULE not in {f.rule_id for f in result.findings}

    def test_weights_measured_on_another_ecosystem_decide_nothing_here(self, tmp_path) -> None:
        result = Kit.scan(self.package(tmp_path), {**Kit.model(), "scope": ["pypi"]})
        assert RULE not in {f.rule_id for f in result.findings}

    def test_a_running_file_too_large_to_read_is_unknown_with_its_cause(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-big",
            {"version": "1.0.0", "main": "index.js"},
            {"index.js": "var a = 1;\n" * 160_000},
        )
        result = Kit.scan(pkg, Kit.model())
        assert result.verdict["intent"]["decision"] == "unknown"
        assert result.verdict["intent"]["unexamined"][0].startswith("package/index.js:")
        assert RULE not in {f.rule_id for f in result.findings}

    def test_the_verdict_never_takes_the_intent_finding_as_evidence(self) -> None:
        assert not VerdictFeatures.is_code(RULE)


class TestEntries:
    def test_commands_are_apart_from_what_require_loads(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-entries",
            {"version": "1.0.0", "main": "lib/index.js", "bin": "cli.js"},
            {
                "lib/index.js": "const dns = require('dns'); dns.lookup('example.invalid', () => {});\n",
                "cli.js": "const dns = require('dns'); dns.lookup('example.invalid', () => {});\n",
            },
        )
        facts = Kit.facts(pkg)
        assert {"t:import:egress", "t:bin:egress"} <= facts
        assert IntentObserver.MAX_FILES >= 50
