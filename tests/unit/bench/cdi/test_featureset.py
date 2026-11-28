"""A recorded scan row becomes a `FeatureSet` by one versioned function that reuses what the scan already made, and calls no detector of its own.

The function reads the row's findings and its package facts; whether a finding is intel or content is `VerdictFeatures.is_intel`, the facts are `VerdictFeatures.package`'s, and the content digest is a
key over the content features alone. The test lists what the module calls out of the scanner and shows it is that and nothing else: no detector, no analyser, no scan.
"""

from __future__ import annotations

import ast
import json
import sys
from typing import Any, ClassVar

import pytest

from support import ROOT

sys.path.insert(0, str(ROOT))

from bench.cdi import featureset
from bench.cdi.featureset import (
    EXTRACTOR,
    EXTRACTOR_VERSION,
    PLACE_SLOT,
    SLOTS,
    AiFeatures,
    FeatureFamilies,
    FeatureSetBuilder,
)

ROW: dict[str, Any] = {
    "sha256": "ab" * 32,
    "findings": [
        ["MALWARE.EXFIL.001", "high", "high", "malicious", "pkg/index.js", 3, "capability"],
        [
            "SUSPECT.INSTALL.SCRIPT.001",
            "medium",
            "medium",
            "suspicious",
            "package.json",
            1,
            "install_scripts",
        ],
    ],
    "verdict": {"package": {"hook": 1.0, "n_deps": 2.0, "can_egress": 1.0}},
}


class Fx:
    @staticmethod
    def build(
        row: dict[str, Any] = ROW, ai_features: list[dict[str, Any]] | None = None, **versions: str
    ) -> dict[str, Any]:
        return FeatureSetBuilder.build_featureset(
            row,
            artifact_id="art:fx@1.0",
            ecosystem="npm",
            versions=versions or None,
            ai_features=ai_features or (),
        )


class TestARecordedRowBecomesAFeatureSet:
    def test_the_findings_and_the_package_facts_are_its_features(self) -> None:
        record = Fx.build()
        names = {f["name"] for f in record["features"]}
        assert {
            "finding:MALWARE.EXFIL.001",
            "finding:SUSPECT.INSTALL.SCRIPT.001",
            "pkg:hook",
            "pkg:n_deps",
            "pkg:can_egress",
        } <= names
        assert record["ecosystem"] == "npm" and record["artifact_id"] == "art:fx@1.0"

    def test_the_slot_of_a_file_no_place_names_is_none_and_a_manifest_is_packaging(self) -> None:
        slots = {f["name"]: f["slot"] for f in Fx.build()["features"]}
        assert (
            slots["finding:MALWARE.EXFIL.001"] == "none"
            and slots["finding:SUSPECT.INSTALL.SCRIPT.001"] == "packaging"
        )

    def test_the_same_row_gives_the_same_bytes(self) -> None:
        assert json.dumps(Fx.build(), sort_keys=True) == json.dumps(Fx.build(), sort_keys=True)

    def test_the_content_digest_does_not_move_with_the_versions_or_an_intel_finding(self) -> None:
        intel = {
            **ROW,
            "findings": [
                *ROW["findings"],
                ["INTEL.KNOWN_MALWARE.001", "high", "high", "malicious", "", 0, "intel"],
            ],
        }
        assert (
            Fx.build(scanner="a")["featureset_digest"]
            == Fx.build(scanner="b")["featureset_digest"]
            == Fx.build(intel)["featureset_digest"]
        )

    def test_another_content_is_another_digest(self) -> None:
        other = {**ROW, "verdict": {"package": {"hook": 0.0, "n_deps": 2.0, "can_egress": 1.0}}}
        assert Fx.build()["featureset_digest"] != Fx.build(other)["featureset_digest"]


class TestTheFunctionIsVersioned:
    def test_the_record_names_the_extractor_and_its_version(self) -> None:
        assert Fx.build()["extractors"][EXTRACTOR] == EXTRACTOR_VERSION

    def test_a_new_version_is_in_every_feature_and_the_record(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(featureset, "EXTRACTOR_VERSION", "9.9.9")
        record = Fx.build()
        assert record["extractors"][EXTRACTOR] == "9.9.9" and {
            f["extractor_version"] for f in record["features"]
        } == {"9.9.9"}


class TestNoDetectorIsDuplicated:
    PATH = ROOT / "bench" / "cdi" / "featureset.py"
    CALLED = ("VerdictFeatures.COSMETIC", "VerdictFeatures.is_intel")
    """What the module takes from the scanner, by name: nothing else."""

    @classmethod
    def used_from_the_scanner(cls) -> list[str]:
        used = set()
        for node in ast.walk(ast.parse(cls.PATH.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "VerdictFeatures"
            ):
                used.add(f"VerdictFeatures.{node.attr}")
        return sorted(used)

    def test_it_lists_what_it_calls_out_of_the_scanner(self) -> None:
        assert self.used_from_the_scanner() == list(self.CALLED)

    def test_it_imports_nothing_of_the_scanner_but_the_verdict_features(self) -> None:
        tree = ast.parse(self.PATH.read_text(encoding="utf-8"))
        modules = [
            n.module
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("cordon_scanner")
        ]
        modules += [
            a.name
            for n in ast.walk(tree)
            if isinstance(n, ast.Import)
            for a in n.names
            if a.name.startswith("cordon_scanner")
        ]
        assert modules == ["cordon_scanner.decide.verdict"]

    def test_no_detector_analyser_engine_or_scan_is_imported(self) -> None:
        text = self.PATH.read_text(encoding="utf-8")
        for banned in (
            "cordon_scanner.detect",
            "cordon_scanner.analysis",
            "cordon_scanner.engine",
            "Scanner(",
        ):
            assert banned not in text

    def test_building_runs_no_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cordon_scanner

        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("a scan was run")

        monkeypatch.setattr(cordon_scanner.Scanner, "scan", refuse)
        assert Fx.build()["features"]


class TestEveryFeatureCarriesItsProvenance:
    """Each feature names where it came from (content or intel), the slot it sits in, its location, confidence, evidence, extractor and version."""

    FIELDS: ClassVar[tuple[str, ...]] = (
        "name",
        "value",
        "source",
        "slot",
        "location",
        "confidence",
        "evidence",
        "extractor",
        "extractor_version",
    )
    SOURCES: ClassVar[set[str]] = {"content", "intel"}

    def test_every_feature_has_every_field(self) -> None:
        intel = {
            **ROW,
            "findings": [
                *ROW["findings"],
                ["MALWARE.KNOWN.001", "high", "high", "malicious", "", 0, "intel"],
            ],
        }
        for feature in Fx.build(intel)["features"]:
            assert all(field in feature for field in self.FIELDS), feature["name"]
            assert feature["source"] in self.SOURCES

    def test_a_known_package_finding_is_intel_and_the_rest_content(self) -> None:
        intel = {
            **ROW,
            "findings": [
                *ROW["findings"],
                ["MALWARE.KNOWN.001", "high", "high", "malicious", "", 0, "intel"],
            ],
        }
        sources = {f["name"]: f["source"] for f in Fx.build(intel)["features"]}
        assert (
            sources["finding:MALWARE.KNOWN.001"] == "intel"
            and sources["finding:MALWARE.EXFIL.001"] == "content"
        )

    def test_the_slots_in_use_are_named(self) -> None:
        slots = {f["slot"] for f in Fx.build()["features"]}
        assert slots <= set(SLOTS)


class TestAModelOnContentFeaturesScoresTheSameWithoutIntel:
    """The features a model is trained on and scores are made from content findings only, so removing the intel feed's findings changes no feature and no score."""

    CONTENT: ClassVar[list[tuple[str, int, int, str, str]]] = [
        ("MALWARE.EXFIL.001", 4, 3, "malicious", "pkg/index.js"),
        ("SUSPECT.INSTALL.SCRIPT.001", 2, 2, "suspicious", "package.json"),
    ]
    INTEL: ClassVar[list[tuple[str, int, int, str, str]]] = [
        ("MALWARE.KNOWN.001", 4, 3, "malicious", ""),
        ("SUSPECT.CAMPAIGN.SIBLING.001", 3, 3, "suspicious", ""),
    ]
    PACKAGE: ClassVar[dict[str, float]] = {"hook": 1.0, "n_deps": 2.0}

    def test_the_features_are_the_same_with_and_without_the_intel_findings(self) -> None:
        from cordon_scanner.decide.verdict_features import VerdictFeatures

        with_intel = VerdictFeatures.evidence([*self.CONTENT, *self.INTEL], dict(self.PACKAGE))
        without = VerdictFeatures.evidence(self.CONTENT, dict(self.PACKAGE))
        assert with_intel == without

    def test_the_shipped_model_scores_them_the_same(self) -> None:
        from cordon_scanner.decide.verdict import MODEL_PATH, VerdictModel
        from cordon_scanner.decide.verdict_features import VerdictFeatures

        model = VerdictModel.load(MODEL_PATH)
        assert model is not None
        scores = [
            VerdictModel.score(
                model,
                VerdictModel.inputs(model, VerdictFeatures.evidence(findings, dict(self.PACKAGE))),
            )
            for findings in ([*self.CONTENT, *self.INTEL], self.CONTENT)
        ]
        assert scores[0] == scores[1]


class TestTheSlotIsTheRowsVocabulary:
    """A feature's slot is one of install, build, import, when_called, opaque, packaging, agent_text and none, read from the places the scan row names."""

    EXPECTED = (
        "install",
        "build",
        "import",
        "when_called",
        "opaque",
        "packaging",
        "agent_text",
        "none",
    )

    def row(self, places: dict[str, list[str]] | None, *paths: str) -> dict[str, Any]:
        findings = [
            [f"MALWARE.X.00{n}", "high", "high", "malicious", path, 1, "capability"]
            for n, path in enumerate(paths)
        ]
        return {**ROW, "findings": findings, "places": places or {}}

    def slots(self, places: dict[str, list[str]] | None, *paths: str) -> dict[str, str]:
        return {
            f["location"]["path"]: f["slot"]
            for f in Fx.build(self.row(places, *paths))["features"]
            if f["name"].startswith("finding:")
        }

    def test_the_vocabulary_is_the_rows(self) -> None:
        assert SLOTS == self.EXPECTED

    def test_every_place_the_scan_names_has_a_slot_in_it(self) -> None:
        from cordon_scanner.rules.fact_terms import FactTerms

        assert set(PLACE_SLOT) >= FactTerms.PLACES - {"skill_named"} | {"skill_named"} and set(
            PLACE_SLOT.values()
        ) <= set(SLOTS)

    def test_a_file_in_each_place_gets_its_slot(self) -> None:
        places = {
            "install_hook": ["a.js"],
            "ci_hook": ["b.js"],
            "import_entry": ["c.js"],
            "agent_tool": ["d.js"],
        }
        assert self.slots(places, "a.js", "b.js", "c.js", "d.js") == {
            "a.js": "install",
            "b.js": "build",
            "c.js": "import",
            "d.js": "when_called",
        }

    def test_a_file_in_two_places_takes_the_earlier_slot(self) -> None:
        assert self.slots({"import_entry": ["a.js"], "install_hook": ["a.js"]}, "a.js") == {
            "a.js": "install"
        }

    def test_a_compiled_or_minified_file_is_opaque_even_in_a_place(self) -> None:
        assert self.slots({"install_hook": ["a.node", "b.min.js"]}, "a.node", "b.min.js") == {
            "a.node": "opaque",
            "b.min.js": "opaque",
        }

    def test_manifests_and_agent_text_keep_theirs_and_an_unplaced_file_is_none(self) -> None:
        assert self.slots({}, "package.json", "SKILL.md", "lib/x.js") == {
            "package.json": "packaging",
            "SKILL.md": "agent_text",
            "lib/x.js": "none",
        }

    def test_a_path_inside_an_archive_is_placed_by_its_member_name(self) -> None:
        assert self.slots({"install_hook": ["pkg/a.js"]}, "x.tgz!pkg/a.js") == {
            "x.tgz!pkg/a.js": "install"
        }

    def test_the_function_is_a_new_version_because_the_slots_changed(self) -> None:
        assert EXTRACTOR_VERSION == "1.1.0"


class TestEveryListedFeatureFamilyIsPresentOrARecordedGap:
    """SI-B1: the families the representation lists are each backed by shipped rules, carried by the slot, or a recorded gap."""

    LISTED: ClassVar[tuple[str, ...]] = (
        "metadata", "hooks", "entry_points", "call_graphs", "sources_sinks", "dynamic_loading", "obfuscation",
        "download_execute", "persistence", "crypto_serialisation", "similarity", "provenance_inconsistencies",
        "agent_mcp_permissions", "language_binary",
    )  # fmt: skip

    def test_the_listed_families_are_exactly_the_registry(self) -> None:
        assert set(FeatureFamilies.FAMILIES) == set(self.LISTED)

    def test_each_family_has_rules_or_says_why_it_has_none(self) -> None:
        for family, (prefixes, why) in FeatureFamilies.FAMILIES.items():
            assert prefixes or why, family

    def test_a_family_with_a_gap_names_it_as_a_gap(self) -> None:
        assert set(FeatureFamilies.gaps()) == {"call_graphs", "crypto_serialisation"}

    def test_every_prefix_names_a_rule_the_scanner_ships(self) -> None:
        """Declared by a detector, or emitted by one (a rule written in its source as `"<prefix>.`)."""
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.engine.registry import Registry

        shipped = {
            d.id
            for d in RuleCatalogue.from_detectors(Registry(allow_third_party=False).detectors())
        }
        source = "\n".join(
            p.read_text(encoding="utf-8") for p in (ROOT / "src" / "cordon_scanner").rglob("*.py")
        )
        for family, (prefixes, _) in FeatureFamilies.FAMILIES.items():
            for prefix in prefixes:
                declared = any(rule.startswith(prefix + ".") for rule in shipped)
                assert declared or f'"{prefix}.' in source, (family, prefix)

    def test_a_finding_of_each_ruled_family_lands_in_that_family(self) -> None:
        for family, (prefixes, _) in FeatureFamilies.FAMILIES.items():
            for prefix in prefixes:
                feature = {"name": f"finding:{prefix}.001", "slot": "none"}
                assert family in FeatureFamilies.of(feature), (family, prefix)

    def test_a_prefix_matches_whole_segments_only(self) -> None:
        assert (
            FeatureFamilies.of({"name": "finding:SUSPECT.INSTALLER.001", "slot": "none"}) == set()
        )

    def test_the_slot_a_package_runs_from_is_the_entry_point_family(self) -> None:
        assert "entry_points" in FeatureFamilies.of({"name": "finding:X.Y.001", "slot": "install"})
        assert "entry_points" not in FeatureFamilies.of(
            {"name": "finding:X.Y.001", "slot": "opaque"}
        )

    def test_package_facts_are_metadata_and_the_hook_fact_is_a_hook(self) -> None:
        assert FeatureFamilies.of({"name": "pkg:n_deps", "slot": "packaging"}) == {"metadata"}
        assert FeatureFamilies.of({"name": "pkg:hook", "slot": "packaging"}) == {"hooks"}


class TestAnAiFeatureCarriesItsModel:
    """SI-B2: two runs over the same bytes give the same FeatureSet hash, and an AI feature records the model version, template, inputs,
    schema and confidence."""

    INPUTS: ClassVar[tuple[str, ...]] = ("sha256:" + "a" * 64, "sha256:" + "b" * 64)

    @classmethod
    def ai(cls, **changes: Any) -> dict[str, Any]:
        given: dict[str, Any] = {
            "model_version": "judge-1",
            "template": "t-3",
            "inputs": cls.INPUTS,
            "schema": "verdict/1",
            "confidence": 0.8,
        }
        return AiFeatures.record("intent", "exfil", **{**given, **changes})

    def test_the_record_carries_the_five_fields_and_the_common_ones(self) -> None:
        feature = self.ai()
        assert AiFeatures.complete(feature)
        assert (
            feature["ai"]
            == {
                "model_version": "judge-1",
                "template": "t-3",
                "inputs": list(self.INPUTS),
                "schema": "verdict/1",
            }
            and feature["confidence"] == 0.8
        )
        assert feature["source"] == "ai" and feature["location"] == {"path": None, "line": None}
        assert feature["extractor_version"] == EXTRACTOR_VERSION and feature["evidence"]

    @pytest.mark.parametrize("field", ["model_version", "template", "schema"])
    def test_a_missing_text_field_is_refused(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            self.ai(**{field: ""})

    @pytest.mark.parametrize(
        "inputs", [(), ("not-a-digest",), ("sha256:" + "a" * 64, "text of a file")]
    )
    def test_inputs_are_digests_and_never_empty(self, inputs: tuple[str, ...]) -> None:
        with pytest.raises(ValueError, match="inputs"):
            self.ai(inputs=inputs)

    @pytest.mark.parametrize("confidence", [-0.1, 1.1, True, "high", None])
    def test_a_confidence_outside_zero_to_one_is_refused(self, confidence: Any) -> None:
        with pytest.raises(ValueError, match="confidence"):
            self.ai(confidence=confidence)

    def test_a_feature_missing_a_field_is_refused_by_the_builder(self) -> None:
        broken = self.ai()
        del broken["ai"]["template"]
        with pytest.raises(ValueError, match="template"):
            Fx.build(ai_features=[broken])

    def test_two_runs_over_the_same_bytes_give_the_same_featureset_hash_and_bytes(self) -> None:
        first = Fx.build(ai_features=[self.ai()])
        again = Fx.build(ai_features=[self.ai()])
        assert first["featureset_digest"] == again["featureset_digest"]
        assert json.dumps(first, sort_keys=True) == json.dumps(again, sort_keys=True)
        assert any(f["source"] == "ai" for f in first["features"])

    def test_a_new_model_version_does_not_move_the_content_hash_but_is_in_the_record(self) -> None:
        old = Fx.build(ai_features=[self.ai()])
        new = Fx.build(ai_features=[self.ai(model_version="judge-2")])
        assert old["featureset_digest"] == new["featureset_digest"]
        assert old["features"] != new["features"]
