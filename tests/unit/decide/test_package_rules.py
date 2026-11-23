"""Package-scope composite rules (learning loop LL-3): a conjunction of facts about the whole package, written in the
terms the learning loop learns in, evaluated on a real scan. The packages below are ordinary code built in a temporary
folder: a helper that runs `git status` and checks a status page, shipped where nothing the package runs reaches it."""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import RulePackError
from cordon_scanner.foundation.models import Confidence
from cordon_scanner.report.facts import ScanFacts
from cordon_scanner.rules.fact_terms import FactTerms
from cordon_scanner.rules.loader import RuleLoader

HELPER = """const { spawn } = require('child_process');
const https = require('https');

function refresh() {
  const child = spawn('git', ['status']);
  https.get('https://example.com/status', () => {});
  return child;
}

module.exports = { refresh };
"""

RULE = """
pack: {id: test.learned, version: 1.0.0, license: Apache-2.0}
rules:
  - id: LEARNED.TEST.001
    category: suspicious
    severity: high
    confidence: medium
    title: Shipped code nothing starts spawns and reaches the network
    message: A file nothing in the package runs both starts a process and reaches the network.
    remediation: Remove the file, or start it from the package's own entry point.
    match:
      kind: composite
      scope: package
      all:
        - file: {where: unreached, capabilities: [spawn, egress]}
"""


class PackageKit:
    @staticmethod
    def tarball(tmp_path: Path, *, index: str) -> Path:
        files = {
            "package/package.json": json.dumps(
                {"name": "facts-demo", "version": "1.0.0", "main": "index.js"}
            ),
            "package/index.js": index,
            "package/lib/helper.js": HELPER,
        }
        path = tmp_path / "facts-demo-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def scan(tmp_path: Path, *, index: str, rule: str = RULE):
        pack = tmp_path / "learned.yaml"
        pack.write_text(rule, encoding="utf-8")
        config = replace(Config.default(), extra_rule_paths=(str(pack),))
        return Scanner(config).scan(PackageKit.tarball(tmp_path, index=index))


class TestARuleOverTheWholePackage:
    def test_it_fires_on_the_file_nothing_reaches(self, tmp_path) -> None:
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        learned = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        assert len(learned) == 1
        assert learned[0].location.path.endswith("lib/helper.js")
        assert learned[0].detector == "package_rules"

    def test_it_does_not_fire_when_the_entry_point_loads_the_file(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path, index="const helper = require('./lib/helper');\nmodule.exports = helper;\n"
        )
        assert not [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]

    def test_the_facts_export_and_the_rule_read_the_same_terms(self, tmp_path) -> None:
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        record = ScanFacts.of(result)
        assert ("file", "unreached", "egress", "spawn") in FactTerms.of_facts(record)
        assert record["package"]["unreached_capability_files"] >= 1


RULE_BY_REACH = RULE.replace("LEARNED.TEST.001", "LEARNED.TEST.002").replace(
    "where: unreached", "where: reach:unreached"
)
RULE_BY_STRING = RULE.replace("LEARNED.TEST.001", "LEARNED.TEST.003").replace(
    "where: unreached", "where: reach:path_string"
)


class TestARuleByHowAFileIsReached:
    """`reach:KIND` in a learned rule is read from the scanner's own reach (`decide/reach.py`)."""

    def test_a_rule_on_the_orphan_fires(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path, index="module.exports = (a, b) => a + b;\n", rule=RULE_BY_REACH
        )
        assert [
            f.location.path.endswith("lib/helper.js")
            for f in result.findings
            if f.rule_id == "LEARNED.TEST.002"
        ] == [True]

    def test_a_rule_on_a_path_string_fires_only_when_a_string_names_the_file(
        self, tmp_path
    ) -> None:
        named = "module.exports = ['lib/helper.js'];\n"
        fired = PackageKit.scan(tmp_path, index=named, rule=RULE_BY_STRING)
        assert [f for f in fired.findings if f.rule_id == "LEARNED.TEST.003"]
        (tmp_path / "again").mkdir()
        orphan = PackageKit.scan(
            tmp_path / "again", index="module.exports = 1;\n", rule=RULE_BY_STRING
        )
        assert not [f for f in orphan.findings if f.rule_id == "LEARNED.TEST.003"]


class TestARuleThatCouldNeverFireIsRefusedAtLoad:
    def test_repository_scope_is_refused_with_its_reason(self, tmp_path) -> None:
        pack = tmp_path / "repo.yaml"
        pack.write_text(RULE.replace("scope: package", "scope: repository"), encoding="utf-8")
        with pytest.raises(RulePackError, match="declared but not implemented"):
            RuleLoader().load_file(pack)

    def test_a_package_term_the_evaluator_does_not_read_is_refused(self, tmp_path) -> None:
        pack = tmp_path / "bad.yaml"
        pack.write_text(RULE.replace("where: unreached", "where: somewhere"), encoding="utf-8")
        with pytest.raises(RulePackError, match="unknown where"):
            RuleLoader().load_file(pack)


class TestTheFactsCarryDestinationsAsDigests:
    def test_the_file_that_reaches_the_network_names_its_host_as_a_digest_only(
        self, tmp_path
    ) -> None:
        import json as _json

        from cordon_scanner.detect.code.capability.memo import DestinationHosts

        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        record = ScanFacts.of(result)
        helper = next(
            f
            for f in record["files"]
            if f["key"] == ScanFacts.file_key(next(p for p in (result.destinations or {})))
        )
        assert helper["hosts"] == [DestinationHosts.digest("example.com")]
        assert helper["domains"] == [DestinationHosts.digest("example.com")]
        assert record["package"]["hosts_distinct"] == 1
        assert "example.com" not in _json.dumps(record)


class TestARederivedRuleIsNotCoveredByTheOldSuppression:
    """A learned finding's fingerprint holds the digest of the predicate that made it, so a suppression written against one predicate never covers a finding of the same id made by another.

    A re-derived rule can keep its id and change what it matches on. A suppression is matched by fingerprint; the fingerprint is made from the rule id, the file and the match hash, and the match
    hash of a learned finding includes the predicate digest."""

    SAME_ID_NEW_PREDICATE = RULE.replace("where: unreached", "where: reach:unreached")

    @staticmethod
    def fingerprints(root, rule: str) -> set[str]:
        root.mkdir(parents=True, exist_ok=True)
        result = PackageKit.scan(root, index="module.exports = (a, b) => a + b;\n", rule=rule)
        return {f.fingerprint for f in result.findings if f.rule_id.startswith("LEARNED.")}

    def test_the_same_predicate_gives_the_same_fingerprint(self, tmp_path) -> None:
        first, second = (
            self.fingerprints(tmp_path / "a", RULE),
            self.fingerprints(tmp_path / "b", RULE),
        )
        assert first and first == second

    def test_the_same_id_with_a_new_predicate_gives_another_fingerprint(self, tmp_path) -> None:
        old = self.fingerprints(tmp_path / "a", RULE)
        new = self.fingerprints(tmp_path / "b", self.SAME_ID_NEW_PREDICATE)
        assert old and new and not old & new


LEARNED_BLOCK = """    learned:
      families: 4
      legit_rate: 0.0004
      interval: [0.0, 0.0009]
      batch: batch-one
"""


class TestAFindingShowsWhereItsRuleCameFrom:
    """A learned finding's explanation carries the four things the rule was learned from: how many families, how often legitimate packages fire it with the interval that rate lies in, the batch, and the facts
    the package satisfied."""

    @staticmethod
    def rule_with(block: str) -> str:
        return RULE.replace("    match:\n", f"{block}    match:\n")

    def test_the_four_fields_are_in_the_explanation(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path,
            index="module.exports = (a, b) => a + b;\n",
            rule=self.rule_with(LEARNED_BLOCK),
        )
        (finding,) = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        basis = finding.explanation.basis
        assert "families=4" in basis and "legit_rate=0.0004" in basis
        assert "interval=0.0000-0.0009" in basis and "batch=batch-one" in basis
        assert any(
            code.startswith("facts=") and "egress" in code and "spawn" in code for code in basis
        )

    def test_a_rule_without_the_block_shows_none_of_them(self, tmp_path) -> None:
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        (finding,) = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        assert finding.explanation.basis == ()

    @pytest.mark.parametrize(
        "block",
        [
            "    learned: {families: 0, legit_rate: 0.1, interval: [0.0, 0.2], batch: b}\n",
            "    learned: {families: 3, legit_rate: 1.5, interval: [0.0, 2.0], batch: b}\n",
            "    learned: {families: 3, legit_rate: 0.1, interval: [0.2, 0.3], batch: b}\n",
            "    learned: {families: 3, legit_rate: 0.1, interval: [0.0], batch: b}\n",
            "    learned: {families: 3, legit_rate: 0.1, interval: [0.0, 0.2], batch: 'a b'}\n",
            "    learned: {families: 3, legit_rate: 0.1, interval: [0.0, 0.2]}\n",
            "    learned: {families: 3, legit_rate: 0.1, interval: [0.0, 0.2], batch: b, extra: 1}\n",
            "    learned: yes\n",
        ],
    )
    def test_a_block_that_is_not_of_that_form_is_refused_at_load(
        self, tmp_path, block: str
    ) -> None:
        pack = tmp_path / "bad.yaml"
        pack.write_text(self.rule_with(block), encoding="utf-8")
        with pytest.raises(RulePackError, match="learned"):
            RuleLoader().load_file(pack)


class TestAMeasuredRateSetsTheConfidence:
    """A learned finding's confidence is what its measured rate earns (1 minus the interval's upper bound), and the policy's
    minimum-confidence floor holds or enforces it like any other finding."""

    @staticmethod
    def block(upper: float, *, n: int | None = 2000) -> str:
        count = f", n: {n}" if n is not None else ""
        return (
            "    learned: {families: 4, legit_rate: 0.0, interval: [0.0, "
            f"{upper}], batch: b{count}}}\n"
        )

    def finding(self, tmp_path, upper: float):
        rule = RULE.replace("    match:\n", f"{self.block(upper)}    match:\n")
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n", rule=rule)
        (found,) = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        return found

    def test_two_measured_rates_give_two_confidences(self, tmp_path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        tight = self.finding(tmp_path / "a", 0.002)
        loose = self.finding(tmp_path / "b", 0.2)
        assert tight.confidence > loose.confidence
        assert (str(tight.confidence), str(loose.confidence)) == ("high", "low")

    def test_the_declared_confidence_of_a_rule_with_no_block_is_kept(self, tmp_path) -> None:
        result = PackageKit.scan(tmp_path, index="module.exports = (a, b) => a + b;\n")
        (found,) = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        assert str(found.confidence) == "medium"

    def test_a_floor_above_the_confidence_holds_the_finding_at_warn(self, tmp_path) -> None:
        from cordon_scanner.decide.policy import PolicyGate

        found = self.finding(tmp_path, 0.2)
        policy = Config.default().policy
        assert (
            PolicyGate._fails(found, replace(policy, min_confidence_to_fail=Confidence.HIGH))
            is False
        )
        assert (
            PolicyGate._fails(found, replace(policy, min_confidence_to_fail=Confidence.LOW)) is True
        )

    def test_the_basis_names_the_number_of_legitimate_units(self, tmp_path) -> None:
        assert "n=2000" in self.finding(tmp_path, 0.002).explanation.basis

    @pytest.mark.parametrize("n", [0, -3, 1.5, "many", True])
    def test_a_count_that_is_not_a_positive_integer_is_refused_at_load(self, tmp_path, n) -> None:
        pack = tmp_path / "bad.yaml"
        pack.write_text(
            RULE.replace(
                "    match:\n",
                self.block(0.01, n=None).replace("b}", f"b, n: {n!r}" + "}") + "    match:\n",
            ),
            encoding="utf-8",
        )
        with pytest.raises(RulePackError, match="learned"):
            RuleLoader().load_file(pack)


class TestARenderedPackCarriesN:
    def test_the_block_holds_the_rate_its_interval_and_the_units_it_was_measured_on(self) -> None:
        from bench.cdi.distill import PackRenderer

        candidate = {
            "predicate": [["file", "unreached", "egress"]],
            "predicate_digest": "ab" * 32,
            "train": {"families": 4, "legit_upper": 0.004, "legit_units": 1500, "legit_hits": 3},
            "confirm": {"families": 3, "legit_upper": 0.005},
        }
        text = PackRenderer.render(candidate, "LEARNED.TEST.001")
        assert (
            "      n: 1500\n" in text
            and "      legit_rate: 0.002000\n" in text
            and "      families: 4\n" in text
        )


class TestADistilledPredicateRendersToAPackThatFiresOnItsFixtureOnly:
    """A distilled candidate, rendered as a pack, is loaded by the scanner, fires on the package shaped like the fixture and not on its control (the entry point loads the file)."""

    CANDIDATE: ClassVar[dict[str, Any]] = {
        "predicate": [["file", "unreached", "egress", "spawn"]],
        "predicate_digest": "cd" * 32,
        "train": {"families": 4, "legit_upper": 0.004, "legit_units": 1500, "legit_hits": 3},
        "confirm": {"families": 3, "legit_upper": 0.005},
    }

    def rendered(self) -> str:
        from bench.cdi.distill import PackRenderer

        return PackRenderer.render(self.CANDIDATE, "LEARNED.TEST.001")

    def test_it_fires_on_the_fixture(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path, index="module.exports = (a, b) => a + b;\n", rule=self.rendered()
        )
        assert [f.rule_id for f in result.findings if f.rule_id.startswith("LEARNED.")] == [
            "LEARNED.TEST.001"
        ]

    def test_it_does_not_fire_on_the_control(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path,
            index="const helper = require('./lib/helper');\nmodule.exports = helper;\n",
            rule=self.rendered(),
        )
        assert not [f for f in result.findings if f.rule_id.startswith("LEARNED.")]

    def test_the_finding_shows_the_measured_basis_the_pack_carried(self, tmp_path) -> None:
        result = PackageKit.scan(
            tmp_path, index="module.exports = (a, b) => a + b;\n", rule=self.rendered()
        )
        (found,) = [f for f in result.findings if f.rule_id == "LEARNED.TEST.001"]
        assert "families=4" in found.explanation.basis and "n=1500" in found.explanation.basis
        assert found.assurance == "suspected, machine-made"


class TestThePreTestAndTheScannerReadTheSameFacts:
    """The distiller's reading of a facts record and the scanner's give the same terms for every shape of a fixture list, so the pre-test's fire set is the scanner's."""

    def test_the_two_readings_agree_on_every_fixture(self) -> None:
        from bench.cdi.distill import Terms

        records = [
            ScanFacts.of(PackageKit.scan(Path(tmp), index=index)) for tmp, index in self.fixtures()
        ]
        assert records
        for record in records:
            assert Terms.of(record) == FactTerms.of_facts(record)

    @staticmethod
    def fixtures():
        import tempfile

        for index in (
            "module.exports = (a, b) => a + b;\n",
            "const helper = require('./lib/helper');\nmodule.exports = helper;\n",
        ):
            yield tempfile.mkdtemp(), index
