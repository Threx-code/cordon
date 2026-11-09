"""The claim a blocked finding makes: malware, risky behaviour, or policy.

Design: `reviews/pypi-98/16-HAZARD-LABEL.md`. The claim is report-only. These tests hold the three
properties that make it safe to ship beside an unchanged gate:

* every rule the tool can emit resolves through the table, so no finding is unclaimed by accident;
* nothing that decides a block imports the claims module;
* a detector can add signals to a finding but never remove the table's.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.engine.registry import Registry
from cordon_scanner.foundation.models import Category, Evidence, EvidenceKind, RedactionMode
from cordon_scanner.foundation.results import ScanResult, ScanStats
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.claims import (
    _NO_SIGNAL_PREFIXES,
    _POLICY_PREFIXES,
    _SIGNALS_BY_PREFIX,
    _UNCLAIMED_PREFIXES,
    MALWARE_SIGNALS,
    SIGNALS_KEY,
    Claim,
    Claims,
    Signal,
)
from cordon_scanner.report.json_ import JsonReporter
from cordon_scanner.rules.loader import RuleLoader
from support import ROOT, Support


class ClaimHelpers:
    """Helpers for test_claims.py."""

    @staticmethod
    def declared_rule_ids() -> list[str]:
        """Every rule the tool can emit, from detectors and rule packs (as `test_taxonomy`)."""
        ids = {rule.id for rule in RuleCatalogue.from_detectors(Registry().detectors())}
        ids |= {rule.id for pack in RuleLoader.load_builtin() for rule in pack.rules}
        return sorted(i for i in ids if not i.startswith(_UNCLAIMED_PREFIXES))

    @staticmethod
    def finding(rule_id: str, *, signals: str | None = None, category: Category | None = None):
        """A finding of one rule, with detector-added signals when given."""
        metadata = ((SIGNALS_KEY, signals),) if signals is not None else ()
        overrides: dict[str, object] = {
            "rule_id": rule_id,
            "evidence": Evidence(
                kind=EvidenceKind.HASH,
                match_hash="0" * 16,
                redaction=RedactionMode.HASH_ONLY,
                metadata=metadata,
            ),
        }
        if category is not None:
            overrides["category"] = category
        return Support.a_finding(**overrides)

    @staticmethod
    def imports_claims(path: Path) -> bool:
        """Whether a module imports `cordon_scanner.foundation.claims` anywhere in its body."""
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "claims" in node.module:
                return True
            if isinstance(node, ast.Import) and any("claims" in a.name for a in node.names):
                return True
        return False

    @staticmethod
    def decision_modules() -> list[Path]:
        """Every module that decides a block: the gate, the verdict and its model, configuration
        and severity floors, and the bench's per-finding block test."""
        src = ROOT / "src" / "cordon_scanner"
        paths = [*sorted((src / "decide").rglob("*.py"))]
        paths += sorted((src / "foundation" / "config").rglob("*.py"))
        paths += [
            src / "foundation" / "scoring.py",
            src / "foundation" / "models.py",
            src / "foundation" / "results.py",
            ROOT / "bench" / "tools" / "content.py",
        ]
        return paths


class TestCompleteness:
    def test_the_catalogue_is_not_empty(self) -> None:
        assert len(ClaimHelpers.declared_rule_ids()) > 100

    @pytest.mark.parametrize("rule_id", ClaimHelpers.declared_rule_ids())
    def test_every_declared_rule_resolves(self, rule_id: str) -> None:
        """A rule is a policy rule, has signals, or is a model-only verdict listed as such; a
        rule that falls through would claim `risky_behaviour` silently."""
        assert (
            Claims.is_policy_rule(rule_id)
            or Claims.table_signals(rule_id)
            or rule_id.startswith(_NO_SIGNAL_PREFIXES)
        ), f"{rule_id} falls through the claims table. Give it signals or a policy prefix."

    def test_no_signal_entry_is_unreachable(self) -> None:
        """An entry below a prefix of itself, or under a policy prefix, is never matched."""
        dead = []
        for i, (prefix, _) in enumerate(_SIGNALS_BY_PREFIX):
            earlier = [p for p, _ in _SIGNALS_BY_PREFIX[:i] if prefix.startswith(p)]
            if earlier or prefix.startswith(_POLICY_PREFIXES):
                dead.append(prefix)
        assert dead == []

    def test_every_signal_is_used(self) -> None:
        used = {s for _, signals in _SIGNALS_BY_PREFIX for s in signals}
        assert used == set(Signal)


class TestDecisionIsolation:
    def test_there_are_decision_modules_to_check(self) -> None:
        assert len(ClaimHelpers.decision_modules()) > 5

    @pytest.mark.parametrize(
        "path", ClaimHelpers.decision_modules(), ids=lambda p: p.relative_to(ROOT).as_posix()
    )
    def test_no_decision_path_reads_the_claim(self, path: Path) -> None:
        assert not ClaimHelpers.imports_claims(path), (
            f"{path.relative_to(ROOT)} imports the claims module. The claim is report-only: a "
            f"block must not depend on it (16-HAZARD-LABEL.md, requirement R2)."
        )


class TestFindingClaim:
    @pytest.mark.parametrize(
        ("rule_id", "claim"),
        [
            ("MALWARE.PACKAGE.KNOWN.001", Claim.MALWARE),
            ("SUSPECT.EXFIL.CREDENTIAL_STORE.001", Claim.MALWARE),
            ("SUSPECT.DESTROY.HOME_OR_ROOT.001", Claim.MALWARE),
            ("MALWARE.DROPPER.001", Claim.RISKY_BEHAVIOUR),
            ("MALWARE.INSTALL.PERSIST.001", Claim.RISKY_BEHAVIOUR),
            ("SUSPECT.ANTI_ANALYSIS.001", Claim.RISKY_BEHAVIOUR),
            ("SUSPECT.VERDICT.MODEL.001", Claim.RISKY_BEHAVIOUR),
            ("SECRET.AWS.001", Claim.POLICY),
            ("VULNERABLE.DEPENDENCY.KNOWN.001", Claim.POLICY),
            ("SUSPECT.PACKAGE.NAME_RISK.001", Claim.POLICY),
            ("SUSPECT.PACKAGE.STARJACKING.001", Claim.MALWARE),
        ],
    )
    def test_a_rule_claims_what_its_evidence_shows(self, rule_id: str, claim: Claim) -> None:
        assert Claims.of_finding(ClaimHelpers.finding(rule_id)) is claim

    def test_the_rule_id_prefix_is_not_the_claim(self) -> None:
        """A MALWARE.* rule that shows behaviour only reads as risky behaviour."""
        assert Claims.of_finding(ClaimHelpers.finding("MALWARE.DROPPER.001")) is not Claim.MALWARE

    def test_a_detector_can_add_a_malware_signal(self) -> None:
        plain = ClaimHelpers.finding("MALWARE.DROPPER.001", signals="drop_point")
        assert Claims.of_finding(plain) is Claim.MALWARE

    def test_a_detector_cannot_remove_the_tables_signal(self) -> None:
        """Metadata only adds: a finding naming only behaviour keeps its table's THEFT."""
        f = ClaimHelpers.finding("SUSPECT.EXFIL.DROP_POINT.001", signals="fetch_run")
        assert Signal.THEFT in Claims.signals_of(f)
        assert Claims.of_finding(f) is Claim.MALWARE

    def test_an_unknown_signal_name_is_ignored(self) -> None:
        f = ClaimHelpers.finding("MALWARE.DROPPER.001", signals="not_a_signal, fetch_run")
        assert Claims.signals_of(f) == frozenset({Signal.FETCH_RUN})

    def test_a_finding_about_the_scan_claims_nothing(self) -> None:
        f = ClaimHelpers.finding("OPERATIONAL.FORMAT.001", category=Category.OPERATIONAL)
        assert Claims.of_finding(f) is None

    def test_the_finding_model_does_not_carry_the_claim(self) -> None:
        """Only reporters add it, so nothing reading a Finding can decide on it."""
        assert "claim" not in ClaimHelpers.finding("SECRET.AWS.001").to_dict()

    def test_malware_signals_are_the_owners_list(self) -> None:
        assert {str(s) for s in MALWARE_SIGNALS} == {
            "conceal",
            "theft",
            "drop_point",
            "known_bad",
            "propagate",
            "destroy",
        }


class TestUnitClaim:
    def test_nothing_blocking_claims_nothing(self) -> None:
        assert Claims.of_unit([]) is None

    def test_malware_wins_over_behaviour(self) -> None:
        unit = [
            ClaimHelpers.finding("MALWARE.INSTALL.PERSIST.001"),
            ClaimHelpers.finding("SUSPECT.OBFUSCATION.ENCODED.001"),
        ]
        assert Claims.of_unit(unit) is Claim.MALWARE

    def test_policy_only_when_every_blocking_finding_is_policy(self) -> None:
        assert Claims.of_unit([ClaimHelpers.finding("SECRET.AWS.001")]) is Claim.POLICY
        mixed = [
            ClaimHelpers.finding("SECRET.AWS.001"),
            ClaimHelpers.finding("SUSPECT.AGENT.SKILL_LISTENER.001"),
        ]
        assert Claims.of_unit(mixed) is Claim.RISKY_BEHAVIOUR

    def test_a_model_verdict_alone_never_claims_malware(self) -> None:
        assert (
            Claims.of_unit([ClaimHelpers.finding("SUSPECT.VERDICT.MODEL.001")])
            is Claim.RISKY_BEHAVIOUR
        )

    def test_the_text_a_person_reads(self) -> None:
        assert [c.text for c in Claim] == ["malware", "risky behaviour", "policy"]


class TestJsonReport:
    @staticmethod
    def _render(blocking: frozenset[str] | None) -> dict[str, object]:
        f = ClaimHelpers.finding("SUSPECT.EXFIL.CREDENTIAL_STORE.001")
        result = ScanResult(
            findings=(f,),
            stats=ScanStats(files_scanned=1, dependencies=0, duration_ms=1),
            complete=True,
            engine_version="0.1.0",
            rulepack_version="1.0.0",
            rulepack_hash="deadbeef",
            config_hash="cafebabe",
        )
        opts = ReportOptions(
            color=False,
            blocking=blocking if blocking is None else frozenset({f.fingerprint}),
        )
        return json.loads(JsonReporter().render_to_string(result, opts))

    def test_a_blocked_unit_states_its_claim(self) -> None:
        assert self._render(frozenset({"x"}))["claim"] == "malware"

    def test_no_unit_claim_without_the_gates_verdict(self) -> None:
        payload = self._render(None)
        assert "claim" not in payload
        assert payload["findings"][0]["claim"] == "malware"  # type: ignore[index]
