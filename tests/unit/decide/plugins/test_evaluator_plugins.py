"""A third-party evaluator plugin is loaded only when signed and well formed, reads nothing but its table, and its verdict is evidence."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any, ClassVar

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.plugins.evaluator_plugins import (
    EvaluatorPlugin,
    EvaluatorPlugins,
    PluginRefused,
)
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from cordon_scanner.rules.pack_signatures import PackSignatures

SIGNER = Ed25519Signer(bytes([0x44]) * 32)
PINNED = (SIGNER.public.hex(),)
MANIFEST: dict[str, Any] = {
    "id": "acme-eval",
    "version": "1.2.0",
    "kind": "evaluator",
    "table": [
        {
            "id": "young-publisher",
            "when": {"ecosystem": "npm", "publisher": "new"},
            "severity": "medium",
            "reason": "a first release from a publisher seen today",
        }
    ],
}


class Kit:
    @staticmethod
    def signed(manifest: dict[str, Any], signer: Ed25519Signer = SIGNER) -> dict[str, Any]:
        sig = signer.sign(PackSignatures.canonical(manifest))
        return {
            "manifest": manifest,
            "signature": {"public": signer.public.hex(), "sig": sig.hex()},
        }


class TestOnlyASignedPluginLoads:
    def test_a_signed_versioned_plugin_loads(self) -> None:
        plugin = EvaluatorPlugins.load(Kit.signed(MANIFEST), PINNED)
        assert plugin.name == "PLUGIN.acme-eval.1.2.0"

    def test_an_unsigned_one_is_refused(self) -> None:
        with pytest.raises(PluginRefused, match="unsigned"):
            EvaluatorPlugins.load({"manifest": MANIFEST}, PINNED)

    def test_one_signed_by_a_key_that_is_not_pinned_is_refused(self) -> None:
        stranger = Ed25519Signer(bytes([0x55]) * 32)
        with pytest.raises(PluginRefused, match="signature"):
            EvaluatorPlugins.load(Kit.signed(MANIFEST, stranger), PINNED)

    def test_an_edit_after_signing_is_refused(self) -> None:
        bundle = Kit.signed(MANIFEST)
        bundle["manifest"] = copy.deepcopy(MANIFEST)
        bundle["manifest"]["table"][0]["severity"] = "info"
        with pytest.raises(PluginRefused, match="signature"):
            EvaluatorPlugins.load(bundle, PINNED)

    def test_no_pinned_key_means_none_loads(self) -> None:
        with pytest.raises(PluginRefused):
            EvaluatorPlugins.load(Kit.signed(MANIFEST))

    @pytest.mark.parametrize(
        "change", [{"version": "1.2"}, {"kind": "script"}, {"id": "Bad Name"}, {"table": []}]
    )
    def test_a_malformed_manifest_is_refused_even_when_signed(self, change: dict[str, Any]) -> None:
        with pytest.raises(PluginRefused):
            EvaluatorPlugins.load(Kit.signed({**MANIFEST, **change}), PINNED)

    def test_an_entry_with_a_key_that_could_hold_code_is_refused(self) -> None:
        entry = {**MANIFEST["table"][0], "run": "import os"}
        with pytest.raises(PluginRefused, match="other keys"):
            EvaluatorPlugins.load(Kit.signed({**MANIFEST, "table": [entry]}), PINNED)


class TestTheVerdictIsEvidence:
    def test_a_matching_artifact_gives_a_finding_the_decision_can_see(self) -> None:
        plugin = EvaluatorPlugins.load(Kit.signed(MANIFEST), PINNED)
        verdict = plugin.evaluate({"ecosystem": "npm", "publisher": "new"})
        assert verdict is not None
        finding = plugin.evidence(verdict, "package.json")
        evidence = EvidenceSet(findings=(finding,))
        assert evidence.findings[0].rule_id == "PLUGIN.acme-eval.1.2.0.young-publisher"
        assert evidence.findings[0].category == "policy"

    def test_an_artifact_the_table_does_not_name_gives_nothing(self) -> None:
        plugin = EvaluatorPlugins.load(Kit.signed(MANIFEST), PINNED)
        assert plugin.evaluate({"ecosystem": "pypi", "publisher": "new"}) is None


class Asking:
    CLOCK = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    MANIFEST: ClassVar[dict[str, Any]] = {
        "id": "acme-eval",
        "version": "1.2.0",
        "kind": "evaluator",
        "table": [
            {
                "id": "npm-package",
                "when": {"ecosystem": "npm", "kind": "package"},
                "severity": "high",
                "reason": "this evaluator distrusts npm packages",
            }
        ],
    }

    @staticmethod
    def decide(plugins: tuple[EvaluatorPlugin, ...]) -> Decision:
        source = {
            "policy_schema": 2,
            "id": "acme/policy",
            "version": 1,
            "scope": ["acme"],
            "rules": [
                {
                    "id": "plugin-deny",
                    "tier": "deny",
                    "then": "block",
                    "when": {"finding.category": "policy"},
                }
            ],
            "defaults": {},
        }
        artifact = ArtifactRef(
            kind="package",
            subject_id="pkg:npm/left-pad",
            digest=ArtifactDigests.of_bytes(b"artifact"),
            ecosystem="npm",
            released_at="2026-06-01T00:00:00Z",
        )
        return PointRuntime.ask(
            "ci_gate",
            artifact,
            EvidenceSet(),
            PolicyCompiler.compile(PolicySource.from_json(source)),
            Asking.CLOCK,
            environment="production",
            scope_path=("acme",),
            plugins=plugins,
        )


class TestAPluginChangesTheDecision:
    def test_a_signed_plugins_finding_changes_the_decision(self) -> None:
        plugin = EvaluatorPlugins.load(Kit.signed(Asking.MANIFEST), PINNED)
        assert Asking.decide(()).state != "BLOCK"
        assert Asking.decide((plugin,)).state == "BLOCK"

    def test_an_unsigned_plugin_is_refused_so_the_decision_does_not_change(self) -> None:
        with pytest.raises(PluginRefused):
            EvaluatorPlugins.load({"manifest": Asking.MANIFEST}, PINNED)
        assert Asking.decide(()).state != "BLOCK"
