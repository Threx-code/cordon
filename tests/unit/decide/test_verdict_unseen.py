"""Rules the package verdict never saw (release item 66's finding, cordon-47 and the outer layer, 2 Nov).

`Verdict._lowers` spares a finding only if its rule is in the model's keep or floor. A rule added after
the fit has no `r:` feature, so the model's score never saw it, yet it is lowered as if trained. Each
such rule leaves the lowered set by one of two doors: its own measured pair admits it to keep, or a
refit gives it a feature. This file holds both doors shut against accidents: the admitted rules
stay kept, and every code rule in the catalogue is either seen, kept, floored, or on the frozen list
below, so a new rule cannot be lowered silently.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.decide.verdict import MODEL_PATH, Verdict, VerdictModel
from cordon_scanner.decide.verdict_features import VerdictFeatures
from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.engine.registry import Registry
from cordon_scanner.foundation.models import Category, Confidence, Severity
from cordon_scanner.rules.loader import RuleLoader


class UnseenKit:
    @staticmethod
    def model() -> dict:
        model = VerdictModel.load(MODEL_PATH)
        assert model is not None
        return model

    @staticmethod
    def catalogue() -> set[str]:
        detectors = {r.id for r in RuleCatalogue.from_detectors(Registry().detectors())}
        return detectors | {r.id for pack in RuleLoader.load_builtin() for r in pack.rules}

    @staticmethod
    def seen(model: dict) -> set[str]:
        return {f[2:].split("#")[0] for f in model["features"] if f.startswith("r:")}


class TestTheAdmittedRulesAreKept:
    """Admitted by their measured pairs (outer layer, 2 Nov): NETWORK_PROBE 2 content misses in 2
    groups for 0 of 36,231 benign (nettool/pair.py); CODE.REUSE 39 content misses in 8 groups for 9 of
    18,303 holdout benign, 0 of 285 compromised_lib (ab54/summary-final.txt; an upper bound until the
    combined rescan with the verdict on)."""

    ADMITTED: ClassVar[tuple[str, ...]] = (
        "MALWARE.INSTALL.NETWORK_PROBE.001",
        "MALWARE.CODE.REUSE.001",
        # Measured exactly (2 Nov): each candidate unit scanned with the shipped model and with the
        # rule kept, a3b9c5f1's residual misses and unblocked benign pool (scratchpad i66b/exact-*.jsonl):
        "MALWARE.CI.RUNNER_SECRETS.001",  # 6 content misses in 5 groups newly blocked, 0 benign
        "SUSPECT.AGENT.API_REDIRECT.001",  # 3 content misses in 1 group newly blocked, 0 benign
        # MCP, measured exactly (2 Nov) on item 7's design lists, finals excluded: the 40 mcp-area units
        # carrying a lowered frozen rule, scanned with these three kept (scratchpad i66m/exact-v3.jsonl):
        # 6 malicious MCP variants newly blocked (six attack types), 0 of 4 benign changed.
        "SUSPECT.AGENT.HIDDEN_DIRECTIVE.001",
        "SUSPECT.MCP.HANDLER_SHELL.001",
        "SUSPECT.AGENT.TOOL_PRIORITY_CLAIM.001",
        # New outer-layer rules, kept from the start so the verdict never lowers them unseen (item 67),
        # by their pairs on a3b9c5f1's rows (outer-layer scratchpad jsm/):
        "SUSPECT.OBFUSCATION.MANGLED.001",  # 31 content misses in 16 groups for 3 benign (pair4.txt)
        "SUSPECT.OBFUSCATION.REQUIRE_ALIAS.001",  # 7 content misses in 7 groups, 0 benign (pairn.txt)
        # 6 content misses in 2 groups blocked, 0 benign: an interaction host in an install-hook
        # script (jsm/pairn-hosts.txt, row hook_interaction); in a person-run script it warns
        "MALWARE.EXFIL.SCRIPT_CALLBACK.001",
        # Declared HIGH (cordon-47, 3 Nov): 12 content misses in 3 groups, 0 of 36,231 benign units carry it
        # (full-b9bd rows; npmbase/kl-units.jsonl)
        "SUSPECT.BINARY.KEYLOGGER.001",
        # MCP, measured on the full sets (cordon-47, 7 Nov; scratchpad mcp-base/*-rows.jsonl, rows on
        # 0f23e016): units not blocked today that carry the lowered finding, newly blocked if kept.
        # mcp-variants 177 malicious, 636 benign; MCPTox 485/362; MCP-SafetyBench 180/13; AgentDefense
        # 132/384; real MCP packages mcpc 1,700 benign; npm benign 91,199 rows (none carries any of them).
        "SUSPECT.MCP.BORROWED_NAME.001",  # 6 malicious, 0 benign
        "SUSPECT.MCP.INPUT_MIRROR.001",  # 21 malicious, 1 benign (mcpc agentsync-mcp); 2 Nov had 2 vs 1
        "SUSPECT.MCP.LISTENER.001",  # 8 malicious, 0 benign
        "SUSPECT.MCP.TIME_BOMB.001",  # 7 malicious, 0 benign
        # Declared HIGH (cordon-47, 7 Nov), kept from the start: 1 dev-half wild skill (backdoor_test), and
        # 8 of 154,808 public skills carry the shape (scratchpad skill-listener.py).
        "SUSPECT.AGENT.SKILL_LISTENER.001",
        # Declared HIGH (cordon-47, 7 Nov), kept from the start: 2 dev-half malicious skills (context-loader,
        # an injected .notebook-profile), 0 dev benign; 1 of 154,808 public skills, the same proof of concept.
        "SUSPECT.AGENT.SKILL_DISGUISED_ARCHIVE.001",
        # PyPI v0.8.0 grades, kept from the start (11 Nov): content misses of the 158 unseen PyPI
        # units each newly blocks on a799c5d2. Benign units carrying each at any severity on the
        # full gate (16,249 units, a799c5d2): DECODED 5, CREDENTIAL_STORE.002 1, HIDDEN_DESTINATION
        # 2, FOREIGN_PROGRAM 1, IMPLANT 57 before its run leg was narrowed, the others 0.
        "MALWARE.INSTALL.FOREIGN_PROGRAM.001",  # 5 unseen units
        "MALWARE.DROPPER.HIDDEN.001",  # 1 unseen unit
        "MALWARE.DROPPER.DECODED.001",  # analysis team, decoded payload compiled and imported
        "MALWARE.EXFIL.HIDDEN_DESTINATION.002",  # 1 unseen unit
        "MALWARE.EXFIL.CREDENTIAL_STORE.002",  # 1 unseen unit
        "MALWARE.EXFIL.DNS_TUNNEL.001",  # 1 unseen unit
        "MALWARE.IMPLANT.INSTALL.001",  # 1 unseen unit; run leg narrowed to analyser facts
        "MALWARE.DROPPER.DATA_FILE_CODE.001",  # 1 unseen unit (houdus); benign measured at the gate
        "MALWARE.EXFIL.CONFUSION_BEACON.001",  # 1 unseen unit (promptflow_runtime); benign at the gate
    )

    def test_each_is_in_keep(self) -> None:
        keep = set(UnseenKit.model()["keep"])
        assert set(self.ADMITTED) <= keep

    def test_a_kept_high_finding_under_the_line_is_not_lowered(self) -> None:
        # erp.srm.common 1.0.2's shape: HIGH at the rule, a score of 0.0909 under the 0.4502 line.
        keep = frozenset(UnseenKit.model()["keep"])
        for rule in self.ADMITTED:
            assert not Verdict._lowers(
                rule, Severity.HIGH, Confidence.HIGH, Category.MALICIOUS, score=0.0909,
                block=0.4502, liftable=True, floor=frozenset(), keep=keep,
            )  # fmt: skip

    def test_an_unadmitted_unseen_rule_is_still_lowered(self) -> None:
        keep = frozenset(UnseenKit.model()["keep"])
        assert Verdict._lowers(
            "SUSPECT.BINARY.IMPLANT.001", Severity.HIGH, Confidence.HIGH, Category.SUSPICIOUS,
            score=0.0909, block=0.4502, liftable=True, floor=frozenset(), keep=keep,
        )  # fmt: skip


class TestNoRuleIsLoweredUnseenByAccident:
    """The retrain cadence's check (cordon-47, note 61): after any fit, and in the suite now, every code
    rule in the catalogue is seen by the model, kept, floored, or on this frozen list. A rule leaves the
    list only by its measured pair (into keep) or a refit (a feature); a new rule must be placed."""

    UNSEEN_LOWERED: ClassVar[frozenset[str]] = frozenset(
        {
            "MALWARE.AGENT.AUTORUN.001",
            "MALWARE.AGENT.HIJACK.001",
            "MALWARE.AGENT.HOOK_EXFIL.001",
            "MALWARE.CI.CREDENTIAL_HARVEST.001",
            "MALWARE.CI.DECODED_PROGRAM.001",
            "MALWARE.CI.SCHEDULED_FETCH_EXEC.001",
            "MALWARE.CI.SECRET_DUMP.001",
            "MALWARE.CI.SECRET_TO_DROP_POINT.001",
            "MALWARE.CLAMAV.SIGNATURE.001",
            "MALWARE.DECODE_EXEC.ENCODED_SHELL.001",
            "MALWARE.DECODE_EXEC.INVISIBLE.001",
            "MALWARE.DEPENDENCY.BUNDLED.001",
            "MALWARE.DEPENDENCY.REMOTE_TARBALL.BUNDLED.001",
            "MALWARE.DROPPER.SHIPPED_PAYLOAD.001",
            "MALWARE.INSTALL.HIDDEN_ACTION.001",
            "MALWARE.INSTALL.OPAQUE_CODE.001",
            "MALWARE.INSTALL.SHELL_EVASION.001",
            "MALWARE.MODEL.PICKLE_EXEC.001",
            "MALWARE.PROTESTWARE.001",
            "MALWARE.RULEFILE.MATCH.001",
            "SUSPECT.AGENT.ATR.MODEL_SECURITY.001",
            "SUSPECT.AGENT.AUTH_BYPASS_EDIT.001",
            "SUSPECT.AGENT.CREDENTIAL_EXFIL.001",  # measured 2 Nov: 0 malware, 1 benign newly blocked if kept: stays
            "SUSPECT.AGENT.DROPPER_PROSE.001",
            "SUSPECT.AGENT.FRONT_MATTER_CODE.001",
            "SUSPECT.AGENT.HIDDEN_TEXT.001",
            "SUSPECT.AGENT.INSTALL_REDIRECT.001",  # measured 2 Nov: 0 malware, 1 benign newly blocked if kept: stays
            "SUSPECT.AGENT.INTENT_CHAINED.001",
            "SUSPECT.AGENT.JUDGED.001",
            "SUSPECT.AGENT.PHANTOM_PREREQUISITE.001",
            "SUSPECT.AGENT.SENSITIVE_IMPORT.001",
            "SUSPECT.AGENT.SKILL_DECODE_RUN.001",
            "SUSPECT.AGENT.SKILL_HOOK_FETCH.001",
            "SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.001",
            "SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001",
            "SUSPECT.ARCHIVE.PADDED.001",
            "SUSPECT.AZURE.NO_AUTH.CONTAINERREGISTRY_REGISTRIES_ANONYMOUSPULLENABLED.001",
            "SUSPECT.AZURE.OPEN_INGRESS.NETWORK_NETWORKSECURITYGROUPS_SOURCEADDRESSPREFIX.001",
            "SUSPECT.AZURE.PASSWORD_AUTH.COMPUTE_VIRTUALMACHINES_DISABLEPASSWORDAUTHENTICATION.001",
            "SUSPECT.AZURE.PLAINTEXT.STORAGE_STORAGEACCOUNTS_SUPPORTSHTTPSTRAFFICONLY.001",
            "SUSPECT.AZURE.PLAINTEXT.WEB_SITES_FTPSSTATE.001",
            "SUSPECT.AZURE.PLAINTEXT.WEB_SITES_HTTPSONLY.001",
            "SUSPECT.AZURE.SHARED_KEY_AUTH.CONTAINERREGISTRY_REGISTRIES_ADMINUSERENABLED.001",
            "SUSPECT.BINARY.CREDENTIAL_THEFT.001",
            "SUSPECT.BINARY.HIDDEN_IMPORTS.001",
            "SUSPECT.BINARY.IMPLANT.001",
            "SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.001",
            "SUSPECT.BINARY.PACKED.001",
            "SUSPECT.BINARY.PROCESS_INJECTION.001",
            "SUSPECT.BUILD.MSBUILD_FETCH_EXEC.001",
            "SUSPECT.CI.ARTIFACT_POISONING.001",
            "SUSPECT.CI.AZURE_INJECTION.001",
            "SUSPECT.CI.BITBUCKET_INJECTION.001",
            "SUSPECT.CI.BUILDKITE_INJECTION.001",
            "SUSPECT.CI.DEVCONTAINER_FETCH.001",
            "SUSPECT.CI.ENVIRONMENT_INJECTION.001",
            "SUSPECT.CI.GITLAB_INJECTION.001",
            "SUSPECT.CI.JENKINS_INJECTION.001",
            "SUSPECT.CODE.MODEL.001",
            "SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001",
            "SUSPECT.DEPENDENCY.FOREIGN_COMMIT.BUNDLED.001",
            "SUSPECT.DEPENDENCY.HALLUCINATED.001",
            "SUSPECT.DEPENDENCY.HALLUCINATED.BUNDLED.001",
            "SUSPECT.DEPENDENCY.LOCAL_SHADOW.001",
            "SUSPECT.DEPENDENCY.PROVISIONAL.001",
            "SUSPECT.DEPENDENCY.REMOTE_TARBALL.BUNDLED.001",
            "SUSPECT.DEPENDENCY.REMOVED_NAME.001",
            "SUSPECT.DEPENDENCY.SOURCE.BUNDLED.001",
            "SUSPECT.DEPENDENCY.TYPOSQUAT.BUNDLED.001",
            "SUSPECT.DEPENDENCY.UNREGISTERED.001",
            "SUSPECT.DEPENDENCY.UNVETTED.001",
            "SUSPECT.DEPENDENCY.YANKED.001",
            "SUSPECT.DOCUMENT.DDE.001",
            "SUSPECT.DOCUMENT.REMOTE_OBJECT.001",
            "SUSPECT.DOCUMENT.RTF_OBJECT.001",
            "SUSPECT.DROPPER.REMOTE_COMMAND.001",
            "SUSPECT.EXFIL.BROWSER_SECRETS.001",  # measured 2 Nov (MCP): 0 malware, 1 benign: stays
            "SUSPECT.EXTENSION.HIDDEN_NAME.001",
            "SUSPECT.EXTENSION.LOOKALIKE.001",
            "SUSPECT.HELM.UNTRUSTED_REPOSITORY.BUNDLED.001",
            "SUSPECT.INSTALL.UNEXAMINED.001",
            "SUSPECT.LOCKFILE.INTEGRITY_CONFLICT.BUNDLED.001",
            "SUSPECT.LOCKFILE.INTEGRITY_MALFORMED.BUNDLED.001",
            "SUSPECT.LOCKFILE.SOURCE.BUNDLED.001",
            "SUSPECT.MCP.ARGUMENT_OVERRIDE.001",
            "SUSPECT.MCP.CONTAINER_HOST_ACCESS.001",
            "SUSPECT.MCP.ENV_INJECTION.001",
            "SUSPECT.MCP.INPUT_FORWARDED.001",
            "SUSPECT.MCP.LIVE_TOOL_DESCRIPTION.001",
            "SUSPECT.MCP.LOOKALIKE.001",
            "SUSPECT.MCP.SCHEMA_POISONING.001",  # measured 2 Nov (MCP): 0 malware, 1 benign: stays
            "SUSPECT.MCP.TOOLS_CHANGED.001",
            "SUSPECT.MCP.TOOL_POISONING.001",
            "SUSPECT.MCP.UNTRUSTED_REMOTE.001",
            "SUSPECT.MEDIA.APPENDED_PAYLOAD.001",
            "SUSPECT.MODEL.LOADED_ON_IMPORT.001",
            "SUSPECT.MODEL.MALICIOUS_PACKAGE.001",
            "SUSPECT.OBFUSCATION.TAG_SMUGGLING.001",  # measured 2 Nov: 0 malware, 1 benign newly blocked if kept: stays
            "SUSPECT.PACKAGE.REPOSITORY.001",
            "SUSPECT.RECIPE.PROVISIONAL.001",
            "SUSPECT.REGISTRY.REVIEW.001",
            "SUSPECT.RELEASE.NEW_BINARY.001",
            "SUSPECT.RELEASE.NEW_CAPABILITY.001",
            "SUSPECT.RELEASE.NEW_INSTALL_HOOK.001",
            "SUSPECT.RELEASE.NEW_OBFUSCATION.001",
            "SUSPECT.RELEASE.NEW_PUBLISHER.001",
            "SUSPECT.RELEASE.NEW_YOUNG_DEPENDENCY.001",
            "SUSPECT.RULEFILE.MATCH.001",
            "SUSPECT.RULEFILE.UNMATCHED.001",
            "SUSPECT.SBOM.DRIFT.001",
            "SUSPECT.TARGETED_PAYLOAD.001",
            "SUSPECT.VCS.HOOKS_PATH.001",
            "SUSPECT.VCS.HOOK_ADDED.001",
        }
    )

    def test_every_code_rule_is_placed(self) -> None:
        model = UnseenKit.model()
        placed = (
            UnseenKit.seen(model) | set(model["keep"]) | set(model["floor"]) | self.UNSEEN_LOWERED
        )
        code = {r for r in UnseenKit.catalogue() if VerdictFeatures.is_code(r)}
        assert not sorted(code - placed), "place these: measure a pair (keep) or refit (a feature)"

    def test_the_frozen_list_only_names_rules_still_unseen(self) -> None:
        model = UnseenKit.model()
        stale = self.UNSEEN_LOWERED & (
            UnseenKit.seen(model) | set(model["keep"]) | set(model["floor"])
        )
        assert not sorted(stale), "these left the lowered set: remove them from UNSEEN_LOWERED"
