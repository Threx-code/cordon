"""The one stdlib runtime every point calls, and the order its evidence is gathered in (spec 8.3).

`resolve -> evidence.gather -> decide -> act`, with `cache.store` and `outbox.append` in the local store. Each evidence source has a
fixture; the order is intelligence, a cloud decision, a scan, provenance; a source that fails is a source that did not answer; and
the whole run, a decision made end to end, needs nothing that is not the standard library.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.cloud.runtime import CordonRuntime, ScanEvidence, Sources
from cordon_scanner.decide.decision.evidence import (
    FindingFact,
    GapFact,
    IntelMatch,
    Provenance,
)
from cordon_scanner.decide.resolve.action import ActionResolver
from cordon_scanner.decide.resolve.resolution import Resolution, SourceUnavailable
from kits.bundle_kit import T0, Kit, Platform
from support import ROOT

COMMIT = "0123456789abcdef0123456789abcdef01234567"
SLSA = [
    {"id": "slsa", "tier": "require", "then": "review", "when": {"provenance.slsa_level": "<3"}}
]
DENY = [{"id": "deny", "tier": "deny", "then": "block", "when": {"finding.category": "suspicious"}}]
LEVELS = {"*": "block", "ci": "warn"}


class Calls:
    """Adapters that record that they were asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []
        self.acted: list[tuple[str, str]] = []
        self.cloud_answer = None
        self.scan_answer = ScanEvidence()
        self.provenance_answer: Provenance | None = Provenance(slsa_level=3)
        self.intel_answer: tuple[IntelMatch, ...] = ()
        self.failing: set[str] = set()

    def _answer(self, name: str, value: Any) -> Any:
        self.asked.append(name)
        if name in self.failing:
            raise SourceUnavailable(name)
        return value

    def sources(self) -> Sources:
        return Sources(
            intel=lambda artifact: self._answer("intel", self.intel_answer),
            cloud=lambda artifact: self._answer("cloud", self.cloud_answer),
            scan=lambda artifact: self._answer("scan", self.scan_answer),
            provenance=lambda artifact: self._answer("provenance", self.provenance_answer),
            rules_version="rules-1",
        )

    @staticmethod
    def resolver(reference: str) -> Resolution:
        return ActionResolver.resolve(reference, Scm())


class Scm:
    def commit_of(self, owner: str, repo: str, ref: str) -> str:
        return COMMIT


class World:
    @staticmethod
    def build(
        tmp_path: Path,
        calls: Calls,
        *,
        rules: list[dict[str, Any]] | None = None,
        lifetime: timedelta = timedelta(days=2),
    ) -> CordonRuntime:
        platform = Platform()
        store = LocalStore(tmp_path)
        local = Kit.runtime(platform, store)
        expires = T0 + lifetime
        policy = Kit.compiled(1, expires, on_incomplete=LEVELS, rules=rules)
        local.accept([platform.publish(policy, issued=T0, expires=expires)], T0)
        return CordonRuntime(
            local,
            resolvers={"ci_action": Calls.resolver},
            sources=calls.sources(),
            act=lambda decision, point: calls.acted.append((decision.state, point)),
        )

    @staticmethod
    def run(
        runtime: CordonRuntime,
        *,
        online: bool = False,
        minutes: int = 5,
        environment: str = "production",
    ):
        return runtime.run(
            "ci_action",
            "actions/checkout@v4",
            "ci_gate",
            T0 + timedelta(minutes=minutes),
            environment=environment,
            scope_path=("acme",),
            online=online,
        )


class TestTheOrderAndTheFallThrough:
    def test_intelligence_is_asked_first_and_a_known_malware_match_ends_the_gathering(
        self, tmp_path: Path
    ) -> None:
        calls = Calls()
        calls.intel_answer = (
            IntelMatch(
                kind="known_malware", id="MAL-1", source="osv", first_seen="2026-11-01T00:00:00Z"
            ),
        )
        outcome = World.run(World.build(tmp_path, calls), online=True)
        assert outcome.decision.state == "BLOCK" and "R100" in outcome.decision.reason_codes
        assert calls.asked == ["intel"] and outcome.ran == ("intel", "stopped:known_malware")

    def test_online_a_cloud_decision_made_under_this_policy_is_reused_and_nothing_is_scanned(
        self, tmp_path: Path
    ) -> None:
        calls = Calls()
        runtime = World.build(tmp_path, calls)
        calls.cloud_answer = World.run(
            runtime
        ).decision  # a decision under the held policy, as the control plane would have made it
        calls.asked.clear()
        outcome = World.run(World.build(tmp_path / "second", calls), online=True)
        assert outcome.source == "cloud" and calls.asked == ["intel", "cloud"]

    def test_a_cloud_decision_under_another_policy_is_not_reused(self, tmp_path: Path) -> None:
        calls = Calls()
        other = World.build(tmp_path / "other", Calls(), rules=DENY)
        calls.cloud_answer = World.run(other).decision
        outcome = World.run(World.build(tmp_path / "mine", calls), online=True)
        assert outcome.source == "decided" and calls.asked == ["intel", "cloud", "scan"]

    def test_a_cloud_source_that_fails_falls_through_to_the_scan(self, tmp_path: Path) -> None:
        calls = Calls()
        calls.failing.add("cloud")
        outcome = World.run(World.build(tmp_path, calls), online=True)
        assert calls.asked == ["intel", "cloud", "scan"] and outcome.decision.state == "ALLOW"

    def test_offline_the_cloud_is_not_asked(self, tmp_path: Path) -> None:
        calls = Calls()
        World.run(World.build(tmp_path, calls), online=False)
        assert calls.asked == ["intel", "scan"]


class TestTheScan:
    def test_what_the_scan_finds_is_decided_on(self, tmp_path: Path) -> None:
        calls = Calls()
        finding = FindingFact(
            rule_id="SUSPECT.X.001", severity="high", confidence="high", category="suspicious"
        )
        calls.scan_answer = ScanEvidence(findings=(finding,))
        outcome = World.run(World.build(tmp_path, calls, rules=DENY))
        assert outcome.decision.state == "BLOCK" and "R401" in outcome.decision.reason_codes

    def test_the_evidence_of_a_scan_is_kept_by_digest_and_the_scan_is_not_repeated(
        self, tmp_path: Path
    ) -> None:
        calls = Calls()
        runtime = World.build(tmp_path, calls)
        first = World.run(runtime)
        second = World.run(runtime, minutes=6)
        assert calls.asked.count("scan") == 1
        assert first.ran == ("intel", "scan") and second.ran == ("intel", "scan:kept")

    def test_new_rules_scan_again(self, tmp_path: Path) -> None:
        calls = Calls()
        runtime = World.build(tmp_path, calls)
        World.run(runtime)
        newer = CordonRuntime(
            runtime._local,
            resolvers={"ci_action": Calls.resolver},
            sources=replace(calls.sources(), rules_version="rules-2"),
        )
        World.run(newer, minutes=6)
        assert calls.asked.count("scan") == 2

    def test_a_scan_that_fails_is_missing_evidence_not_a_clean_result(self, tmp_path: Path) -> None:
        calls = Calls()
        calls.failing.add("scan")
        outcome = World.run(World.build(tmp_path, calls))
        assert outcome.decision.state == "BLOCK" and "R200" in outcome.decision.reason_codes

    def test_a_point_with_no_scan_source_has_missing_evidence_and_asks_nothing_to_scan(
        self, tmp_path: Path
    ) -> None:
        class WithoutScan(Calls):
            def sources(self) -> Sources:
                return replace(super().sources(), scan=None)

        calls = WithoutScan()
        outcome = World.run(World.build(tmp_path, calls))
        assert outcome.decision.state == "BLOCK" and "R200" in outcome.decision.reason_codes
        assert "scan" not in calls.asked

    def test_an_incomplete_scan_is_an_incomplete_decision(self, tmp_path: Path) -> None:
        calls = Calls()
        calls.scan_answer = ScanEvidence(
            gaps=(GapFact(rule_id="SUSPECT.PACKAGE.UNPARSEABLE.001", path="a.js"),)
        )
        outcome = World.run(World.build(tmp_path, calls))
        assert outcome.decision.state == "BLOCK" and "R204" in outcome.decision.reason_codes


class TestProvenance:
    def test_it_is_verified_when_a_rule_reads_it_and_not_otherwise(self, tmp_path: Path) -> None:
        reading, other = Calls(), Calls()
        World.run(World.build(tmp_path / "a", reading, rules=SLSA))
        World.run(World.build(tmp_path / "b", other))
        assert "provenance" in reading.asked and "provenance" not in other.asked

    def test_what_it_finds_is_decided_on(self, tmp_path: Path) -> None:
        calls = Calls()
        calls.provenance_answer = Provenance(slsa_level=1)
        outcome = World.run(World.build(tmp_path, calls, rules=SLSA))
        assert outcome.decision.state == "REVIEW" and "R500" in outcome.decision.reason_codes

    def test_a_verification_that_fails_is_missing_evidence(self, tmp_path: Path) -> None:
        calls = Calls()
        calls.failing.add("provenance")
        outcome = World.run(World.build(tmp_path, calls, rules=SLSA))
        assert "R200" in outcome.decision.reason_codes and outcome.decision.state == "BLOCK"


class TestResolveAndAct:
    def test_an_unresolved_name_is_r203_and_the_cloud_is_not_asked(self, tmp_path: Path) -> None:
        calls = Calls()
        outcome = World.build(tmp_path, calls).run(
            "ci_action",
            "./local/action",
            "ci_gate",
            T0 + timedelta(minutes=5),
            environment="production",
            scope_path=("acme",),
            online=True,
        )
        assert "R203" in outcome.decision.reason_codes and "cloud" not in calls.asked

    def test_a_kind_with_no_resolver_is_unresolved(self, tmp_path: Path) -> None:
        outcome = World.build(tmp_path, Calls()).run(
            "mcp_server", "npx tool", "cli", T0 + timedelta(minutes=5), environment="production"
        )
        assert (
            outcome.resolution.reason == "unparseable" and "R203" in outcome.decision.reason_codes
        )

    def test_the_point_s_own_adapter_is_given_the_decision(self, tmp_path: Path) -> None:
        calls = Calls()
        outcome = World.run(World.build(tmp_path, calls))
        assert calls.acted == [(outcome.decision.state, "ci_gate")]

    def test_what_was_decided_is_kept_and_queued(self, tmp_path: Path) -> None:
        calls = Calls()
        runtime = World.build(tmp_path, calls)
        World.run(runtime)
        World.run(runtime)
        store = LocalStore(tmp_path)
        decisions = [item for item in store.pending() if item.kind == "decision"]
        assert len(decisions) == 1 and store.cache_size() == 1


class TestWithNothingButTheStandardLibrary:
    SCRIPT = """
import sys
sys.path[:0] = [{src!r}, {tests!r}]
from datetime import timedelta
from pathlib import Path
import tempfile
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.cloud.runtime import CordonRuntime, ScanEvidence, Sources
from cordon_scanner.decide.resolve.action import ActionResolver
from kits.bundle_kit import T0, Kit, Platform

class Scm:
    def commit_of(self, owner, repo, ref):
        return "0123456789abcdef0123456789abcdef01234567"

platform = Platform()
local = Kit.runtime(platform, LocalStore(Path(tempfile.mkdtemp())))
expires = T0 + timedelta(days=2)
local.accept([platform.publish(Kit.compiled(1, expires), issued=T0, expires=expires)], T0)
runtime = CordonRuntime(
    local,
    resolvers={{"ci_action": lambda ref: ActionResolver.resolve(ref, Scm())}},
    sources=Sources(scan=lambda artifact: ScanEvidence()),
)
outcome = runtime.run("ci_action", "actions/checkout@v4", "ci_gate", T0 + timedelta(minutes=1), environment="production", scope_path=("acme",))
foreign = sorted(
    name for name in {{m.partition(".")[0] for m in sys.modules}}
    if name not in sys.stdlib_module_names and name not in ("cordon_scanner", "kits", "bundle_kit") and not name.startswith("_")
)
print(outcome.decision.state, foreign)
"""

    def test_a_decision_is_made_end_to_end_with_site_packages_off_and_no_foreign_module_loaded(
        self,
    ) -> None:
        src, tests = str(ROOT / "src"), str(ROOT / "tests")
        done = subprocess.run(
            [sys.executable, "-I", "-S", "-c", self.SCRIPT.format(src=src, tests=tests)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert done.returncode == 0, done.stderr[-800:]
        assert done.stdout.strip() == "ALLOW []"


class TestARevokedDigestIsNeverServedFromACache:
    """The revocation list is asked first, before intelligence, a reused cloud decision or a kept decision: an ALLOW remembered for a digest that is revoked afterwards is a BLOCK with R101, at the hook and at the gate."""

    @staticmethod
    def runtime(tmp_path: Path, calls: Calls, revoked: set[str]) -> CordonRuntime:
        sources = replace(
            calls.sources(),
            revoked=lambda artifact: artifact.digest in revoked or calls._answer("revoked", False),
        )
        built = World.build(tmp_path, calls)
        return CordonRuntime(
            built._local, resolvers={"ci_action": Calls.resolver}, sources=sources, act=None
        )

    @staticmethod
    def ask(runtime: CordonRuntime, point: str, *, online: bool = False) -> Any:
        return runtime.run(
            "ci_action",
            "actions/checkout@v4",
            point,
            T0 + timedelta(minutes=5),
            environment="production",
            scope_path=("acme",),
            online=online,
        )

    def test_an_allow_kept_at_the_gate_becomes_a_block_once_the_digest_is_revoked(
        self, tmp_path: Path
    ) -> None:
        calls, revoked = Calls(), set()
        runtime = self.runtime(tmp_path, calls, revoked)
        first = self.ask(runtime, "ci_gate")
        again = self.ask(runtime, "ci_gate")
        assert first.decision.state == "ALLOW" and again.source == "kept"
        revoked.add(first.resolution.artifact().digest)
        after = self.ask(runtime, "ci_gate")
        assert (
            after.decision.state == "BLOCK"
            and "R101" in after.decision.reason_codes
            and after.source != "kept"
        )

    def test_the_same_at_the_agent_hook(self, tmp_path: Path) -> None:
        calls, revoked = Calls(), set()
        runtime = self.runtime(tmp_path, calls, revoked)
        first = self.ask(runtime, "agent_hook")
        assert first.decision.state == "ALLOW" and self.ask(runtime, "agent_hook").source == "kept"
        revoked.add(first.resolution.artifact().digest)
        after = self.ask(runtime, "agent_hook")
        assert after.decision.state == "BLOCK" and "R101" in after.decision.reason_codes

    def test_a_cloud_decision_on_offer_does_not_stand_in_for_a_revoked_digest(
        self, tmp_path: Path
    ) -> None:
        calls, revoked = Calls(), set()
        runtime = self.runtime(tmp_path, calls, revoked)
        first = self.ask(runtime, "ci_gate")
        calls.cloud_answer = first.decision  # the control plane would reuse this ALLOW
        revoked.add(first.resolution.artifact().digest)
        after = self.ask(runtime, "ci_gate", online=True)
        assert (
            after.decision.state == "BLOCK"
            and "R101" in after.decision.reason_codes
            and after.source != "cloud"
        )
        assert "cloud" not in calls.asked[-3:]

    def test_the_revocation_list_is_asked_before_anything_else(self, tmp_path: Path) -> None:
        calls = Calls()
        outcome = self.ask(self.runtime(tmp_path, calls, set()), "ci_gate")
        assert outcome.ran[0] == "revoked" and calls.asked[0] == "revoked"

    def test_a_revoked_digest_stops_the_gathering_there(self, tmp_path: Path) -> None:
        calls, revoked = Calls(), set()
        runtime = self.runtime(tmp_path, calls, revoked)
        revoked.add(self.ask(runtime, "ci_gate").resolution.artifact().digest)
        calls.asked.clear()
        outcome = self.ask(runtime, "ci_gate")
        assert outcome.ran == ("revoked", "stopped:revoked") and calls.asked == []

    def test_a_list_that_cannot_be_read_is_a_missing_fact_not_a_pass(self, tmp_path: Path) -> None:
        calls = Calls()
        calls.failing.add("revoked")
        runtime = self.runtime(tmp_path, calls, set())
        outcome = self.ask(runtime, "ci_gate")
        assert outcome.decision.state != "ALLOW"


class SpyStore(LocalStore):
    """A store that records the keys under which scan evidence is kept."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.scan_keys: list[str] = []

    def keep_scan(self, key: str, evidence: dict[str, Any]) -> None:
        self.scan_keys.append(key)
        super().keep_scan(key, evidence)


class TestTenantsShareTheAnalysisAndNeverTheDecision:
    """BP-22-8, code part: the decision's key includes the policy's sha, so no decision is shared across tenants; the analysis of a public digest is
    kept under a key with neither a policy nor a tenant in it, so it is."""

    SUSPICIOUS = FindingFact(
        rule_id="SUSPECT.X.001", severity="high", confidence="high", category="suspicious"
    )

    def tenant(
        self, root: Path, rules: list[dict[str, Any]] | None
    ) -> tuple[CordonRuntime, SpyStore]:
        calls = Calls()
        calls.scan_answer = ScanEvidence(findings=(self.SUSPICIOUS,))
        platform, store = Platform(), SpyStore(root)
        local = Kit.runtime(platform, store)
        expires = T0 + timedelta(days=2)
        policy = Kit.compiled(1, expires, on_incomplete=LEVELS, rules=rules)
        local.accept([platform.publish(policy, issued=T0, expires=expires)], T0)
        return CordonRuntime(
            local, resolvers={"ci_action": Calls.resolver}, sources=calls.sources()
        ), store

    def test_two_policies_give_two_keys_for_the_same_question(self, tmp_path: Path) -> None:
        lenient, _ = self.tenant(tmp_path / "a", None)
        strict, _ = self.tenant(tmp_path / "b", DENY)
        one, two = World.run(lenient), World.run(strict)
        assert one.decision.inputs_digest != two.decision.inputs_digest
        assert one.decision.policy.sha256 != two.decision.policy.sha256
        assert (one.decision.state, two.decision.state) == ("ALLOW", "BLOCK")

    def test_the_same_policy_gives_the_same_key(self, tmp_path: Path) -> None:
        first, _ = self.tenant(tmp_path / "a", DENY)
        second, _ = self.tenant(tmp_path / "b", DENY)
        assert World.run(first).decision.inputs_digest == World.run(second).decision.inputs_digest

    def test_the_analysis_is_kept_under_the_same_key_whatever_the_policy(self, tmp_path: Path) -> None:
        (lenient, store_a), (strict, store_b) = self.tenant(tmp_path / "a", None), self.tenant(tmp_path / "b", DENY)
        World.run(lenient)
        World.run(strict)
        assert store_a.scan_keys and store_a.scan_keys == store_b.scan_keys

    def test_a_decision_kept_by_one_policy_is_not_served_to_another(self, tmp_path: Path) -> None:
        root = tmp_path / "shared"
        lenient, store = self.tenant(root, None)
        World.run(lenient)
        kept = list((root / "decisions").glob("*.json"))
        strict, _ = self.tenant(tmp_path / "other", DENY)
        decision = World.run(strict).decision
        assert all(path.stem != decision.inputs_digest.partition(":")[2] for path in kept)
        assert store.scan_keys
