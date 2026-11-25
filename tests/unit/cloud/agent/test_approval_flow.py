"""BP-9-4 and BP-9-5, flow 9.3: an agent adds an MCP server; the hook decides REVIEW (R700), names the approver and a ticket and queues an
approval request; once the approver has approved that digest, the retry decides ALLOW (R901) and the agent proceeds.

The platform's answer is recorded in the shape `POST /v1/decide` returns (an answer with the signed decision envelope) and signed here with a
decision key the tenant root delegated; the device takes it only as that."""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.cloud.agent.agent_hook import AgentCalls, AgentHook
from cordon_scanner.cloud.agent.cloud_decisions import CloudAsk, CloudDecisions
from cordon_scanner.cloud.agent.decision_envelope import DecisionEnvelope
from cordon_scanner.cloud.bundle_chain import Dsse
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.cloud.runtime import CordonRuntime, ScanEvidence, Sources
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.evidence import Approval, EvidenceSet, FindingFact
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.decide.resolve.resolution import Resolution
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, TENANT, Kit, Platform

REVIEW = [
    {
        "id": "review",
        "tier": "require",
        "then": "review",
        "reason": "R700",
        "when": {"finding.category": "policy"},
    }
]
APPROVER = "security@acme.example"
ADD = "claude mcp add files -- npx -y @acme/files"
DECIDER = Ed25519Signer(Kit.seed("hook-decider"))
STRANGER = Ed25519Signer(Kit.seed("hook-stranger"))
NOW = T0 + timedelta(minutes=5)


class Flow:
    """One device, one policy that sends an MCP add to review, and the platform's recorded answers."""

    def __init__(self, tmp_path: Path) -> None:
        self.platform = Platform()
        self.store = LocalStore(tmp_path)
        self.expires = T0 + timedelta(days=2)
        self.policy = Kit.compiled(1, self.expires, on_incomplete={"*": "block"}, rules=REVIEW)
        self.delegation = self.delegated()
        self.asked: list[dict[str, Any]] = []
        self.version: str | None = None
        self.answer: Any = None  # what the platform answers next: (status, body) or an exception

    def delegated(self) -> dict[str, Any]:
        keys = [
            ("policy", self.platform.policy_key.public),
            ("decision.hook", DECIDER.public),
        ]
        document = {
            "_type": "cordon.delegation/v1",
            "tenant": TENANT,
            "issued_at": T0.isoformat(),
            "keys": [
                {
                    "keyid": Dsse.keyid(public),
                    "public": public.hex(),
                    "role": role,
                    "not_before": (T0 - timedelta(days=1)).isoformat(),
                    "version": 1,
                }
                for role, public in keys
            ],
        }
        return Platform.sign("application/vnd.cordon.delegation+json", document, self.platform.root)

    def transport(
        self, method: str, url: str, *, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        self.asked.append(
            {
                "method": method,
                "url": url,
                "body": json.loads(body or b"{}"),
                "auth": headers.get("Authorization"),
            }
        )
        if isinstance(self.answer, Exception):
            raise self.answer
        status, document = self.answer
        return status, json.dumps(document).encode()

    def runtime(self) -> CordonRuntime:
        local = Kit.runtime(self.platform, self.store, delegation=self.delegation)
        local.accept([self.platform.publish(self.policy, issued=T0, expires=self.expires)], T0)
        pins = (self.platform.root.public, self.delegation, TENANT)
        ask = CloudAsk("dt", "production", url="https://api.cordon.test", transport=self.transport)
        sources = Sources(
            scan=lambda artifact: ScanEvidence(
                findings=(
                    FindingFact(
                        rule_id="POLICY.X.001", severity="low", confidence="high", category="policy"
                    ),
                )
            ),
            cloud=CloudDecisions.source(pins, NOW, ask),
            rules_version="rules-1",
        )
        resolvers = {"mcp_server": self.resolve}
        return CordonRuntime(local, resolvers=resolvers, sources=sources)

    def resolve(self, reference: str) -> Resolution:
        digest = ArtifactDigests.of_bytes(f"mcp_server:{reference}".encode())
        return Resolution(
            kind="mcp_server",
            subject_id="mcp/files",
            status="resolved",
            digest=digest,
            version=self.version,
        )

    def hook(self, retry_online: bool) -> tuple[str, str]:
        hook_input = {
            "session_id": "s",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": ADD},
        }
        answer = AgentHook.respond(
            self.runtime(),
            self.store,
            hook_input,
            NOW,
            environment="production",
            approver=APPROVER,
            retry_online=retry_online,
        )
        body = answer["hookSpecificOutput"]
        return body["permissionDecision"], body.get("permissionDecisionReason", "")

    def requests(self) -> list[dict[str, Any]]:
        return [json.loads(p.body) for p in self.store.pending() if p.kind == "approval-request"]

    @staticmethod
    def signed(
        decision: Decision,
        signer: Ed25519Signer,
        subject_id: str,
        digest: str,
        extra: tuple[dict[str, Any], ...],
        extra_first: bool,
    ) -> dict[str, Any]:
        """The decision's envelope, with other subjects in its statement when asked: signed by the same key, so only its content is wrong."""
        if not extra:
            return DecisionEnvelope.sign(decision, signer, subject_id=subject_id, digest=digest)
        statement = DecisionEnvelope.statement(decision, subject_id, digest)
        statement["subject"] = (
            [*extra, *statement["subject"]] if extra_first else [*statement["subject"], *extra]
        )
        body = ArtifactDigests.canonical_json(statement)
        signature = signer.sign(Dsse.pae(DecisionEnvelope.TYPE, body))
        return {
            "payloadType": DecisionEnvelope.TYPE,
            "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [
                {
                    "keyid": Dsse.keyid(signer.public),
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    def approved(
        self,
        signer: Ed25519Signer = DECIDER,
        *,
        policy: Any = None,
        extra_subjects: tuple[dict[str, Any], ...] = (),
        extra_first: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        """The platform's recorded answer once the approver has approved the digest: the decision it makes, signed."""
        call = AgentCalls.of(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": ADD}}
        )
        assert call is not None
        artifact = self.resolve(call.reference).artifact()
        evidence = EvidenceSet(
            findings=(
                FindingFact(
                    rule_id="POLICY.X.001", severity="low", confidence="high", category="policy"
                ),
            ),
            approvals=(
                Approval(
                    id="AP-1",
                    kind="approve",
                    expires_at=(NOW + timedelta(days=30)).isoformat(),
                    digests=(str(artifact.digest),),
                ),
            ),
        )
        decision: Decision = PointRuntime.ask(
            "agent_hook",
            artifact,
            evidence,
            policy or self.policy,
            NOW,
            actor="agent",
            environment="production",
        )
        envelope = self.signed(
            decision, signer, artifact.subject_id, str(artifact.digest), extra_subjects, extra_first
        )
        answer = {
            "index": 0,
            "subject": artifact.subject_id,
            "digest": artifact.digest,
            "state": decision.state,
            "reasons": list(decision.reason_codes),
            "decision_id": "dec-1",
            "envelope": envelope,
        }
        return 200, {"answers": [answer]}


class Fixtures:
    @pytest.fixture
    def flow(self, tmp_path: Path) -> Flow:
        return Flow(tmp_path)


class TestTheAgentAddsAnMcpServer(Fixtures):
    """BP-9-4."""

    def test_the_hook_decides_review_names_the_approver_and_a_ticket_and_queues_the_request(
        self, flow: Flow
    ) -> None:
        flow.answer = (404, {"error": "not_decided"})
        permission, reason = flow.hook(retry_online=True)
        (request,) = flow.requests()
        assert (
            permission == "deny"
            and "R700" in reason
            and APPROVER in reason
            and request["ticket"] in reason
        )
        assert (
            request["state"] == "REVIEW"
            and request["what"] == "add_mcp"
            and request["approver"] == APPROVER
        )
        assert "claude mcp" not in json.dumps(request)

    def test_asking_again_does_not_queue_a_second_request(self, flow: Flow) -> None:
        flow.answer = (404, {})
        flow.hook(retry_online=True)
        flow.hook(retry_online=True)
        assert len(flow.requests()) == 1


class TestTheApprovalArrives(Fixtures):
    """BP-9-5."""

    def test_the_retry_decides_allow_with_the_approval_as_its_reason_and_the_agent_proceeds(
        self, flow: Flow
    ) -> None:
        flow.answer = (404, {})
        assert flow.hook(retry_online=True)[0] == "deny"
        flow.answer = flow.approved()
        permission, _ = flow.hook(retry_online=True)
        assert permission == "allow"
        question = flow.asked[-1]
        assert (
            question["url"] == "https://api.cordon.test/v1/decide"
            and question["auth"] == "Bearer dt"
        )
        assert question["body"]["context"] == {
            "point": "agent_hook",
            "environment": "production",
            "actor": "agent:claude-code",
        }
        decision = DecisionEnvelope.verify(
            flow.approved()[1]["answers"][0]["envelope"],
            root_public=flow.platform.root.public,
            delegation=flow.delegation,
            tenant=TENANT,
            now=NOW,
        )["predicate"]
        assert decision["state"] == "ALLOW" and "R901" in decision["reason_codes"]

    def test_without_the_retry_the_call_stays_denied(self, flow: Flow) -> None:
        flow.answer = flow.approved()
        assert flow.hook(retry_online=False)[0] == "deny" and flow.asked == []

    def test_an_allowed_call_never_asks_the_platform(self, flow: Flow) -> None:
        flow.policy = Kit.compiled(1, flow.expires, on_incomplete={"*": "block"}, rules=[])
        flow.answer = flow.approved()
        assert flow.hook(retry_online=True)[0] == "allow" and flow.asked == []


class TestAnAnswerTheDeviceCannotTrustChangesNothing(Fixtures):
    @staticmethod
    def forged_by_edit(flow: Flow) -> tuple[int, dict[str, Any]]:
        status, body = flow.approved()
        envelope = body["answers"][0]["envelope"]
        envelope["payload"] = base64.b64encode(
            base64.b64decode(envelope["payload"]).replace(b"ALLOW", b"BLOCK")
        ).decode("ascii")
        return status, body

    def test_a_key_the_tenant_root_did_not_delegate(self, flow: Flow) -> None:
        flow.answer = flow.approved(STRANGER)
        assert flow.hook(retry_online=True)[0] == "deny"

    def test_an_edited_envelope(self, flow: Flow) -> None:
        flow.answer = self.forged_by_edit(flow)
        assert flow.hook(retry_online=True)[0] == "deny"

    def test_an_answer_about_another_digest(self, flow: Flow) -> None:
        status, body = flow.approved()
        body["answers"][0]["digest"] = ArtifactDigests.of_bytes(b"another")
        flow.answer = (status, body)
        assert flow.hook(retry_online=True)[0] == "deny"

    def test_a_decision_made_under_another_policy(self, flow: Flow) -> None:
        other = Kit.compiled(2, flow.expires, on_incomplete={"*": "block"}, rules=[])
        flow.answer = flow.approved(policy=other)
        assert flow.hook(retry_online=True)[0] == "deny"

    @pytest.mark.parametrize(
        "answer",
        [(500, {"error": "down"}), (200, {"answers": []}), (200, {}), (401, {"error": "token"})],
    )
    def test_an_error_or_an_empty_answer(
        self, flow: Flow, answer: tuple[int, dict[str, Any]]
    ) -> None:
        flow.answer = answer
        assert flow.hook(retry_online=True)[0] == "deny"

    def test_a_platform_that_cannot_be_reached(self, flow: Flow) -> None:
        from cordon_scanner.cloud import CloudError

        flow.answer = CloudError("could not reach api.cordon.test")
        assert flow.hook(retry_online=True)[0] == "deny"


class TestWhatTheDeviceAsksAndTakes(Fixtures):
    OTHER: ClassVar[dict[str, Any]] = {"name": "mcp/other", "digest": {"sha256": "0" * 64}}

    def test_the_question_carries_the_subject_the_version_and_the_digest(self, flow: Flow) -> None:
        flow.version = "1.4.2"
        flow.answer = flow.approved()
        flow.hook(retry_online=True)
        digest = flow.resolve("x").digest
        assert [a["version"] for a in flow.asked[-1]["body"]["artifacts"]] == ["1.4.2"]
        assert flow.asked[-1]["body"]["artifacts"][0]["subject"] == "mcp/files"
        assert flow.asked[-1]["body"]["artifacts"][0]["digest"].startswith("sha256:") and digest

    def test_a_server_with_no_known_version_is_asked_about_with_an_empty_one(
        self, flow: Flow
    ) -> None:
        flow.answer = flow.approved()
        flow.hook(retry_online=True)
        assert flow.asked[-1]["body"]["artifacts"][0]["version"] == ""

    @pytest.mark.parametrize("first", [False, True])
    def test_a_statement_about_more_than_the_one_subject_is_refused_even_when_one_matches(
        self, flow: Flow, first: bool
    ) -> None:
        flow.answer = flow.approved(extra_subjects=(self.OTHER,), extra_first=first)
        assert flow.hook(retry_online=True)[0] == "deny"
