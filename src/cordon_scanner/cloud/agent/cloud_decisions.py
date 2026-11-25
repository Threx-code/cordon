"""The platform's decision for an artifact, asked at the agent hook after a local denial (flow 9.3): how an approval reaches the retry.

A call the policy sends to review or blocks is denied and an approval request is queued. When an approver approves that digest, the
platform's next decision for it is an ALLOW with the approval as its reason (R901). The device cannot learn that from its own bundle,
so the hook, after a local denial, asks `POST /v1/decide` once; the answer is taken only as a signed decision: a DSSE envelope that a
key delegated for a decision role signed, for this very subject and digest, under the tenant root the device pinned. An answer that
does not verify, an unreachable platform or any refusal is no answer, and the local denial stands. The runtime uses a platform decision
only when it was made under the policy the device holds (`Gatherer`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.cloud import CloudEndpoint, CloudError
from cordon_scanner.cloud.agent.decision_envelope import DecisionEnvelope
from cordon_scanner.cloud.bundle_chain import BundleError
from cordon_scanner.cloud.transport import CloudTransport, Transport
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.decision.records import DecisionError

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from cordon_scanner.decide.decision.evidence import ArtifactRef


@dataclass(frozen=True, slots=True)
class CloudAsk:
    """How a device asks the platform: its token and base URL, the environment it decides for and the agent product it speaks for."""

    token: str
    environment: str
    url: str | None = None
    product: str = "claude-code"
    transport: Transport | None = None


class CloudDecisions:
    POINT: ClassVar[str] = "agent_hook"

    @classmethod
    def source(
        cls,
        pins: tuple[bytes, Any, str],
        now: datetime,
        ask: CloudAsk,
        decision_delegation: object = None,
    ) -> Callable[[ArtifactRef], Decision | None]:
        """A decision source for the runtime: the verified platform decision for an artifact, or None.

        Under a root the customer holds, `decision_delegation` is the one the policy key signed (kept by the bundle puller): a decision
        verifies through it. Without one, a decision key the root did not name itself is not trusted."""
        root, delegation, tenant = pins

        def decide(artifact: ArtifactRef) -> Decision | None:
            if artifact.digest is None:
                return None
            try:
                response = CloudTransport.request(
                    "POST",
                    f"{CloudEndpoint.base_url(ask.url)}/v1/decide",
                    json_body=cls.question(artifact, ask),
                    token=ask.token,
                    transport=ask.transport,
                )
                if response.status != 200:
                    return None
                statement = DecisionEnvelope.verify(
                    cls.envelope(response.body, artifact),
                    root_public=root,
                    delegation=delegation,
                    tenant=tenant,
                    now=now,
                    decision_delegation=decision_delegation,
                )
                return cls.decision(statement, artifact)
            except (CloudError, BundleError, DecisionError, ValueError, KeyError, TypeError):
                # S2: an answer the device cannot trust is no answer; the local decision stands.
                return None

        return decide

    @classmethod
    def question(cls, artifact: ArtifactRef, ask: CloudAsk) -> dict[str, Any]:
        return {
            "artifacts": [
                {
                    "subject": artifact.subject_id,
                    "version": artifact.version or "",
                    "digest": artifact.digest,
                }
            ],
            "context": {
                "point": cls.POINT,
                "environment": ask.environment,
                "actor": f"agent:{ask.product}",
            },
            "mode": "cached_only",
        }

    @staticmethod
    def envelope(body: dict[str, Any], artifact: ArtifactRef) -> object:
        """The envelope of the answer to the one artifact asked about."""
        answers = body["answers"]
        if len(answers) != 1 or answers[0].get("digest") != artifact.digest:
            raise ValueError("the answer is not about the artifact asked")
        return answers[0]["envelope"]

    @staticmethod
    def decision(statement: dict[str, Any], artifact: ArtifactRef) -> Decision:
        subject = statement["subject"]
        algorithm, _, value = str(artifact.digest).partition(":")
        if (
            len(subject) != 1
            or subject[0]["name"] != artifact.subject_id
            or subject[0]["digest"] != {algorithm: value}
        ):
            raise ValueError("the decision is about another subject or digest")
        return Decision.from_json(statement["predicate"])


__all__ = ["CloudAsk", "CloudDecisions"]
