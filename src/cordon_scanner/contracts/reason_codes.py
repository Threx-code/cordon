"""The reason codes a decision carries (design spec 5.5): stable, documented, never reused.

A code is a promise to every consumer of a decision: a console, a policy author, an auditor, a
customer's pipeline. Its number and its name never change and a retired code is never given to another
meaning; a new meaning takes a new number. The registry is closed -- `ReasonCodes.lookup` refuses a
code that is not listed -- and `tests/unit/contracts/reason_codes.golden.json` records every code ever
issued, so a removal or a rename fails a test.

```
  R1xx  hard stops        no approval or exception lifts them
  R2xx  incompleteness    the evidence needed is missing, stale or unverifiable (invariant I4)
  R3xx  quality guard     a content rule in an ecosystem not yet measured (I10)
  R4xx  content findings  what the scanner found in the artifact
  R5xx  provenance        who built it, who signed it, how new it is
  R6xx  AI component      MCP tool poisoning, skill attacks, capability, model provider
  R7xx  workflow          approvals and exceptions
  R9xx  allow reasons     why something was allowed
```
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar, Final

_CODE: Final = re.compile(r"R[1-9][0-9]{2}")


@dataclass(frozen=True, slots=True)
class ReasonCode:
    """One reason code: its number, its name and what it says."""

    code: str
    name: str
    group: str
    #: A few words for a heading.
    title: str
    #: How serious the code reads on a screen (`info` to `critical`). For display only: the decision
    #: comes from policy, never from this.
    severity: str
    meaning: str
    #: Whether a decision with this code can be lifted by an approval or an exception. R1xx never.
    overridable: bool = True


class ReasonCodes:
    """The registry. Never edited in place: a code is added, never changed or removed."""

    GROUPS: ClassVar[dict[str, str]] = {
        "R1": "hard stop",
        "R2": "incompleteness",
        "R3": "quality guard",
        "R4": "content finding",
        "R5": "provenance and source",
        "R6": "AI component",
        "R7": "workflow",
        "R9": "allow reason",
    }

    SEVERITIES: ClassVar[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

    ALL: ClassVar[tuple[ReasonCode, ...]] = (
        ReasonCode(
            "R100",
            "known_malware",
            "R1",
            "Known malware",
            "critical",
            "known malware for this digest (intelligence)",
            False,
        ),
        ReasonCode(
            "R101",
            "revoked",
            "R1",
            "Revoked",
            "critical",
            "the artifact was revoked by Cordon or by the tenant",
            False,
        ),
        ReasonCode(
            "R102",
            "integrity_mismatch",
            "R1",
            "Integrity mismatch",
            "critical",
            "the digest is not what the registry or the lock claims",
            False,
        ),
        ReasonCode(
            "R103",
            "tenant_kill_list",
            "R1",
            "On the kill list",
            "critical",
            "the subject is on the tenant's kill list",
            False,
        ),
        ReasonCode(
            "R200",
            "evidence_missing",
            "R2",
            "Evidence missing",
            "high",
            "required evidence is missing",
            True,
        ),
        ReasonCode(
            "R201",
            "intelligence_stale",
            "R2",
            "Intelligence stale",
            "high",
            "the intelligence is older than the policy allows",
            True,
        ),
        ReasonCode(
            "R202",
            "policy_bundle_expired",
            "R2",
            "Policy bundle expired",
            "high",
            "the policy bundle has expired",
            True,
        ),
        ReasonCode(
            "R203",
            "subject_unresolved",
            "R2",
            "Subject unresolved",
            "high",
            "the subject or its version could not be resolved",
            True,
        ),
        ReasonCode(
            "R204",
            "scan_incomplete",
            "R2",
            "Scan incomplete",
            "high",
            "the scan did not complete (fail closed)",
            True,
        ),
        ReasonCode(
            "R205",
            "provenance_unverifiable",
            "R2",
            "Provenance unverifiable",
            "high",
            "provenance is present but cannot be verified",
            True,
        ),
        ReasonCode(
            "R300",
            "unmeasured_content_rule",
            "R3",
            "Rule not yet measured",
            "low",
            "a content rule in an ecosystem the policy marks warn until measured",
            True,
        ),
        ReasonCode(
            "R400",
            "malicious_behaviour",
            "R4",
            "Malicious behaviour",
            "critical",
            "malicious behaviour found in the content",
            True,
        ),
        ReasonCode(
            "R401",
            "suspicious_behaviour",
            "R4",
            "Suspicious behaviour",
            "high",
            "suspicious behaviour found in the content",
            True,
        ),
        ReasonCode(
            "R402",
            "secret_exposure",
            "R4",
            "Secret exposed",
            "high",
            "a secret is exposed in the content",
            True,
        ),
        ReasonCode(
            "R403",
            "vulnerable_exploited",
            "R4",
            "Exploited vulnerability",
            "critical",
            "a vulnerability known to be exploited",
            True,
        ),
        ReasonCode(
            "R404",
            "vulnerable_known",
            "R4",
            "Known vulnerability",
            "medium",
            "a known vulnerability",
            True,
        ),
        ReasonCode(
            "R405",
            "licence_policy",
            "R4",
            "Licence not allowed",
            "medium",
            "a licence the policy does not allow",
            True,
        ),
        ReasonCode(
            "R500",
            "provenance_level_low",
            "R5",
            "Provenance too low",
            "medium",
            "below the provenance level the policy requires",
            True,
        ),
        ReasonCode(
            "R501",
            "unsigned_or_signer_not_allowed",
            "R5",
            "Unsigned or signer not allowed",
            "medium",
            "unsigned, or the signer is not allowed",
            True,
        ),
        ReasonCode(
            "R502",
            "new_publisher",
            "R5",
            "New publisher",
            "low",
            "a publisher new to the registry",
            True,
        ),
        ReasonCode(
            "R503",
            "release_too_young",
            "R5",
            "Release too young",
            "low",
            "released more recently than the policy allows",
            True,
        ),
        ReasonCode(
            "R504",
            "lookalike_name",
            "R5",
            "Lookalike name",
            "high",
            "a name that looks like a popular one",
            True,
        ),
        ReasonCode(
            "R505",
            "registry_not_allowed",
            "R5",
            "Registry not allowed",
            "medium",
            "a registry the policy does not allow",
            True,
        ),
        ReasonCode(
            "R600",
            "mcp_tool_poisoning",
            "R6",
            "MCP tool poisoning",
            "critical",
            "an MCP tool description that steers the agent",
            True,
        ),
        ReasonCode(
            "R601",
            "skill_instruction_attack",
            "R6",
            "Skill instruction attack",
            "critical",
            "a skill whose instructions attack the agent or the user",
            True,
        ),
        ReasonCode(
            "R602",
            "excessive_capability",
            "R6",
            "Excessive capability",
            "high",
            "a capability beyond what the component declares",
            True,
        ),
        ReasonCode(
            "R603",
            "model_or_provider_not_approved",
            "R6",
            "Model or provider not approved",
            "medium",
            "a model or provider that is not approved",
            True,
        ),
        ReasonCode(
            "R604",
            "tool_list_changed",
            "R6",
            "Tool list changed",
            "high",
            "the remote MCP server's tool list changed since approval",
            True,
        ),
        ReasonCode(
            "R700",
            "approval_required",
            "R7",
            "Approval required",
            "info",
            "policy requires an approval",
            True,
        ),
        ReasonCode(
            "R701",
            "approval_expired",
            "R7",
            "Approval expired",
            "info",
            "the approval has expired",
            True,
        ),
        ReasonCode(
            "R702",
            "exception_active",
            "R7",
            "Exception active",
            "info",
            "an exception is active",
            True,
        ),
        ReasonCode(
            "R703",
            "conditions_apply",
            "R7",
            "Conditions apply",
            "info",
            "allowed with conditions",
            True,
        ),
        ReasonCode(
            "R900",
            "allowed_by_policy",
            "R9",
            "Allowed by policy",
            "info",
            "allowed by policy",
            True,
        ),
        ReasonCode(
            "R901", "approved_digest", "R9", "Approved", "info", "approved for this digest", True
        ),
        ReasonCode(
            "R902",
            "tenant_allow_list",
            "R9",
            "On the allow list",
            "info",
            "on the tenant's allow list",
            True,
        ),
        ReasonCode(
            "R903",
            "no_findings_above_threshold",
            "R9",
            "Nothing above the threshold",
            "info",
            "no finding above the policy's threshold",
            True,
        ),
    )

    #: Codes that were issued and are withdrawn. A retired code stays here, and is never listed in ALL.
    RETIRED: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def lookup(cls, code: str) -> ReasonCode:
        """The registered reason code `code`; a code that is not registered is an error."""
        for entry in cls.ALL:
            if entry.code == code:
                return entry
        raise KeyError(f"{code!r} is not a registered reason code")

    @classmethod
    def is_registered(cls, code: str) -> bool:
        return any(entry.code == code for entry in cls.ALL)

    @classmethod
    def in_group(cls, group: str) -> tuple[ReasonCode, ...]:
        return tuple(entry for entry in cls.ALL if entry.group == group)

    @classmethod
    def problems(cls) -> list[str]:
        """What is wrong with the registry itself; empty when it is sound: a malformed or duplicated code or
        name, a code in the wrong group, a retired code in use, a hard stop that can be overridden."""
        found: list[str] = []
        seen_codes: set[str] = set()
        seen_names: set[str] = set()
        for entry in cls.ALL:
            if _CODE.fullmatch(entry.code) is None:
                found.append(f"{entry.code}: not a reason code")
            if entry.code[:2] != entry.group:
                found.append(f"{entry.code}: is not in group {entry.group}")
            if entry.group not in cls.GROUPS:
                found.append(f"{entry.code}: unknown group {entry.group}")
            if entry.code in seen_codes or entry.name in seen_names:
                found.append(f"{entry.code}: code or name issued twice")
            if entry.code in cls.RETIRED:
                found.append(f"{entry.code}: retired and listed")
            if entry.severity not in cls.SEVERITIES:
                found.append(f"{entry.code}: unknown severity {entry.severity}")
            if entry.group == "R1" and entry.overridable:
                found.append(f"{entry.code}: a hard stop cannot be overridable")
            seen_codes.add(entry.code)
            seen_names.add(entry.name)
        return found


__all__ = ["ReasonCode", "ReasonCodes"]
