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

    ALL: ClassVar[tuple[ReasonCode, ...]] = (
        ReasonCode(
            "R100", "known_malware", "R1", "known malware for this digest (intelligence)", False
        ),
        ReasonCode(
            "R101", "revoked", "R1", "the artifact was revoked by Cordon or by the tenant", False
        ),
        ReasonCode(
            "R102",
            "integrity_mismatch",
            "R1",
            "the digest is not what the registry or the lock claims",
            False,
        ),
        ReasonCode(
            "R103", "tenant_kill_list", "R1", "the subject is on the tenant's kill list", False
        ),
        ReasonCode("R200", "evidence_missing", "R2", "required evidence is missing"),
        ReasonCode(
            "R201", "intelligence_stale", "R2", "the intelligence is older than the policy allows"
        ),
        ReasonCode("R202", "policy_bundle_expired", "R2", "the policy bundle has expired"),
        ReasonCode(
            "R203", "subject_unresolved", "R2", "the subject or its version could not be resolved"
        ),
        ReasonCode("R204", "scan_incomplete", "R2", "the scan did not complete (fail closed)"),
        ReasonCode(
            "R205", "provenance_unverifiable", "R2", "provenance is present but cannot be verified"
        ),
        ReasonCode(
            "R300",
            "unmeasured_content_rule",
            "R3",
            "a content rule in an ecosystem the policy marks warn until measured",
        ),
        ReasonCode("R400", "malicious_behaviour", "R4", "malicious behaviour found in the content"),
        ReasonCode(
            "R401", "suspicious_behaviour", "R4", "suspicious behaviour found in the content"
        ),
        ReasonCode("R402", "secret_exposure", "R4", "a secret is exposed in the content"),
        ReasonCode("R403", "vulnerable_exploited", "R4", "a vulnerability known to be exploited"),
        ReasonCode("R404", "vulnerable_known", "R4", "a known vulnerability"),
        ReasonCode("R405", "licence_policy", "R4", "a licence the policy does not allow"),
        ReasonCode(
            "R500", "provenance_level_low", "R5", "below the provenance level the policy requires"
        ),
        ReasonCode(
            "R501", "unsigned_or_signer_not_allowed", "R5", "unsigned, or the signer is not allowed"
        ),
        ReasonCode("R502", "new_publisher", "R5", "a publisher new to the registry"),
        ReasonCode(
            "R503", "release_too_young", "R5", "released more recently than the policy allows"
        ),
        ReasonCode("R504", "lookalike_name", "R5", "a name that looks like a popular one"),
        ReasonCode("R505", "registry_not_allowed", "R5", "a registry the policy does not allow"),
        ReasonCode(
            "R600", "mcp_tool_poisoning", "R6", "an MCP tool description that steers the agent"
        ),
        ReasonCode(
            "R601",
            "skill_instruction_attack",
            "R6",
            "a skill whose instructions attack the agent or the user",
        ),
        ReasonCode(
            "R602", "excessive_capability", "R6", "a capability beyond what the component declares"
        ),
        ReasonCode(
            "R603",
            "model_or_provider_not_approved",
            "R6",
            "a model or provider that is not approved",
        ),
        ReasonCode(
            "R604",
            "tool_list_changed",
            "R6",
            "the remote MCP server's tool list changed since approval",
        ),
        ReasonCode("R700", "approval_required", "R7", "policy requires an approval"),
        ReasonCode("R701", "approval_expired", "R7", "the approval has expired"),
        ReasonCode("R702", "exception_active", "R7", "an exception is active"),
        ReasonCode("R703", "conditions_apply", "R7", "allowed with conditions"),
        ReasonCode("R900", "allowed_by_policy", "R9", "allowed by policy"),
        ReasonCode("R901", "approved_digest", "R9", "approved for this digest"),
        ReasonCode("R902", "tenant_allow_list", "R9", "on the tenant's allow list"),
        ReasonCode(
            "R903", "no_findings_above_threshold", "R9", "no finding above the policy's threshold"
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
            if entry.group == "R1" and entry.overridable:
                found.append(f"{entry.code}: a hard stop cannot be overridable")
            seen_codes.add(entry.code)
            seen_names.add(entry.name)
        return found


__all__ = ["ReasonCode", "ReasonCodes"]
