"""What a blocked finding claims: malware, risky behaviour, or policy.

The block decision says *whether* a scan fails. This says *what the failure means*, so a reader can
tell a package that steals credentials from one that runs a downloader at install, and both from a
committed key. Both are blocked by default (owner, 2026-11-09: "yes I approve the label, blocking
unchanged"); only the name differs. Design: `reviews/pypi-98/16-HAZARD-LABEL.md`.

**Report-only**, and so it lives with the reporters. Nothing that decides a block reads this module:
not the policy gate, the baseline, the verdict model or its features, the configuration, nor the
severity floors, and the finding model does not carry it. A test asserts it by import.
`Category` cannot carry the claim, because `Category.MALICIOUS` is what fails by default
(`Policy.fail_on_categories`), so renaming a category would change which units block.

**From evidence, never from the package.** The scanner cannot know whether a package is
legitimate, so the claim names what the evidence shows:

* a **malware signal** is evidence of harm: concealment of the payload, theft or exfiltration, a
  drop point or command channel, known-bad intelligence, self-propagation, destruction;
* a **behaviour signal** is risky on its own and common in legitimate code: download and run,
  persistence, running received data, a listener, an environment gate, instruction text.

A unit whose blocking findings carry any malware signal claims `malware`. One blocked only by
secrets, vulnerabilities or provenance claims `policy`. Anything else blocked claims
`risky_behaviour`.

Signals come from a table keyed by rule-id prefix, matched in order like `Taxonomy`, and a test
asserts every declared rule resolves. A detector whose evidence is more specific than its rule may
add signals through evidence metadata (`SIGNALS_KEY`, comma-separated). It can never remove the
table's, so no detector can talk a finding down.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.models import Finding


class Signal(enum.StrEnum):
    """One class of evidence a finding carries."""

    # Malware signals: evidence of harm, not just of risk.
    CONCEAL = "conceal"
    THEFT = "theft"
    DROP_POINT = "drop_point"
    KNOWN_BAD = "known_bad"
    PROPAGATE = "propagate"
    DESTROY = "destroy"

    # Behaviour signals: risky, and common in legitimate code.
    FETCH_RUN = "fetch_run"
    PERSIST = "persist"
    EVAL_RECEIVED = "eval_received"
    EXPOSE = "expose"
    GATED = "gated"
    TEXT_ONLY = "text_only"
    RUNS_AT_INSTALL = "runs_at_install"


MALWARE_SIGNALS: frozenset[Signal] = frozenset(
    {
        Signal.CONCEAL,
        Signal.THEFT,
        Signal.DROP_POINT,
        Signal.KNOWN_BAD,
        Signal.PROPAGATE,
        Signal.DESTROY,
    }
)


class Claim(enum.StrEnum):
    """What a blocked unit, or one finding, claims."""

    MALWARE = "malware"
    RISKY_BEHAVIOUR = "risky_behaviour"
    POLICY = "policy"

    @property
    def text(self) -> str:
        """The words a person reads."""
        return {"malware": "malware", "risky_behaviour": "risky behaviour", "policy": "policy"}[
            self.value
        ]


SIGNALS_KEY = "signals"
"""Evidence metadata key a detector sets to add signals to one finding (comma-separated values)."""

_S = Signal

# Families that say where code comes from or what it exposes by accident, not what it does.
_POLICY_PREFIXES: tuple[str, ...] = (
    "SECRET.",
    "VULNERABLE.",
    "POLICY.",
    "SUSPECT.IAC.",
    "SUSPECT.CFN.",
    "SUSPECT.AZURE.",
    "SUSPECT.K8S.",
    "SUSPECT.HELM.",
    "SUSPECT.COMPOSE.",
    "SUSPECT.DOCKERFILE.",
    "SUSPECT.CI.",
    "SUSPECT.CONTAINER.",
    # D3 (lead, 2026-11-09): provenance and integrity.
    "SUSPECT.PACKAGE.NAME_RISK.",
    "SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.",
    "SUSPECT.PACKAGE.PROVENANCE.",
    "SUSPECT.PACKAGE.REPOSITORY.",
    "SUSPECT.PROVENANCE.",
    "SUSPECT.RELEASE.",
    "SUSPECT.SBOM.",
    "SUSPECT.SUBMODULE.",
    "SUSPECT.LOCKFILE.",
    "SUSPECT.REGISTRY.REVIEW.",
    "SUSPECT.RECIPE.",
    "SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.",
    "SUSPECT.BINARY.STRINGS.",
    "SUSPECT.BINARY.EXECUTABLE_PATH.",
    "SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.",
    "SUSPECT.DEPENDENCY.FOREIGN_COMMIT.",
    "SUSPECT.DEPENDENCY.LOCAL_SHADOW.",
    "SUSPECT.DEPENDENCY.PROVISIONAL.",
    "SUSPECT.DEPENDENCY.REMOVED_NAME.",
    "SUSPECT.DEPENDENCY.SOURCE",
    "SUSPECT.DEPENDENCY.UNVETTED.",
    "SUSPECT.DEPENDENCY.YANKED.",
    "SUSPECT.MCP.UNPINNED.",
    "SUSPECT.MCP.UNTRUSTED_REMOTE.",
    "SUSPECT.MCP.TOOLS_CHANGED.",
    "SUSPECT.AGENT.PLUGIN_SOURCE.",
    "SUSPECT.AGENT.ATR.MODEL_SECURITY.",
    # A file that stopped the rule engine before an answer: a fail-closed incomplete scan, which
    # claims neither malware nor behaviour (lead, 2026-11-09).
    "SUSPECT.RULEFILE.UNMATCHED.",
    # D3 boundary (lead, 2026-11-09): name similarity alone is not proof of deception.
    "SUSPECT.TYPOSQUAT.",
    "SUSPECT.DEPENDENCY.TYPOSQUAT.",
    "SUSPECT.DEPENDENCY.HALLUCINATED.",
    "SUSPECT.DEPENDENCY.CONFUSION.",
    "SUSPECT.DEPENDENCY.UNREGISTERED.",
    "SUSPECT.EXTENSION.LOOKALIKE.",
    "SUSPECT.MCP.LOOKALIKE.",
    "SUSPECT.MCP.BORROWED_NAME.",
)

# Ordered: a more specific prefix sits above any prefix of itself (a test refuses a dead entry).
_SIGNALS_BY_PREFIX: tuple[tuple[str, frozenset[Signal]], ...] = tuple(
    (prefix, frozenset(signals))
    for prefix, signals in (
        # Known-bad intelligence.
        ("MALWARE.PACKAGE.KNOWN.", {_S.KNOWN_BAD}),
        ("MALWARE.DEPENDENCY.KNOWN.", {_S.KNOWN_BAD}),
        ("MALWARE.EXTENSION.KNOWN.", {_S.KNOWN_BAD}),
        ("MALWARE.EXTENSION.REMOVED.", {_S.KNOWN_BAD}),
        ("MALWARE.RECIPE.KNOWN.", {_S.KNOWN_BAD}),
        ("MALWARE.DEPENDENCY.BUNDLED.", {_S.KNOWN_BAD}),
        ("MALWARE.CLAMAV.", {_S.KNOWN_BAD}),
        ("MALWARE.CODE.REUSE.", {_S.KNOWN_BAD}),
        ("MALWARE.RULEFILE.", {_S.KNOWN_BAD}),
        ("SUSPECT.RULEFILE.MATCH.", {_S.KNOWN_BAD}),
        ("SUSPECT.EXTENSION.REMOVED.", {_S.KNOWN_BAD}),
        ("SUSPECT.EXTENSION.MALICIOUS_VERSIONS.", {_S.KNOWN_BAD}),
        ("SUSPECT.CAMPAIGN.", {_S.KNOWN_BAD}),
        ("SUSPECT.MODEL.MALICIOUS_PACKAGE.", {_S.KNOWN_BAD}),
        # Theft and drop points.
        ("MALWARE.EXFIL.DROP_POINT.", {_S.THEFT, _S.DROP_POINT}),
        ("MALWARE.EXFIL.FLOW_TO_DROP.", {_S.THEFT, _S.DROP_POINT}),
        ("MALWARE.EXFIL.DNS_CALLBACK.", {_S.THEFT, _S.DROP_POINT}),
        ("MALWARE.EXFIL.HIDDEN_DESTINATION.", {_S.THEFT, _S.DROP_POINT, _S.CONCEAL}),
        ("MALWARE.EXFIL.", {_S.THEFT}),
        ("SUSPECT.EXFIL.DROP_POINT.", {_S.THEFT, _S.DROP_POINT}),
        ("SUSPECT.EXFIL.DNS.", {_S.THEFT, _S.DROP_POINT}),
        ("SUSPECT.EXFIL.", {_S.THEFT}),
        ("MALWARE.CI.SECRET_TO_DROP_POINT.", {_S.THEFT, _S.DROP_POINT}),
        ("MALWARE.CI.CREDENTIAL_HARVEST.", {_S.THEFT}),
        ("MALWARE.CI.RUNNER_SECRETS.", {_S.THEFT}),
        ("MALWARE.CI.SECRET_DUMP.", {_S.THEFT}),
        ("MALWARE.CI.SECRET_EXFIL.", {_S.THEFT}),
        ("MALWARE.CI.DECODED_PROGRAM.", {_S.CONCEAL}),
        ("MALWARE.CI.SCHEDULED_FETCH_EXEC.", {_S.FETCH_RUN}),
        ("MALWARE.AGENT.HOOK_EXFIL.", {_S.THEFT}),
        ("MALWARE.AGENT.HOOK_FETCH_EXEC.", {_S.FETCH_RUN}),
        ("MALWARE.AGENT.AUTORUN.", {_S.PERSIST}),
        ("MALWARE.AGENT.CONFIG_PLANTED.", {_S.PERSIST}),
        ("MALWARE.AGENT.HIJACK.", {_S.TEXT_ONLY}),
        ("MALWARE.ACCOUNT.", {_S.THEFT}),  # D5
        ("MALWARE.REVERSE_SHELL.", {_S.DROP_POINT}),
        ("MALWARE.CRYPTOMINER.", {_S.THEFT}),
        ("SUSPECT.CRYPTOMINER.", {_S.THEFT}),
        ("SUSPECT.BINARY.CREDENTIAL_THEFT.", {_S.THEFT}),
        ("SUSPECT.BINARY.KEYLOGGER.", {_S.THEFT}),
        ("SUSPECT.BINARY.CHAT_ENDPOINT.", {_S.THEFT}),
        ("SUSPECT.BINARY.NATIVE_PROGRAM_IN_PURE_WHEEL.", {_S.FETCH_RUN}),
        ("MALWARE.KEYLOGGER.", {_S.THEFT}),
        ("MALWARE.CLIPPER.", {_S.THEFT}),
        ("SUSPECT.MCP.SECRET_HARVEST.", {_S.THEFT}),
        ("SUSPECT.ARCHIVE.LINK_TO_SECRET.", {_S.THEFT}),
        ("SUSPECT.REGISTRY.SELF_PUBLISH.", {_S.PROPAGATE}),
        # Destruction (D1).
        ("SUSPECT.DESTROY.", {_S.DESTROY}),
        ("MALWARE.PROTESTWARE.", {_S.DESTROY}),
        # Concealment.
        ("MALWARE.DECODE_EXEC.", {_S.CONCEAL}),
        ("SUSPECT.DECODE_EXEC.", {_S.CONCEAL}),
        ("SUSPECT.EXECUTE.DECODED_BYTES.", {_S.CONCEAL}),
        ("SUSPECT.SOURCE.UNPARSED_RUNNING.", {_S.CONCEAL}),
        ("SUSPECT.DECODE_CHAIN.", {_S.CONCEAL}),
        ("MALWARE.DYNAMIC_DISPATCH.", {_S.CONCEAL}),
        ("SUSPECT.DYNAMIC_DISPATCH.", {_S.CONCEAL}),
        ("SUSPECT.OBFUSCATION.", {_S.CONCEAL}),
        ("MALWARE.INSTALL.DECODED_LAUNCH.", {_S.CONCEAL}),
        ("MALWARE.INSTALL.DISGUISED_PROGRAM.", {_S.CONCEAL}),
        ("MALWARE.INSTALL.HIDDEN_ACTION.", {_S.CONCEAL}),
        ("MALWARE.INSTALL.OPAQUE_CODE.", {_S.CONCEAL}),
        ("MALWARE.INSTALL.SHELL_EVASION.", {_S.CONCEAL}),
        ("MALWARE.INSTALL.SPELLED_CODE.", {_S.CONCEAL}),
        ("SUSPECT.INSTALL.OBFUSCATED_HOOK.", {_S.CONCEAL}),
        ("SUSPECT.INSTALL.STRING_CODE.", {_S.CONCEAL}),
        ("SUSPECT.FILE.DISGUISED_PROGRAM.", {_S.CONCEAL}),
        ("SUSPECT.MEDIA.", {_S.CONCEAL}),
        ("SUSPECT.ARCHIVE.", {_S.CONCEAL}),
        ("SUSPECT.POLYGLOT.", {_S.CONCEAL}),
        ("SUSPECT.BINARY.PACKED.", {_S.CONCEAL}),
        ("SUSPECT.BINARY.HIDDEN_IMPORTS.", {_S.CONCEAL}),
        ("SUSPECT.BINARY.IMPLANT.", {_S.CONCEAL}),
        ("SUSPECT.BINARY.PROCESS_INJECTION.", {_S.CONCEAL}),
        ("SUSPECT.EXTENSION.HIDDEN_NAME.", {_S.CONCEAL}),
        ("MALWARE.MOBILE.", {_S.CONCEAL}),
        # Deception in use (D3 boundary): confusion with install-time code, a borrowed star count,
        # a manifest that lies about the archive, a tool squatting another's name. Similarity
        # alone is in `_POLICY_PREFIXES`.
        ("SUSPECT.INSTALL.DEPENDENCY_CONFUSION.", {_S.CONCEAL}),
        ("SUSPECT.MCP.TOOL_SQUATTING.", {_S.CONCEAL}),
        ("SUSPECT.PACKAGE.STARJACKING.", {_S.CONCEAL}),
        ("SUSPECT.PACKAGE.MANIFEST_CONFUSION.", {_S.CONCEAL}),
        # Agent text and skills (package-37's mapping, §9).
        ("SUSPECT.AGENT.HIDDEN_TEXT.", {_S.CONCEAL}),
        ("SUSPECT.AGENT.HIDDEN_INSTRUCTION.", {_S.CONCEAL}),
        ("SUSPECT.AGENT.HIDDEN_DIRECTIVE.", {_S.CONCEAL}),
        ("SUSPECT.AGENT.SKILL_DISGUISED_ARCHIVE.", {_S.CONCEAL}),
        ("SUSPECT.AGENT.SKILL_DECODE_RUN.", {_S.CONCEAL}),
        ("SUSPECT.AGENT.DROPPER_PROSE.", {_S.CONCEAL, _S.FETCH_RUN}),
        ("SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.", {_S.CONCEAL}),
        ("SUSPECT.AGENT.CREDENTIAL_EXFIL.", {_S.THEFT}),
        ("SUSPECT.AGENT.ATR.CONTEXT_EXFILTRATION.", {_S.THEFT}),
        ("SUSPECT.AGENT.SENSITIVE_IMPORT.", {_S.THEFT}),
        ("SUSPECT.AGENT.API_REDIRECT.", {_S.DROP_POINT}),
        ("SUSPECT.AGENT.INSTALL_REDIRECT.", {_S.DROP_POINT}),
        ("SUSPECT.AGENT.FETCH_EXEC.", {_S.FETCH_RUN}),
        ("SUSPECT.AGENT.SKILL_HOOK_FETCH.", {_S.FETCH_RUN}),
        ("SUSPECT.AGENT.PHANTOM_PREREQUISITE.", {_S.FETCH_RUN}),
        ("SUSPECT.AGENT.SKILL_RUNS_INPUT.", {_S.EVAL_RECEIVED}),
        ("SUSPECT.AGENT.SKILL_LISTENER.", {_S.EXPOSE}),
        ("SUSPECT.AGENT.HOOK.", {_S.RUNS_AT_INSTALL}),
        ("SUSPECT.AGENT.FRONT_MATTER_CODE.", {_S.RUNS_AT_INSTALL}),
        ("SUSPECT.AGENT.", {_S.TEXT_ONLY}),
        # Download and run.
        ("MALWARE.DROPPER.", {_S.FETCH_RUN}),
        ("SUSPECT.DROPPER.", {_S.FETCH_RUN}),
        ("MALWARE.INSTALL.FETCH_EXEC.", {_S.FETCH_RUN}),
        ("MALWARE.INSTALL.REMOTE_CODE.", {_S.FETCH_RUN}),
        ("MALWARE.INSTALL.WINDOWS_LOADER.", {_S.FETCH_RUN}),
        ("MALWARE.INSTALL.GYP_COMMAND.", {_S.FETCH_RUN}),
        ("SUSPECT.BUILD.", {_S.FETCH_RUN}),
        ("SUSPECT.DOCUMENT.REMOTE_OBJECT.", {_S.FETCH_RUN}),
        ("SUSPECT.MCP.SHELL_LAUNCH.", {_S.FETCH_RUN}),
        ("MALWARE.DEPENDENCY.", {_S.FETCH_RUN}),
        ("SUSPECT.DEPENDENCY.REMOTE_TARBALL", {_S.FETCH_RUN}),
        ("SUSPECT.MODEL.REMOTE_CODE.", {_S.FETCH_RUN}),
        # Persistence.
        # Antivirus told to stop looking: concealment of what lands next.
        ("MALWARE.IMPLANT.AV_EXCLUSION.", {_S.CONCEAL}),
        ("MALWARE.IMPLANT.", {_S.FETCH_RUN, _S.PERSIST}),
        ("MALWARE.PERSIST.", {_S.PERSIST}),
        ("MALWARE.IMPORT.PERSIST.", {_S.PERSIST}),
        ("MALWARE.IMPORT.PROGRAM_START.", {_S.RUNS_AT_INSTALL}),
        ("MALWARE.IMPORT.FETCH_RUN.", {_S.FETCH_RUN, _S.RUNS_AT_INSTALL}),
        ("MALWARE.INSTALL.FETCH_RUN.", {_S.FETCH_RUN, _S.RUNS_AT_INSTALL}),
        ("MALWARE.INSTALL.PERSIST.", {_S.PERSIST}),
        ("MALWARE.INSTALL.BACKGROUND.", {_S.PERSIST}),
        ("SUSPECT.PERSIST.", {_S.PERSIST}),
        ("SUSPECT.INSTALL.AUTOSTART.", {_S.PERSIST}),
        ("SUSPECT.VCS.", {_S.PERSIST}),
        # Running what was received.
        ("MALWARE.MODEL.", {_S.EVAL_RECEIVED}),
        ("SUSPECT.MODEL.", {_S.EVAL_RECEIVED}),
        ("SUSPECT.MCP.HANDLER_SHELL.", {_S.EVAL_RECEIVED}),
        ("SUSPECT.MCP.INPUT_FORWARDED.", {_S.EVAL_RECEIVED}),
        ("SUSPECT.MCP.ENV_INJECTION.", {_S.EVAL_RECEIVED}),
        ("SUSPECT.DOCUMENT.", {_S.EVAL_RECEIVED}),
        # Exposure.
        ("SUSPECT.MCP.LISTENER.", {_S.EXPOSE}),
        ("SUSPECT.MCP.INSECURE_TRANSPORT.", {_S.EXPOSE}),
        ("SUSPECT.MCP.CONTAINER_HOST_ACCESS.", {_S.EXPOSE}),
        ("MALWARE.INSTALL.NETWORK_PROBE.", {_S.EXPOSE}),
        # Environment gates (D4).
        ("MALWARE.ANTI_ANALYSIS.", {_S.GATED}),
        ("SUSPECT.ANTI_ANALYSIS.", {_S.GATED}),
        ("SUSPECT.TARGETED_PAYLOAD.", {_S.GATED}),
        ("SUSPECT.MCP.TIME_BOMB.", {_S.GATED}),
        # Tool text.
        ("SUSPECT.MCP.", {_S.TEXT_ONLY}),
        # Runs at install, nothing more specific known.
        ("MALWARE.INSTALL.", {_S.RUNS_AT_INSTALL}),
        ("SUSPECT.INSTALL.", {_S.RUNS_AT_INSTALL}),
    )
)

# Verdicts from a model, with no evidence of their own (D2): no signal, so they never claim malware
# alone. Listed so the completeness test can tell them from a forgotten rule.
_NO_SIGNAL_PREFIXES: tuple[str, ...] = (
    "SUSPECT.VERDICT.",
    "SUSPECT.CODE.MODEL.",
    "SUSPECT.INTENT.",
)

_UNCLAIMED_PREFIXES: tuple[str, ...] = ("CAP.", "AST.", "OPERATIONAL.")


class Claims:
    """The claim of one finding, and of the findings that block a unit."""

    @staticmethod
    def is_policy_rule(rule_id: str) -> bool:
        return rule_id.startswith(_POLICY_PREFIXES)

    @staticmethod
    def table_signals(rule_id: str) -> frozenset[Signal]:
        """The signals the table gives a rule; empty for policy and no-signal rules."""
        if rule_id.startswith(_POLICY_PREFIXES):
            return frozenset()
        for prefix, signals in _SIGNALS_BY_PREFIX:
            if rule_id.startswith(prefix):
                return signals
        return frozenset()

    @staticmethod
    def added_signals(finding: Finding) -> frozenset[Signal]:
        """Signals a detector added to this finding. Unknown names are ignored, never fatal: a
        claim is a report, and a typo in one detector must not fail a scan."""
        known = {s.value for s in Signal}
        out: set[Signal] = set()
        for key, value in finding.evidence.metadata:
            if key == SIGNALS_KEY:
                out.update(Signal(v) for v in (p.strip() for p in value.split(",")) if v in known)
        return frozenset(out)

    @classmethod
    def signals_of(cls, finding: Finding) -> frozenset[Signal]:
        return cls.table_signals(finding.rule_id) | cls.added_signals(finding)

    @classmethod
    def of_finding(cls, finding: Finding) -> Claim | None:
        """What one finding claims; None for findings about the scan or capability inputs."""
        from cordon_scanner.foundation.models import Category

        if finding.category is Category.OPERATIONAL or finding.rule_id.startswith(
            _UNCLAIMED_PREFIXES
        ):
            return None
        signals = cls.signals_of(finding)
        if signals & MALWARE_SIGNALS:
            return Claim.MALWARE
        if cls.is_policy_rule(finding.rule_id) and not signals:
            return Claim.POLICY
        return Claim.RISKY_BEHAVIOUR

    @classmethod
    def of_unit(cls, blocking: Iterable[Finding]) -> Claim | None:
        """What a blocked unit claims, from the findings that block it: malware if any carries a
        malware signal, policy if every one is a policy rule, risky behaviour otherwise. None when
        nothing blocks."""
        claims = [c for c in (cls.of_finding(f) for f in blocking) if c is not None]
        if not claims:
            return None
        if Claim.MALWARE in claims:
            return Claim.MALWARE
        if all(c is Claim.POLICY for c in claims):
            return Claim.POLICY
        return Claim.RISKY_BEHAVIOUR


__all__ = ["MALWARE_SIGNALS", "SIGNALS_KEY", "Claim", "Claims", "Signal"]
