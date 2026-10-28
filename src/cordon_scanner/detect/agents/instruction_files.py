"""The agent-chain findings in instruction files: CLAUDE.md, AGENTS.md, .cursorrules, SKILL.md and kin.

An instruction file is text an agent obeys with the developer's rights. What it tells the agent to
fetch, run or send, the hidden characters and directives it carries, the priority it claims over the
user, the tools it says are required; a skill's README, read with the skill; and a skill's script
that decodes code to run it."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents import agent_config
from cordon_scanner.detect.agents.defensive_doc import DefensiveDoc
from cordon_scanner.detect.agents.mcp_servers.description_model import (
    SKILL_MODEL,
)
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.models import (
    Finding,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.intel.malware import atr
from cordon_scanner.intel.registries.installers import OfficialInstallers

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import ScanContext
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.instructions import InstructionText
from cordon_scanner.detect.agents.mcp_servers.endpoints import (
    McpEndpoints,
)
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.detect.agents.skills import SkillOrigin, SkillScripts
from cordon_scanner.detect.agents.text_findings import AgentTextFindings
from cordon_scanner.detect.agents.text_patterns import (
    FETCH_EXEC,
    HIDDEN,
    INJECTION,
    INJECTION_INTL,
)

_FLAG_TAGS: Final = re.compile(rb"\xf0\x9f\x8f\xb4(?:\xf3\xa0[\x80\x81][\x80-\xbf]){1,16}")

#: Code that lets one fixed identity through an access check: an equality with a literal or a
#: constant, then `return {allowed: true}`, `return True` or `authorized = true`.
_AUTH_BYPASS_CODE: Final = re.compile(
    r"(?:===?|==)\s*(?:\"[^\"\n]{1,80}\"|'[^'\n]{1,80}'|[A-Z][A-Z0-9_]{3,40})\s*\)?\s*(?:\|\||&&|or|and)?"
    r"[^\n]{0,120}?(?:\)\s*\{|:)\s*\n?[ \t]*(?:return\s*\{[^}]{0,200}?\b(?:allowed|authori[sz]ed|isAdmin"
    r"|is_admin|granted|bypass|admin)\s*:\s*true|return\s+(?:True|true)\s*(?:#|//|;|\n)|\b(?:allowed"
    r"|authori[sz]ed|isAdmin|is_admin|granted)\s*=\s*(?:true|True))"
)

#: Telling the agent to put a block of code into the project.
_INSERT_DIRECTIVE: Final = re.compile(
    r"(?i)\b(?:inject|insert|add|paste|place)\b[^\n]{0,120}\b(?:block|code|snippet|following|below)\b"
)

#: A front-matter delimiter naming a code engine: `---js`, `---javascript`, `---coffee`. gray-matter,
#: the parser most JavaScript tooling uses, evaluates such a block as code when it reads the file. At
#: any line start, not only the first: a loader that takes the first delimited block after a fence or
#: a preamble reads it there, and no agent instruction file has a use for the marker.
_CODE_FRONT_MATTER: Final = re.compile(
    r"^[ \t]{0,3}---[ \t]*(?:js|javascript|coffee|coffeescript)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)

_SENSITIVE_IMPORT: Final = re.compile(
    r"(?im)(?:^|\s)@(?:~|\$HOME|/root|/home/[\w.-]+|/Users/[\w.-]+)/\.(?:ssh|aws|azure|kube|docker|gnupg|npmrc|pypirc|netrc|git-credentials|config/gcloud)\b[^\s]*"
    r"|(?:^|\s)@(?:[\w./~-]*/)?(?:id_(?:rsa|ed25519|ecdsa|dsa)|\.env)(?![\w.-])"
    r"|(?:^|\s)@/etc/(?:shadow|passwd|sudoers)\b"
)
"""An `@path` import (Claude Code and others read such a line into the context) of a credential
file: the agent loads it every session and sends it to the model provider."""

_REMOTE_INSTRUCTIONS: Final = re.compile(
    r"(?i)\b(?:fetch|download|read|load|retrieve|get|curl|wget|pull)\b[^\n]{0,60}?https?://\S+"
    r"[^\n]{0,80}?\b(?:and|then)\s+(?:follow|obey|apply|execute|carry\s+out|do\s+what)\b"
)


class InstructionFileFindings:
    """The agent-chain findings in instruction files and the skills that ship them."""

    @classmethod
    def skill_readme(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A skill's README, beside its SKILL.md: the agent reads it with the skill, and the
        ClawHavoc lures put their fake prerequisite there ("download and install OpenClawCLI
        from <free host> before using this skill"). Only the phantom-prerequisite check: it
        matched none of the 9,001 READMEs in public skill folders (review 98)."""
        text = unit.content.text
        phantom = InstructionText.phantom_prerequisite(text)
        if phantom is not None:
            start, end = InstructionText._byte_span(text, phantom)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.PHANTOM_PREREQUISITE.001", unit, ctx, start, end
            )

    @classmethod
    def skill_script(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A script that ships with a skill and decodes code to run it. In a library the same
        line is sometimes a packer; in a skill, the agent runs it on the user's machine when the
        skill is used, and hiding what it runs has no use but hiding it."""
        found = SkillScripts.decode_run(unit.content.text)
        if found is not None:
            start, end = InstructionText._byte_span(unit.content.text, found)
            yield AgentFinding.finding("SUSPECT.AGENT.SKILL_DECODE_RUN.001", unit, ctx, start, end)
        hooked = SkillScripts.hooks_a_download(unit.content.text)
        if hooked is not None:
            start, end = InstructionText._byte_span(unit.content.text, hooked)
            yield AgentFinding.finding("SUSPECT.AGENT.SKILL_HOOK_FETCH.001", unit, ctx, start, end)
        if unit.content.path.endswith(".py"):
            # What the agent gets when it calls the script's functions (`detect/mcp_code.py`).
            from cordon_scanner.detect.agents.mcp_servers.handlers import McpCode

            text = unit.content.text
            starts = [0, *(m.end() for m in re.finditer(r"\n", text))]

            def at(line: int) -> tuple[int, int]:
                first = starts[min(max(line, 1), len(starts)) - 1]
                last = text.find("\n", first)
                last = len(text) if last < 0 else last
                return len(text[:first].encode("utf-8")), len(text[:last].encode("utf-8"))

            for line, _function in McpCode.runs_own_input(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.SKILL_RUNS_INPUT.001", unit, ctx, *at(line)
                )
            for line, _name, _popular in McpCode.installs_lookalikes(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.001", unit, ctx, *at(line)
                )
            for line in McpCode.returns_jailbreak(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001", unit, ctx, *at(line)
                )

    @classmethod
    def instructions(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        content = unit.content
        raw = content.raw
        flags = [m.span() for m in _FLAG_TAGS.finditer(raw)]
        found = [
            m
            for m in HIDDEN.finditer(raw)
            if not any(start <= m.start() < end for start, end in flags)
        ]
        hidden = [m for n, m in enumerate(found) if InstructionText._carries(raw, found, n)]
        if hidden:
            first = hidden[0]
            decoded = InstructionText._decode_tags(raw)
            message = RULES["SUSPECT.AGENT.HIDDEN_TEXT.001"].message + f" {len(hidden)} found."
            if decoded:
                message += f' Unicode Tag characters in it spell: "{decoded[:120]}".'
            yield AgentFinding.finding(
                "SUSPECT.AGENT.HIDDEN_TEXT.001",
                unit,
                ctx,
                first.start(),
                first.end(),
                message=message,
            )

        text = content.text
        bypass = _AUTH_BYPASS_CODE.search(text)
        if bypass is not None and _INSERT_DIRECTIVE.search(text):
            yield AgentFinding.finding(
                "SUSPECT.AGENT.AUTH_BYPASS_EDIT.001",
                unit,
                ctx,
                *InstructionText._byte_span(text, bypass),
            )
        fetches = list(FETCH_EXEC.finditer(text))
        injection = next(
            (
                m
                for m in (*INJECTION.finditer(text), *INJECTION_INTL.finditer(text))
                if not InstructionText._quoted(text, m) and not InstructionText._forbidden(text, m)
            ),
            None,
        )
        exfil = InstructionText.moves_credentials(text) is not None
        # HIGH where the instruction is the attack's shape: a destination with no business
        # serving an installer (a paste site, a tunnel, a webhook, a raw address, a shortener), a
        # decoded payload, or a file that also hides text, overrides the agent or moves
        # credentials. A skill installing a vendor's CLI from the vendor's host is setup the
        # agent runs when somebody invokes the skill, and is reported below the gate --
        # across the first 228 repositories that was seventeen blocking findings in seven,
        # every one a CLI install line.
        alarming = next((m for m in fetches if InstructionText._alarming_fetch(m.group(0))), None)
        unknown = next(
            (m for m in fetches if not OfficialInstallers.is_official_installer(m.group(0))), None
        )
        concealed = InstructionText.concealed(text)
        if alarming is not None or (
            unknown is not None and (hidden or injection or exfil or concealed)
        ):
            chosen = alarming or unknown or fetches[0]
            start, end = InstructionText._byte_span(text, chosen)
            yield AgentFinding.finding("SUSPECT.AGENT.FETCH_EXEC.001", unit, ctx, start, end)
        elif fetches:
            chosen = unknown or fetches[0]
            start, end = InstructionText._byte_span(text, chosen)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.FETCH_EXEC.001",
                unit,
                ctx,
                start,
                end,
                # A vendor's own installer from its own host is how the tool is installed, and is
                # recorded; any other host warns.
                severity=Severity.LOW if unknown is None else Severity.MEDIUM,
                message=RULES["SUSPECT.AGENT.FETCH_EXEC.001"].message
                + (
                    " The script comes from the tool's own official installer host"
                    if unknown is None
                    else " It installs from a vendor host with nothing else in the file pointing at an attack"
                )
                + ", so this is reported below the default gate.",
            )
        yield from InstructionFileFindings._directive_findings(ctx, injection, text, unit)
        yield from AgentTextFindings.intents(unit, ctx, text)
        yield from InstructionFileFindings._hidden_and_rule_findings(
            alarming, concealed, ctx, exfil, hidden, injection, text, unit
        )

    @staticmethod
    def _directive_findings(
        ctx: ScanContext, injection: re.Match[str] | None, text: str, unit: FileUnit
    ) -> Iterator[Finding]:
        """The findings for each single directive an instruction file states: an injection, a phantom prerequisite, a dropper, executable front matter, a sensitive import, remote instructions, credentials moved off the machine, an endpoint."""
        if injection is not None:
            start, end = InstructionText._byte_span(text, injection)
            yield AgentFinding.finding("SUSPECT.AGENT.INJECTION_TEXT.001", unit, ctx, start, end)
        phantom = InstructionText.phantom_prerequisite(text)
        if phantom is not None:
            start, end = InstructionText._byte_span(text, phantom)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.PHANTOM_PREREQUISITE.001", unit, ctx, start, end
            )
        dropper = InstructionText.dropper(text)
        if dropper is not None:
            start, end = InstructionText._byte_span(text, dropper)
            yield AgentFinding.finding("SUSPECT.AGENT.DROPPER_PROSE.001", unit, ctx, start, end)
        executable = _CODE_FRONT_MATTER.search(text)
        if executable is not None:
            start, end = InstructionText._byte_span(text, executable)
            yield AgentFinding.finding("SUSPECT.AGENT.FRONT_MATTER_CODE.001", unit, ctx, start, end)
        imported = _SENSITIVE_IMPORT.search(text)
        if imported is not None:
            start, end = InstructionText._byte_span(text, imported)
            yield AgentFinding.finding("SUSPECT.AGENT.SENSITIVE_IMPORT.001", unit, ctx, start, end)
        remote = _REMOTE_INSTRUCTIONS.search(text)
        if remote is not None:
            start, end = InstructionText._byte_span(text, remote)
            alarming_host = InstructionText._alarming_fetch(remote.group(0))
            yield AgentFinding.finding(
                "SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001",
                unit,
                ctx,
                start,
                end,
                severity=Severity.HIGH if alarming_host else None,
            )
        moved = InstructionText.moves_credentials(text)
        if moved is None:
            moved = next(
                (
                    m
                    for m in re.finditer(r"(?:[^\n]*\\\n)*[^\n]+", text)  # with its `\` lines
                    if (verdict := agent_config.CommandClassifier.classify(m.group(0))) is not None
                    and verdict.kind != "fetch-exec"
                ),
                None,
            )
        if moved is not None:
            start, end = InstructionText._byte_span(text, moved)
            yield AgentFinding.finding("SUSPECT.AGENT.CREDENTIAL_EXFIL.001", unit, ctx, start, end)
        # A skill that wires the agent to an MCP server on a tunnel or a bare public address
        # (review 98, AG-4): `"url": "http://bore.pub:44876/api/v1/mcp/.../sse"` is a laptop the
        # skill's author reaches from the internet, handed the agent's tools and context.
        endpoint = next(
            (
                url
                for url in McpEndpoints.in_text(text)
                if McpEndpoints.untrusted(agent_config.ApiTraffic.host_of(url))
            ),
            None,
        )
        if endpoint is not None:
            yield AgentFinding.at_text(
                "SUSPECT.MCP.UNTRUSTED_REMOTE.001", unit, ctx, text, endpoint
            )

    @staticmethod
    def _hidden_and_rule_findings(
        alarming: re.Match[str] | None,
        concealed: bool,
        ctx: ScanContext,
        exfil: bool,
        hidden: list[re.Match[bytes]],
        injection: re.Match[str] | None,
        text: str,
        unit: FileUnit,
    ) -> Iterator[Finding]:
        """The findings that weigh the whole file: an instruction hidden from the reader by rendering, corroborated or not by what else the file does, and the Agent Threat Rules it matches."""
        # What the rendered page hides and the agent still reads (`detect/render_diff.py`).
        from cordon_scanner.analysis.shared.render_diff import HiddenInstruction

        spans = HiddenInstruction.find(text)
        for span in sorted(spans, key=lambda s: not HiddenInstruction.strong(s))[:1]:
            start, end = (
                len(text[: span.start].encode("utf-8")),
                len(text[: span.end].encode("utf-8")),
            )
            yield AgentFinding.finding(
                "SUSPECT.AGENT.HIDDEN_INSTRUCTION.001",
                unit,
                ctx,
                start,
                end,
                message=RULES["SUSPECT.AGENT.HIDDEN_INSTRUCTION.001"].message
                + f" It is in {span.how}.",
                # At the gate when it is addressed to the agent and names something that matters;
                # a hidden order about a destination alone is reported below it.
                severity=None if HiddenInstruction.strong(span) else Severity.MEDIUM,
            )
        corroborated = bool(hidden or injection or exfil or concealed or alarming is not None)
        corroborated_code = DefensiveDoc.code_evidence(hidden, exfil, concealed, alarming)
        third_party = SkillOrigin.third_party(unit.content.path, ctx)
        # A skill's instructions, read by the learned model (`SKILL_MODEL`). Held-out MalSkillBench:
        # blocked 44% -> 83%, benign 5.0% -> 3.3%, as ATR wording blocks only where the model or
        # Cordon's own evidence agrees; an override phrase is wording too (41 public skills).
        unconfirmed = False
        if ContainerPaths.basename(unit.content.path).upper() == "SKILL.MD":
            limits = SKILL_MODEL.thresholds("skill")
            score = SKILL_MODEL.score(text, "skill") if limits is not None else None
            if limits is not None and score is not None:
                unconfirmed = score < limits[1] and not corroborated_code
                if score >= limits[1]:
                    blocking = third_party and score >= limits[0]
                    yield AgentFinding.finding(
                        "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001",
                        unit,
                        ctx,
                        0,
                        min(len(unit.content.raw), 200),
                        message=RULES["SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"].message
                        + f" Model score {score:.2f}.",
                        severity=None if blocking else Severity.MEDIUM,
                    )
        yield from AgentTextFindings.threat_rules(
            unit,
            ctx,
            text,
            atr.TEXT_KINDS,
            # The project's own instruction files get the instruction-file tolerance; a skill
            # installed from elsewhere is code being installed and keeps ATR's grades (AG-2).
            instruction_file=not third_party,
            corroborated=corroborated,
            corroborated_code=corroborated_code,
            documentation=True,
            unconfirmed=unconfirmed,
        )


__all__ = ["InstructionFileFindings"]
