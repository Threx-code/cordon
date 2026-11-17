"""Agent skills: whether a skill is the project's own or installed from elsewhere, and the scripts that
ship with it.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.detect.agents.defensive_doc import DefensiveDoc
from cordon_scanner.foundation.formats.datayaml import DataYaml, DataYamlError
from cordon_scanner.foundation.models import Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.models import Finding


#: Scripts that ship with a skill, which the agent runs when the skill is used.
#: The events an agent runs a hook on (Claude Code, Codex, Gemini CLI, Cursor).
_HOOK_EVENT: Final = re.compile(
    r"\b(?:SessionStart|UserPromptSubmit|PreToolUse|PostToolUse|SessionEnd|beforeSubmitPrompt|"
    r"beforeShellExecution|afterFileEdit)\b"
)

#: A download piped straight into a shell or PowerShell.
_PIPED_DOWNLOAD: Final = re.compile(
    r"(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,300}\|\s*(?:iex|Invoke-Expression)\b"
)

#: A payload written into the script, encoded: a quoted run of base64, hex or the like. What makes
#: decoding suspicious is that the code run is fixed and unreadable; a command the script builds
#: and encodes for transport (`echo $cmd_b64 | base64 -d | bash` over a remote shell) is neither.
_ENCODED_LITERAL: Final = r"b?['\"][A-Za-z0-9+/=_\-\\x]{16,}['\"]"

_DECODER: Final = (
    r"(?:(?:[\w.]+\.)?(?:b64decode|b32decode|b85decode|a85decode|decodebytes|decompress|unhexlify|"
    r"fromhex|atob)|(?:marshal|pickle)\.loads)"
)

#: A decoder's call, its argument a literal or a name, captured as `arg`.
_DECODE_CALL: Final = re.compile(
    rf"\b{_DECODER}\s*\(\s*(?P<arg>{_ENCODED_LITERAL}|[A-Za-z_]\w{{0,40}})"
    r"|\bBuffer\.from\s*\(\s*(?P<jsarg>[^,)]{1,200}),\s*['\"]base64['\"]"
)
#: `_DECODE_CALL`'s three ways to match, in its order, read by `SkillScripts.decode_calls`: as one
#: expression, `\b(?:[\w.]+\.)?` read a dotted run again from every word start in it -- quadratic in
#: `.2.2.2...`, in a skill's scripts (review 98, 27-PERFORMANCE).
_DECODE_NAMED: Final = re.compile(
    r"\b(?:[\w.]+\.)?(?:b64decode|b32decode|b85decode|a85decode|decodebytes|decompress|unhexlify|"
    rf"fromhex|atob)\s*\(\s*(?P<arg>{_ENCODED_LITERAL}|[A-Za-z_]\w{{0,40}})"
)
_DECODE_LOADS: Final = re.compile(
    rf"\b(?:marshal|pickle)\.loads\s*\(\s*(?P<arg>{_ENCODED_LITERAL}|[A-Za-z_]\w{{0,40}})"
)
_DECODE_BUFFER: Final = re.compile(
    r"\bBuffer\.from\s*\(\s*(?P<arg>[^,)]{1,200}),\s*['\"]base64['\"]"
)
_DOTTED_RUN: Final = re.compile(r"[\w.]+")
#: A line assigning a name an encoded literal, and a call that executes a bare name: each read once
#: per text by `SkillScripts.decode_run` (`_encoded_names`, `_executions`).
_ASSIGNED_ENCODED: Final = re.compile(
    rf"(?m)^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w{{0,40}})\s*=\s*{_ENCODED_LITERAL}"
)
_EXECUTES_NAME: Final = re.compile(r"\b(?:exec|eval|Function)\s*\(\s*([A-Za-z_]\w*)\s*[,)]")
_BOUNDARY: Final = re.compile(r"\b")

#: A shell or PowerShell running an encoded literal.
_SHELL_DECODE_RUN: Final = re.compile(
    r"\becho\s+['\"]?[A-Za-z0-9+/=]{16,}['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)\b[^\n|]{0,40}\|\s*(?:ba|z|da)?sh\b"
    r"|(?i:\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,})"
)


class SkillOrigin:
    """Whether a skill is the project's own or installed from elsewhere (review 98, AG-2).

    A `SKILL.md` committed in the repository being scanned is the project's own instructions, and
    gets the tolerance written for its own CLAUDE.md. Any other skill -- inside an archive, under
    an installed or vendored folder, or scanned as a download rather than as a repository root --
    is third-party code being installed, and is graded like a tool description.
    """

    _INSTALLED: ClassVar[tuple[str, ...]] = (
        "node_modules/",
        "site-packages/",
        "/.cursor/extensions/",
        "/.vscode/extensions/",
        "vendor/",
        "third_party/",
    )

    @staticmethod
    def third_party(path: str, ctx: ScanContext) -> bool:
        if not path.lower().endswith("skill.md"):
            return False
        if "!" in path or any(part in path.lower() for part in SkillOrigin._INSTALLED):
            return True
        repository = ctx.repository
        return repository is None or not repository.scanned_repository_root


class SkillScripts:
    """Scripts that ship with an agent skill: files beside or below a SKILL.md."""

    @staticmethod
    def in_skill(path: str, ctx: ScanContext) -> bool:
        """Whether a SKILL.md sits in the script's directory or one of its three parents."""
        parts = path.replace("\\", "/").split("/")[:-1]
        for depth in range(len(parts), max(-1, len(parts) - 4), -1):
            candidate = "/".join([*parts[:depth], "SKILL.md"])
            if candidate in ctx.tree_paths:
                return True
        return False

    #: What an archive's first bytes are: zip (and every zip-based container), 7z, rar.
    ARCHIVE_MAGIC: ClassVar[tuple[bytes, ...]] = (b"PK\x03\x04", b"7z\xbc\xaf", b"Rar!")
    #: Names an archive or a zip-based container honestly goes by, beyond the document and model
    #: formats the readers already name (`OFFICE_SUFFIXES`, `PICKLE_SUFFIXES`).
    CONTAINER_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".zip", ".jar", ".war", ".ear", ".whl", ".egg", ".apk", ".aab", ".aar", ".xpi", ".crx",
        ".vsix", ".nupkg", ".ipa", ".epub", ".kmz", ".mcpack", ".skill", ".7z", ".rar",
        ".odt", ".ods", ".odp", ".odg", ".ppsx", ".potx", ".npz", ".keras", ".pages", ".numbers",
        ".key", ".cbz", ".cbr", ".sb3", ".xps", ".msix", ".appx", ".3mf", ".usdz",
    )  # fmt: skip

    @classmethod
    def disguised_archive(cls, path: str, raw: bytes) -> bool:
        """An archive under a name that says it is something else: a zip in `.instructions.docx.txt`
        or a dotfile. A skill's files are read by the agent as what they are named; one that is
        really an archive is there to be unpacked by an instruction, out of every reader's sight."""
        from cordon_scanner.analysis.formats.documents import OFFICE_SUFFIXES
        from cordon_scanner.analysis.formats.pickles import PICKLE_SUFFIXES

        name = path.replace("\\", "/").rpartition("/")[2].lower()
        honest = (*cls.CONTAINER_SUFFIXES, *OFFICE_SUFFIXES, *PICKLE_SUFFIXES)
        return raw.startswith(cls.ARCHIVE_MAGIC) and not name.endswith(honest)

    @staticmethod
    def beside_skill(path: str, ctx: ScanContext) -> bool:
        """Whether a SKILL.md sits in the same directory as this file."""
        directory = path.replace("\\", "/").rpartition("/")[0]
        return (
            f"{directory}/SKILL.md" in ctx.tree_paths if directory else "SKILL.md" in ctx.tree_paths
        )

    @staticmethod
    def hooks_a_download(text: str) -> re.Match[str] | None:
        """A script that writes an agent hook whose command pipes a download into a shell: from then
        on, every session the agent starts runs whatever that URL serves that day."""
        for event in _HOOK_EVENT.finditer(text):
            window = text[max(0, event.start() - 600) : event.end() + 600]
            piped = _PIPED_DOWNLOAD.search(window)
            if piped is not None:
                return _PIPED_DOWNLOAD.search(text, max(0, event.start() - 600))
        return None

    @staticmethod
    def decode_calls(text: str) -> Iterator[re.Match[str]]:
        r"""`_DECODE_CALL.finditer(text)`, each dotted run read once: the same matches, at the same
        places, with the argument as `arg` (`_DECODE_CALL`'s `arg` or `jsarg`).

        At each place `_DECODE_CALL` tries `_DECODE_NAMED`, then `_DECODE_LOADS`, then
        `_DECODE_BUFFER`. The last two start with a fixed word, so a search finds them. The first
        can only start in a run of `[\w.]`, and if it matches at a word start in a run it matches
        at the run's first boundary too, with a longer prefix -- which is where the search would
        have found it first -- unless that boundary is a `.` just before the word, too short to be
        a prefix (`[\w.]+\.`), so the word after it is tried as well. So each run is tried once,
        from that boundary, and the leftmost of the three is the match.
        """
        runs = [(m.start(), m.end()) for m in _DOTTED_RUN.finditer(text)]
        later: dict[re.Pattern[str], re.Match[str] | None] = {}
        position, index = 0, 0
        while position <= len(text):
            for pattern in (_DECODE_LOADS, _DECODE_BUFFER):
                found = later.get(pattern)
                if pattern not in later or (found is not None and found.start() < position):
                    later[pattern] = pattern.search(text, position)
            limit = min(
                (found.start() for found in later.values() if found is not None), default=len(text)
            )
            while index < len(runs) and runs[index][1] <= position:
                index += 1
            named = None
            for run in range(index, len(runs)):
                run_start, run_end = runs[run]
                begin = max(position, run_start)
                if begin > limit:
                    break
                boundary = _BOUNDARY.search(text, begin, run_end)
                if boundary is not None and boundary.start() < run_end:
                    first = boundary.start()
                    named = _DECODE_NAMED.match(text, first)
                    if named is None and text[first] == "." and first + 1 < run_end:
                        # A prefix is `[\w.]+\.`, two characters at least: from a boundary on a
                        # `.`, the word right after it is not covered, so it is tried too.
                        named = _DECODE_NAMED.match(text, first + 1)
                    if named is not None:
                        break
            candidates = [
                (found.start(), order, found)
                for order, found in enumerate((named, later[_DECODE_LOADS], later[_DECODE_BUFFER]))
                if found is not None
            ]
            if not candidates:
                return
            _, _, call = min(candidates, key=lambda c: (c[0], c[1]))
            yield call
            position = call.end()

    @staticmethod
    def decode_run(text: str) -> re.Match[str] | None:
        """An encoded payload written into the script, decoded and executed: inline
        (`exec(b64decode("..."))`), or decoded into a name that is then executed. The payload must
        be a literal, or a name assigned one, so a command the script builds and encodes for
        transport is not it."""
        line = re.compile(r"[^\n]+")
        shell = _SHELL_DECODE_RUN.search(text)
        if shell is not None:
            return shell
        assigned_names: set[str] | None = None
        runs_of: dict[str, list[int]] | None = None
        for call in SkillScripts.decode_calls(text):
            argument = (call.group("arg") or "").strip()
            if assigned_names is None:
                assigned_names = SkillScripts._encoded_names(text)
            if not SkillScripts._encoded(argument, assigned_names):
                continue
            start = text.rfind("\n", 0, call.start()) + 1
            before = text[start : call.start()]
            if re.search(r"\b(?:exec|eval|Function)\s*\(\s*$", before):
                return line.search(text, start)
            assigned = re.fullmatch(
                r"\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w{0,40})\s*=\s*", before
            )
            if assigned is None:
                continue
            if runs_of is None:
                runs_of = SkillScripts._executions(text)
            run = SkillScripts._first_execution(text, assigned.group(1), call.end(), runs_of)
            if run is not None:
                return line.search(text, run)
        return None

    @staticmethod
    def _encoded(argument: str, assigned_names: set[str]) -> bool:
        """Whether a decoder's argument is a fixed encoded payload: a literal, or a name the file
        assigns one (`_encoded_names`)."""
        if re.fullmatch(_ENCODED_LITERAL, argument):
            return True
        return bool(re.fullmatch(r"[A-Za-z_]\w{0,40}", argument)) and argument in assigned_names

    @staticmethod
    def _encoded_names(text: str) -> set[str]:
        r"""Every name a line of `text` assigns an encoded literal, read in one pass: the names for
        which `^\s*(?:const\s+|let\s+|var\s+)?NAME\s*=\s*LITERAL` (multiline) would match. Asked per
        decoder call, that search read the whole text again each time (review 98, 27-PERFORMANCE)."""
        return {m.group(1) for m in _ASSIGNED_ENCODED.finditer(text)}

    @staticmethod
    def _executions(text: str) -> dict[str, list[int]]:
        """Where `exec(`, `eval(` or `Function(` is called with a bare name, by that name, in order."""
        found: dict[str, list[int]] = {}
        for m in _EXECUTES_NAME.finditer(text):
            found.setdefault(m.group(1), []).append(m.start())
        return found

    @staticmethod
    def _first_execution(
        text: str, name: str, after: int, runs_of: dict[str, list[int]]
    ) -> int | None:
        r"""Where `\b(?:exec|eval|Function)\s*\(\s*NAME\s*[,)]` first matches in `text[after:]`, as a
        position in `text`. A slice starts at a word boundary, so a call that opens exactly at
        `after` counts even behind a word character; everywhere else the boundary is the text's."""
        if re.compile(rf"(?:exec|eval|Function)\s*\(\s*{re.escape(name)}\s*[,)]").match(
            text, after
        ):
            return after
        starts = runs_of.get(name, [])
        index = bisect.bisect_left(starts, after)
        return starts[index] if index < len(starts) else None


class SkillClaims:
    """What a third-party skill's front matter claims, and the acts its instructions carry that it
    does not (`SUSPECT.AGENT.SKILL_CLAIM_MISMATCH.001`, reviews/mcp-98/31).

    A skill's front matter is the claim its user approves; its instructions are what the agent then
    does. The acts are facts the file's own readers already report on their own, below the gate; the
    claim is read only to see whether the description announces them. It only ever adds: an act the
    description claims is graded exactly as before, and a claim cannot excuse an act that is hidden
    from the user.
    """

    #: The capability classes a description can claim. The vocabulary of the learned verdict's
    #: `skill_claims_*` facts (`VerdictFeatures.SKILL_CLAIM`, which `decide` may not be imported
    #: from here: a test holds the two equal).
    CLAIM: ClassVar[dict[str, re.Pattern[str]]] = {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in {
            "network": r"\b(?:api|http|web|url|download|upload|fetch|online|search|browse|"
            r"webhook|slack|github|notion|google|cloud|server|service|remote|sync)\b",
            "credentials": r"\b(?:token|key|secret|credential|password|auth|oauth|login|"
            r"wallet|keychain|ssh|vault)\b",
            "shell": r"\b(?:shell|terminal|command|install|deploy|docker|kubectl|git|run|"
            r"execute|script|process|system|automation)\b",
            "files": r"\b(?:file|folder|directory|document|pdf|csv|excel|image|disk|backup)\b",
        }.items()
    }
    #: What a tool named in `allowed-tools` declares, beside the prose: a structural claim.
    TOOL_CLAIM: ClassVar[dict[str, str]] = {
        "bash": "shell",
        "shell": "shell",
        "powershell": "shell",
        "webfetch": "network",
        "websearch": "network",
        "read": "files",
        "write": "files",
        "edit": "files",
        "multiedit": "files",
        "glob": "files",
        "grep": "files",
        "notebookedit": "files",
    }
    #: The finding of a reader that is an act, and the act it is.
    ACT_RULE: ClassVar[dict[str, str]] = {
        "SUSPECT.AGENT.FETCH_EXEC.001": "fetch_run",
        "SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001": "remote_instructions",
    }
    #: The claim an act needs. An act that is concealed needs one nobody can make.
    REQUIRES: ClassVar[dict[str, str]] = {
        "fetch_run": "shell",
        "remote_instructions": "network",
    }
    #: What a skill with no declared description is read as: `unknown` (no check, except an act that
    #: is concealed, which no claim could excuse) or `nothing` (it claims no class at all).
    NO_DESCRIPTION: ClassVar[str] = "unknown"
    #: Findings the learned skill reading made: at or above its warn line, a quoted example is not
    #: lowered (`DefensiveDoc.lowers`).
    SKILL_MODEL_RULE: Final = "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"
    MAX_FRONT_MATTER: ClassVar[int] = 20_000
    _CLOSE: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^---[ \t]*\r?$")
    _TOOL_NAME: ClassVar[re.Pattern[str]] = re.compile(r"[\w-]{1,60}")

    @staticmethod
    def front_matter(text: str) -> dict[str, Any] | None:
        """The leading `---` block read as YAML (hostile-input reader: no anchors, bounded depth),
        or None when there is none or it is not a mapping."""
        if not text.startswith(("---\n", "---\r\n")):
            return None
        close = SkillClaims._CLOSE.search(text, 3)
        if close is None or close.start() > SkillClaims.MAX_FRONT_MATTER:
            return None
        try:
            loaded = DataYaml.load(text[3 : close.start()], source="SKILL.md")
        except DataYamlError:
            return None
        return loaded if isinstance(loaded, dict) else None

    @staticmethod
    def claimed(front: dict[str, Any]) -> frozenset[str] | None:
        """The classes the front matter claims, or None when it declares no description."""
        description = front.get("description")
        if not isinstance(description, str) or not description.strip():
            return None
        name = front.get("name")
        said = f"{name if isinstance(name, str) else ''} {description[:4_000]}"
        said = said.replace("-", " ").replace("_", " ")
        classes = {kind for kind, pattern in SkillClaims.CLAIM.items() if pattern.search(said)}
        tools = front.get("allowed-tools", front.get("allowed_tools"))
        listed = tools if isinstance(tools, list) else [tools] if isinstance(tools, str) else []
        for entry in listed[:100]:
            for found in SkillClaims._TOOL_NAME.finditer(str(entry)[:400]):
                word = found.group(0).lower()
                if word.startswith("mcp__"):
                    classes.add("network")
                elif word in SkillClaims.TOOL_CLAIM:
                    classes.add(SkillClaims.TOOL_CLAIM[word])
        return frozenset(classes)

    @staticmethod
    def unclaimed(
        text: str, findings: Iterable[Finding], *, concealed: bool
    ) -> tuple[frozenset[str] | None, list[tuple[str, Finding]]]:
        """The classes the description claims (None: none declared) and the acts it does not.

        An act is a reader's finding at MEDIUM: one already at the gate needs no help, and the
        official installer's LOW finding is recorded as an installer. A quoted example in a
        document about the attack is not an act (`DefensiveDoc.lowers`, with the skill model's
        reading beside it). Whether the description claims what the act needs decides it; an act
        that is concealed is unclaimed whatever the description says."""
        front = SkillClaims.front_matter(text)
        claimed = SkillClaims.claimed(front) if front is not None else None
        if claimed is None and SkillClaims.NO_DESCRIPTION == "unknown" and not concealed:
            return None, []
        held = list(findings)
        model_agrees = any(f.rule_id == SkillClaims.SKILL_MODEL_RULE for f in held)
        raw = text.encode("utf-8")
        acts: list[tuple[str, Finding]] = []
        for finding in held:
            act = SkillClaims.ACT_RULE.get(finding.rule_id)
            if act is None or finding.severity != Severity.MEDIUM:
                continue
            location = finding.location
            start = len(raw[: location.byte_start or 0].decode("utf-8", "ignore"))
            end = start + len(
                raw[location.byte_start or 0 : location.byte_end or 0].decode("utf-8", "ignore")
            )
            if DefensiveDoc.lowers(True, text, start, end, model_agrees=model_agrees):
                continue
            if concealed or SkillClaims.REQUIRES[act] not in (claimed or frozenset()):
                acts.append((act, finding))
        return claimed, acts


__all__ = ["SkillClaims", "SkillOrigin", "SkillScripts"]
