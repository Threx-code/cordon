"""Agent skills: whether a skill is the project's own or installed from elsewhere, and the scripts that
ship with it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext


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
        for call in SkillScripts.decode_calls(text):
            argument = (call.group("arg") or "").strip()
            if not SkillScripts._encoded(argument, text):
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
            name = re.escape(assigned.group(1))
            run = re.search(rf"\b(?:exec|eval|Function)\s*\(\s*{name}\s*[,)]", text[call.end() :])
            if run is not None:
                return line.search(text, call.end() + run.start())
        return None

    @staticmethod
    def _encoded(argument: str, text: str) -> bool:
        """Whether a decoder's argument is a fixed encoded payload: a literal, or a name the file
        assigns one."""
        if re.fullmatch(_ENCODED_LITERAL, argument):
            return True
        if re.fullmatch(r"[A-Za-z_]\w{0,40}", argument):
            return (
                re.search(
                    rf"(?m)^\s*(?:const\s+|let\s+|var\s+)?{re.escape(argument)}\s*=\s*{_ENCODED_LITERAL}",
                    text,
                )
                is not None
            )
        return False


__all__ = ["SkillOrigin", "SkillScripts"]
