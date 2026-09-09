"""Commands written as strings inside another language.

A shell command embedded in source is data to every language pack that could
see it. The Python rules look at a `.py` file and find a string; the shell
rules, which know what `curl -d "$(env)" https://...` means, never run on a
`.py` file at all. The command therefore passes through a scan that examined
both languages, because it fell between them.

This module closes that seam by locating the places where a string is
unambiguously a command -- the argument of a process-spawning call -- and
handing that text back so the shell rules can be applied to it directly.

Extraction is deliberately narrow. It reads the argument of a spawn call and
nothing else, so a usage example in a docstring, a URL in a comment or a
command in a README is not treated as an invocation. Being wrong in that
direction produces a false positive on a file that is already doing something
worth reading, which is the more expensive mistake here.

Python is handled by the AST tier instead, which resolves aliases and folds
spliced literals; this covers the languages there is no standard-library
parser for, where a bounded pattern over the call site is what is available.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_COMMANDS = 32
"""Enough to characterise a file. A file with more spawn sites than this is
already established as interesting, and the rest add cost without changing any
conclusion."""

MAX_COMMAND_CHARS = 4096
"""Commands longer than this are truncated rather than dropped. The signal in a
command is at its head -- the program and its first arguments."""

_ARGUMENT_WINDOW = 2048
"""How far past a call's opening parenthesis to look for its arguments. Bounded
so that an unclosed parenthesis in a malformed file cannot make the scan walk
the whole of it."""

_SPAWN_CALL = re.compile(
    r"""\b(?:
        exec | execSync | execFile | execFileSync | execa | execaSync
      | spawn | spawnSync | fork
      | shell_exec | passthru | proc_open | popen | system
    )\s*\(""",
    re.VERBOSE,
)
"""Calls whose arguments are a command line.

`exec` covers Node's `child_process`; `shell_exec`, `passthru` and `proc_open`
are PHP; `system` and `popen` appear in several languages including Ruby and
Perl. The name alone is the trigger, without requiring the module it came
from, because the import may be aliased and the cost of the extra match is one
bounded pattern over a slice.
"""

_QUOTES = "'\"`"
"""Delimiters that open a string literal in the languages handled here."""

MAX_LITERAL_CHARS = 1000
"""Longest literal read from a call's arguments."""

LANGUAGES = frozenset(
    {
        "javascript",
        "typescript",
        "php",
        "ruby",
        "perl",
        "lua",
        "groovy",
        "java",
        "kotlin",
        "scala",
        "csharp",
        "go",
        "rust",
        "c",
        "cpp",
    }
)
"""Languages where a call named `exec` invokes a process.

The restriction is what keeps this honest. A rule pack, a lockfile or a
document may all contain the text `exec("...")` without any of it being an
invocation, and treating those as command sites turns every file that
*describes* a command into a file that *runs* one. Cordon's own rule packs are
the first thing that mistake flags.

Python is absent deliberately: it is handled by the AST tier, which resolves
aliases and folds spliced literals rather than guessing from a name.
"""


@dataclass(frozen=True, slots=True)
class Command:
    """A command line found inside another language's source."""

    text: str
    line: int


def extract(text: str, language: str | None = None) -> list[Command]:
    """Command strings passed to spawn calls in this source.

    Every string literal in a call's argument list is joined, because the
    command is as often split across a sequence -- `spawn("sh", ["-c", "..."])`
    -- as it is written whole.

    Returns nothing for a language that does not invoke processes this way, so
    a rule pack or a document containing the same text is not read as a call.
    """
    if language not in LANGUAGES:
        return []

    commands: list[Command] = []

    for call in _SPAWN_CALL.finditer(text):
        if len(commands) >= MAX_COMMANDS:
            break

        window = text[call.end() : call.end() + _ARGUMENT_WINDOW]
        parts = _literals(window[: _close_paren(window)])
        if not parts:
            continue

        commands.append(
            Command(
                text=" ".join(parts)[:MAX_COMMAND_CHARS],
                line=text.count("\n", 0, call.start()) + 1,
            )
        )

    return commands


def _literals(window: str) -> list[str]:
    """String literals in a call's arguments.

    Scanned character by character rather than matched with a pattern. A
    literal that honours escapes needs an alternation inside a repetition to
    express as a regex, and Cordon refuses that shape in rule packs because of
    how it backtracks; the engine does not get an exemption from a rule the
    packs are held to. Scanning is also the clearer way to say it, and is
    linear by construction.
    """
    parts: list[str] = []
    index = 0
    length = len(window)

    while index < length:
        quote = window[index]
        if quote not in _QUOTES:
            index += 1
            continue

        index += 1
        start = index
        while index < length and window[index] != quote:
            # An escape consumes the character after it, so an escaped quote
            # does not end the literal.
            index += 2 if window[index] == "\\" else 1

        parts.append(window[start : min(index, start + MAX_LITERAL_CHARS)])

        if index >= length:
            # The window ended mid-literal. What was read is still kept: a
            # command long enough to run past the window is exactly the kind
            # worth matching, and discarding it would report clean on content
            # that was truncated rather than examined.
            break

        index += 1

    return parts


def _close_paren(window: str) -> int:
    """Where the call's argument list ends, or the end of the window.

    Counted rather than matched with a pattern, since balancing parentheses is
    not something a regular expression does and a nested call in the arguments
    is ordinary.
    """
    depth = 1
    for index, character in enumerate(window):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(window)


__all__ = ["LANGUAGES", "MAX_COMMANDS", "MAX_COMMAND_CHARS", "Command", "extract"]
