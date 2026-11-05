"""What in a Nix file runs, as against what it declares (review 98, FP-15).

A NixOS or home-manager configuration names where keys live -- `IdentityFile ~/.ssh/id_ed25519`,
`age.identityPaths = [ ... ]`, `controlPath = "~/.ssh/master-%r@%n:%p"` -- lists `libsecret` as a
package input and gives hosts by address. Read as code, each is a credential store opened or a
drop point named: 100 of 3,000 real Nix repositories were blocked for it, and none of those lines
runs. Nix evaluation is declarative; what runs is narrow:

  * shell in an indented string (`''...''`) handed to something that runs it: a service's
    `script` or `ExecStart`, a build phase, `shellHook`, a shell's `initExtra`, an activation
    script, `writeShellScript`, `runCommand` and their kin;
  * impure evaluation: `builtins.readFile`, `builtins.getEnv`, `builtins.fetchurl`,
    `fetchTarball` and `fetchGit` -- a credential read and sent at evaluation time.

Capability hits outside those spans are declarations and are not combined into findings. Inside
one, a credential read and a network command still are.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final

RUNS_BEFORE: Final = re.compile(
    r"(?:\b(?:script|preStart|postStart|preStop|postStop|reload|ExecStart\w*|ExecStop\w*|ExecReload"
    r"|buildPhase|installPhase|configurePhase|checkPhase|unpackPhase|patchPhase|fixupPhase"
    r"|buildCommand|postInstall|preInstall|postFixup|preFixup|preBuild|postBuild|preConfigure"
    r"|postConfigure|installCheckPhase|distPhase|shellHook|initExtra|initContent|profileExtra"
    r"|interactiveShellInit|loginShellInit|shellInit|promptInit|envExtra|text|source"
    r"|activationScripts(?:\.[\w\"-]{1,60}){0,6}|postActivation|preActivation|extraCommands|commands"
    r"|serviceConfig\.\w{1,40})\s*=\s*"
    r"|\b(?:writeShellScript(?:Bin)?|writeScript(?:Bin)?|writeShellApplication|writeBash(?:Bin)?"
    r"|runCommand\w*|mkShell|entry(?:After|Before|Anywhere|Between))\b[^;]{0,240}"
    r")$"
)
"""What an indented string is handed to when it is shell that runs. Read on the text before it."""

IMPURE: Final = re.compile(
    r"\bbuiltins\s*\.\s*(?:readFile|getEnv|fetchurl|fetchTarball|fetchGit|fetchTree|exec)\b"
)


class NixCode:
    @staticmethod
    def is_nix(path: str) -> bool:
        return path.endswith(".nix")

    @staticmethod
    def running_spans(text: str) -> list[tuple[int, int]]:
        """Byte ranges of `text` that run: executed shell strings and impure evaluation lines."""
        spans: list[tuple[int, int]] = []
        for start, end in NixCode.indented_strings(text):
            # What precedes the opening `''`: the attribute or writer the string is given to.
            before = text[max(0, start - 302) : start - 2].rstrip()
            if RUNS_BEFORE.search(before):
                spans.append((start, end))
        for match in IMPURE.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            spans.append((line_start, len(text) if line_end == -1 else line_end))
        return sorted(spans)

    @staticmethod
    def indented_strings(text: str) -> list[tuple[int, int]]:
        """`''...''` strings, as byte ranges of their content, skipping comments and "..."."""
        out: list[tuple[int, int]] = []
        i, n = 0, len(text)
        while i < n:
            c = text[i]
            if c == "#":
                nl = text.find("\n", i)
                i = n if nl == -1 else nl + 1
                continue
            if text.startswith("/*", i):
                close = text.find("*/", i + 2)
                i = n if close == -1 else close + 2
                continue
            if c == '"':
                i += 1
                while i < n and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
                i += 1
                continue
            if text.startswith("''", i):
                start = i + 2
                j = start
                while j < n:
                    if text.startswith("''", j):
                        follow = text[j + 2 : j + 3]
                        if follow in ("'", "$", "\\"):
                            j += 3  # an escape: `'''`, `''$`, `''\x`
                            continue
                        break
                    j += 1
                out.append((start, j))
                i = j + 2
                continue
            i += 1
        return out

    @staticmethod
    def running_lines(text: str) -> list[tuple[int, int]]:
        """The running spans as 1-based line ranges, each from the line that opens it."""
        out = []
        for start, end in NixCode.running_spans(text):
            out.append((text.count("\n", 0, start) + 1, text.count("\n", 0, end) + 1))
        return out

    @staticmethod
    def shell(text: str) -> list[tuple[str, int]]:
        """The shell a Nix file runs, as (text, line of the line that opens it): what the shell
        rules read, so `cat ~/.ssh/...` and `curl -d` in a service's script are seen as shell."""
        out = []
        for start, end in NixCode.indented_strings(text):
            before = text[max(0, start - 302) : start - 2].rstrip()
            if RUNS_BEFORE.search(before):
                out.append((text[start:end], text.count("\n", 0, start) + 1))
        return out

    @staticmethod
    def keep_running(text: str, hits: Sequence[Any]) -> list[Any]:
        """`hits` on a line that runs."""
        ranges = NixCode.running_lines(text)
        return [h for h in hits if any(first <= h.line <= last for first, last in ranges)]
