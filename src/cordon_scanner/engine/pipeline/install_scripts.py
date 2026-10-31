"""The nested projects a published npm package's own install scripts install.

`DependencyScope` reads a published package's root manifest and lockfile as what installing it
installs, and a nested project's files (`examples/app/package.json`) as its maintainers'. That is
true until the package's `preinstall`, `install` or `postinstall` script installs the nested
project itself: `cd app && npm install` puts `app`'s dependencies on the installing machine, so
they are installed, and a vulnerable one among them is a vulnerability of the package.

`InstallScripts.of(manifest)` reads those three scripts (the ones npm runs when the package is
installed from a registry; `prepare` runs only for git and local installs) and answers:

- the directories a package-manager install runs in, relative to the package: `cd X && npm i`,
  `npm install --prefix X`, `npm --prefix=X ci`, `yarn --cwd X`, `pnpm -C X install`,
  `pnpm --dir X i`, `bun install --cwd X`;
- whether one runs somewhere it cannot name: a directory built from a variable or a command
  substitution. Then every nested project is taken as installed, so the doubt is reported, not
  hidden.

A program the script runs (`node scripts/setup.js`, `sh install.sh`) is named in `programs`, and the
scope reads it: one that spells a package-manager install anywhere in it (`execSync("npm install",
{cwd})`, `spawn("yarn", ...)`) is an install somewhere this cannot name, so unresolved too
(`InstallScripts.installs`). A program the package does not ship is the code-reading layer's.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field

_LIFECYCLE = ("preinstall", "install", "postinstall")
_MANAGERS = {
    "npm": frozenset(
        {"install", "i", "ci", "add", "isntall", "in", "ins", "inst", "insta", "instal"}
    ),
    "yarn": frozenset({"install", "add", ""}),
    "pnpm": frozenset({"install", "i", "add"}),
    "bun": frozenset({"install", "i", "add"}),
}
_DIRECTORY_FLAGS = frozenset({"--prefix", "--cwd", "-C", "--dir"})
_UNRESOLVED = re.compile(r"[$`]")
_RUNNERS = frozenset(
    {"node", "sh", "bash", "zsh", "python", "python3", "ts-node", "tsx", "bun", "deno"}
)
_INLINE_FLAGS = frozenset({"-e", "--eval", "-p", "--print", "-c"})
_INSTALL_IN_PROGRAM = re.compile(
    rb"""\b(?:npm|yarn|pnpm|bun)\b["',\s\[]{1,8}(?:install|i|ci|add)\b|\b(?:npm|yarn|pnpm)\b["',\s]{1,8}--prefix\b"""
)


@dataclass
class InstallScripts:
    """What a manifest's install-time scripts install: `directories`, and `unresolved`."""

    directories: set[str] = field(default_factory=set)
    unresolved: bool = False
    programs: set[str] = field(default_factory=set)
    """The package's own files the scripts run, relative to the package."""

    @staticmethod
    def installs(program: bytes) -> bool:
        """Whether a program the scripts run spells a package-manager install."""
        return _INSTALL_IN_PROGRAM.search(program) is not None

    @staticmethod
    def of(manifest: bytes) -> InstallScripts:
        """The install-time scripts of one `package.json`; nothing for one that does not parse."""
        found = InstallScripts()
        try:
            scripts = json.loads(manifest.decode("utf-8", "replace")).get("scripts")
        except (ValueError, AttributeError):
            return found
        if not isinstance(scripts, dict):
            return found
        for name in _LIFECYCLE:
            script = scripts.get(name)
            if isinstance(script, str):
                found._read(script)
        return found

    def _read(self, script: str) -> None:
        cwd = "."
        for words in InstallScripts._commands(script):
            if words[0] == "cd":
                target = words[1] if len(words) > 1 else "."
                if _UNRESOLVED.search(target):
                    cwd = ""
                else:
                    cwd = posixpath.normpath(posixpath.join(cwd or ".", target))
                continue
            where = self._install_directory(words)
            if where is None:
                self._note_program(words, cwd)
                continue
            if cwd == "" or _UNRESOLVED.search(where):
                self.unresolved = True
                continue
            directory = posixpath.normpath(posixpath.join(cwd, where))
            if directory != "." and not directory.startswith(".."):
                self.directories.add(directory)

    @staticmethod
    def _commands(script: str) -> list[list[str]]:
        """The script's commands, split at `&&`, `||`, `;`, `|` and newlines outside quotes, so a
        quoted `sh -c 'cd app && npm ci'` stays one command. An unbalanced quote falls back to a
        split on blanks, so nothing is skipped for a typo."""
        lexer = shlex.shlex(script.replace("\n", " ; "), posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            tokens = list(lexer)
        except ValueError:
            tokens = re.sub(r"(&&|\|\||[;|])", r" \1 ", script.replace("\n", " ; ")).split()
        commands: list[list[str]] = [[]]
        for token in tokens:
            if token and set(token) <= set(";&|"):
                commands.append([])
            else:
                commands[-1].append(token)
        return [c for c in commands if c]

    def _note_program(self, words: list[str], cwd: str) -> None:
        """The package file a runner (`node x.js`, `sh y.sh`) or the script itself (`./z.sh`) runs."""
        runner = posixpath.basename(words[0])
        if runner in _RUNNERS:
            inline = next(
                (words[i + 1] for i, w in enumerate(words[1:-1], 1) if w in _INLINE_FLAGS), None
            )
            if inline is not None:
                # `node -e '...'`, `sh -c '...'`: the code is the script's own text.
                self.unresolved = self.unresolved or InstallScripts.installs(inline.encode())
                return
            target = next((w for w in words[1:] if not w.startswith("-")), None)
        elif "/" in words[0]:
            target = words[0]
        else:
            return
        if target is None or _UNRESOLVED.search(target) or cwd == "":
            return
        program = posixpath.normpath(posixpath.join(cwd, target))
        if not program.startswith(".."):
            self.programs.add(program)

    @staticmethod
    def _install_directory(words: list[str]) -> str | None:
        """The directory a package-manager install runs in (`.` for the current one), or None
        when the command is no install."""
        verbs = _MANAGERS.get(posixpath.basename(words[0]))
        if verbs is None:
            return None
        where, verb, rest = ".", None, iter(words[1:])
        for word in rest:
            flag, _, value = word.partition("=")
            if flag in _DIRECTORY_FLAGS:
                where = value or next(rest, ".")
            elif word.startswith("-"):
                continue
            elif verb is None:
                verb = word
        return where if (verb or "") in verbs else None


__all__ = ["InstallScripts"]
