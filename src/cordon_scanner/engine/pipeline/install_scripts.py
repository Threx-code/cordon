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

An install the script reaches only through a program it runs (`node scripts/setup.js` calling
`npm install`) is not read here: what that program does is the code-reading layer's question.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field

_LIFECYCLE = ("preinstall", "install", "postinstall")
_SEPARATORS = re.compile(r"&&|\|\||[;|\n]")
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


@dataclass
class InstallScripts:
    """What a manifest's install-time scripts install: `directories`, and `unresolved`."""

    directories: set[str] = field(default_factory=set)
    unresolved: bool = False

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
        for command in _SEPARATORS.split(script):
            try:
                words = shlex.split(command, comments=False)
            except ValueError:
                words = command.split()
            if not words:
                continue
            if words[0] == "cd":
                target = words[1] if len(words) > 1 else "."
                if _UNRESOLVED.search(target):
                    cwd = ""
                else:
                    cwd = posixpath.normpath(posixpath.join(cwd or ".", target))
                continue
            where = self._install_directory(words)
            if where is None:
                continue
            if cwd == "" or _UNRESOLVED.search(where):
                self.unresolved = True
                continue
            directory = posixpath.normpath(posixpath.join(cwd, where))
            if directory != "." and not directory.startswith(".."):
                self.directories.add(directory)

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
