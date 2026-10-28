"""Deno's deno.lock (its npm, JSR and remote modules) and deno.json, read into the dependency graph."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class DenoLock:
    """Deno's lockfile (`deno.lock`, versions 3 to 5): npm packages, JSR packages, remote modules.

    Version 3 nests packages under `packages.npm` / `packages.jsr`; versions 4 and 5 put them at
    the top level under `npm` and `jsr`. Each key is `name@version` (with peer suffixes after `_`
    in later versions) and carries an integrity hash.

    A JSR package is not an npm package of the same name: `@std/path` on JSR and `@std/path` on
    npm are unrelated, and a squatter can hold the npm one. It is recorded under the name JSR
    itself serves it as through its npm-compatible registry, `@jsr/std__path`, from `jsr.io`, with
    the name the project wrote kept as the alias. A remote module (`https://deno.land/x/oak@v12/`)
    is recorded once per module and version, from its URL, with Deno's hash of what it fetched.
    """

    _REMOTE = (
        re.compile(
            r"^https://deno\.land/(?:x/)?(?P<name>[A-Za-z0-9_.-]{1,100})@(?P<version>[^/]{1,64})/"
        ),
        re.compile(
            r"^https://esm\.sh/(?:v\d{1,4}/)?(?P<name>(?:@[^/@]{1,100}/)?[^/@?]{1,100})@(?P<version>[^/?]{1,64})"
        ),
        re.compile(
            r"^https://cdn\.jsdelivr\.net/npm/(?P<name>(?:@[^/@]{1,100}/)?[^/@]{1,100})@(?P<version>[^/]{1,64})/"
        ),
    )

    @staticmethod
    def jsr_name(name: str) -> str:
        """JSR's npm-compatible name: `@std/path` is served as `@jsr/std__path`."""
        scope, _, package = name.removeprefix("@").partition("/")
        return f"@jsr/{scope}__{package}" if package else name

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        from cordon_scanner.ecosystems.packages.javascript.bun import BunLock

        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid deno.lock: {exc}"
            )
        raw_nested = data.get("packages")
        nested: dict[str, Any] = raw_nested if isinstance(raw_nested, dict) else {}
        npm = data.get("npm") if isinstance(data.get("npm"), dict) else nested.get("npm")
        jsr = data.get("jsr") if isinstance(data.get("jsr"), dict) else nested.get("jsr")
        raw_remote = data.get("remote")
        remote: dict[str, Any] = raw_remote if isinstance(raw_remote, dict) else {}
        specifiers = (
            data.get("specifiers")
            if isinstance(data.get("specifiers"), dict)
            else nested.get("specifiers")
        )
        direct = cls._direct(data, specifiers if isinstance(specifiers, dict) else {})
        entries: list[LockEntry] = []
        cls._jsr_entries(jsr, entries, direct)
        cls._remote_entries(remote, entries)
        if not isinstance(npm, dict):
            return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))
        for key, meta in sorted(npm.items()):
            name, version = BunLock.split_spec(str(key).split("_", 1)[0])
            if not name or not version:
                continue
            meta = meta if isinstance(meta, dict) else {}
            requires = meta.get("dependencies")
            if isinstance(requires, dict):
                needed = tuple(sorted(str(k) for k in requires))
            elif isinstance(requires, list):
                needed = tuple(
                    sorted(BunLock.split_spec(str(d).split("_", 1)[0])[0] for d in requires)
                )
            else:
                needed = ()
            integrity = meta.get("integrity")
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=integrity
                    if isinstance(integrity, str) and integrity.startswith("sha")
                    else None,
                    dependencies=needed,
                    direct=name in direct,
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @classmethod
    def _jsr_entries(
        cls, jsr: Any | None, entries: list[LockEntry], direct: frozenset[str]
    ) -> None:
        """One entry per JSR package, with its integrity and its dependencies' edges."""
        from cordon_scanner.ecosystems.packages.javascript.bun import BunLock

        for key, meta in sorted((jsr if isinstance(jsr, dict) else {}).items()):
            name, version = BunLock.split_spec(str(key))
            if not name or not version:
                continue
            meta = meta if isinstance(meta, dict) else {}
            listed = meta.get("dependencies")
            jsr_needed: list[str] = []
            for dep in listed if isinstance(listed, list) else ():
                text = str(dep)
                if text.startswith("jsr:"):
                    jsr_needed.append(cls.jsr_name(BunLock.split_spec(text[4:])[0]))
                elif text.startswith("npm:"):
                    jsr_needed.append(BunLock.split_spec(text[4:])[0])
            integrity = meta.get("integrity")
            entries.append(
                LockEntry(
                    name=cls.jsr_name(name),
                    version=version,
                    integrity=f"sha256-hex:{integrity}"
                    if isinstance(integrity, str) and integrity
                    else None,
                    resolved_from=f"https://jsr.io/{name}/{version}",
                    dependencies=tuple(sorted(jsr_needed)),
                    direct=f"jsr:{name}" in direct,
                    alias=name,
                )
            )

    @classmethod
    def _remote_entries(cls, remote: dict[str, Any], entries: list[LockEntry]) -> None:
        """The remote modules, one entry per module and version, with its digest."""
        modules: dict[tuple[str, str], tuple[str, str]] = {}
        for url, digest in sorted(remote.items()):
            for pattern in cls._REMOTE:
                found = pattern.match(str(url))
                if found:
                    key = (found.group("name"), found.group("version"))
                    modules.setdefault(key, (str(url), str(digest)))
                    break
        for (name, version), (url, digest) in sorted(modules.items()):
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=f"sha256-hex:{digest}" if digest else None,
                    resolved_from=url,
                    direct=True,
                )
            )

    @staticmethod
    def _direct(data: dict[str, Any], specifiers: dict[str, Any]) -> frozenset[str]:
        """The npm packages the project names itself: the workspace's own list where Deno records
        one, otherwise every `npm:` specifier (each is something an import or config named)."""
        from cordon_scanner.ecosystems.packages.javascript.bun import BunLock

        workspace = data.get("workspace")
        listed = workspace.get("dependencies") if isinstance(workspace, dict) else None
        sources = listed if isinstance(listed, list) else list(specifiers)
        names = set()
        for spec in sources:
            text = str(spec)
            if text.startswith("npm:"):
                names.add(BunLock.split_spec(text[len("npm:") :])[0])
            elif text.startswith("jsr:"):
                names.add("jsr:" + BunLock.split_spec(text[len("jsr:") :])[0])
        return frozenset(names)


class DenoManifest:
    """`deno.json` / `deno.jsonc`: the import map is the dependency list.

    ```
      "chalk":     "npm:chalk@4.1.2"             -> npm chalk, 4.1.2
      "@std/path": "jsr:@std/path@^1.0.8"        -> JSR @std/path, as @jsr/std__path
      "oak":       "https://deno.land/x/oak@v12.6.1/mod.ts"  -> deno.land/x oak, v12.6.1
    ```

    JSONC: comments and trailing commas are removed outside strings before decoding.
    """

    @staticmethod
    def without_comments(text: str) -> str:
        out: list[str] = []
        index = 0
        in_string = False
        while index < len(text):
            char = text[index]
            if in_string:
                out.append(char)
                if char == "\\" and index + 1 < len(text):
                    out.append(text[index + 1])
                    index += 2
                    continue
                if char == '"':
                    in_string = False
                index += 1
                continue
            if char == '"':
                in_string = True
                out.append(char)
                index += 1
                continue
            if text.startswith("//", index):
                end = text.find("\n", index)
                index = len(text) if end < 0 else end
                continue
            if text.startswith("/*", index):
                end = text.find("*/", index + 2)
                index = len(text) if end < 0 else end + 2
                continue
            out.append(char)
            index += 1
        return "".join(out)

    @staticmethod
    def declaration(key: str, target: str) -> DeclaredDependency | None:
        from cordon_scanner.ecosystems.packages.javascript.bun import BunLock

        text = target.strip()
        for prefix in ("npm:", "jsr:"):
            if not text.startswith(prefix):
                continue
            # `npm:chalk@4/source/index.js` imports a file inside chalk: the package is the name
            # and version, before any subpath.
            body = text[len(prefix) :].lstrip("/")
            parts = body.split("/")
            package = "/".join(parts[:2]) if body.startswith("@") else parts[0]
            name, version = BunLock.split_spec(package)
            if prefix == "jsr:":
                return DeclaredDependency(
                    name=DenoLock.jsr_name(name), spec=version or "*", alias=name
                )
            return DeclaredDependency(
                name=name, spec=version or "*", alias=key if key != name else None
            )
        for pattern in DenoLock._REMOTE:
            found = pattern.match(text)
            if found:
                return DeclaredDependency(
                    name=found.group("name"), spec=found.group("version"), alias=None
                )
        return None

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> Manifest:
        from cordon_scanner.ecosystems.packages.javascript.bun import BunLock

        try:
            data = BaseEcosystem._json_object(
                BunLock.without_trailing_commas(cls.without_comments(content.text))
            )
        except (json.JSONDecodeError, ValueError) as exc:
            return Manifest(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid {content.basename}: {exc}",
            )
        declared: list[DeclaredDependency] = []
        maps = [data.get("imports")]
        scopes = data.get("scopes")
        if isinstance(scopes, dict):
            maps.extend(scopes.values())
        # One package may be imported under two names at two versions (`chalk` at ^4, `colors`
        # as chalk 5): each is its own declaration. Only the same name at the same spec is one.
        seen: set[tuple[str, str]] = set()
        for mapping in maps:
            if not isinstance(mapping, dict):
                continue
            for key, target in sorted(mapping.items()):
                if not isinstance(target, str):
                    continue
                entry = cls.declaration(str(key), target)
                if entry is not None and (entry.name, entry.spec) not in seen:
                    seen.add((entry.name, entry.spec))
                    declared.append(entry)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=str(data["name"]) if isinstance(data.get("name"), str) else None,
            version=str(data["version"]) if isinstance(data.get("version"), str) else None,
            dependencies=tuple(declared),
        )


__all__ = ["DenoLock", "DenoManifest"]
