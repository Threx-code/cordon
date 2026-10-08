"""npm, pnpm, yarn, Bun and Deno's npm packages.

The manifest is parsed as JSON, never scanned line by line. That distinction is
load-bearing: a line-oriented reader silently assumes pretty-printed input, and
any tool that rewrites `package.json` can emit it on a single line. The check
then finds nothing while a postinstall script sits in plain sight. Reformatting
is not an exotic evasion, it is an accident that happens routinely, and a
parser a whitespace change can blind is not a check.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent

SCOPE_FIELDS = {
    "dependencies": Scope.RUNTIME,
    "devDependencies": Scope.DEV,
    "optionalDependencies": Scope.OPTIONAL,
    "peerDependencies": Scope.PEER,
}


class NpmEcosystem(BaseEcosystem):
    @staticmethod
    def _name_from_location(location: str) -> str:
        """Recover a package name from a node_modules path."""
        _, _, tail = location.rpartition("node_modules/")
        return tail or location

    @staticmethod
    def _str_or_none(value: object) -> str | None:
        return str(value) if isinstance(value, str) and value else None

    id = "npm"
    purl_type = "npm"
    manifest_globs: tuple[str, ...] = ("**/package.json", "**/deno.json", "**/deno.jsonc")
    lockfile_globs: tuple[str, ...] = (
        "**/package-lock.json",
        "**/npm-shrinkwrap.json",
        "**/pnpm-lock.yaml",
        "**/yarn.lock",
        "**/bun.lock",
        "**/deno.lock",
    )
    registry_hosts: frozenset[str] = frozenset(
        {
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "registry.npmmirror.com",
            # Deno's registries: JSR (and its npm-compatible endpoint) and deno.land/x, and the
            # CDNs that serve npm packages by name and version to `import` statements.
            "jsr.io",
            "npm.jsr.io",
            "deno.land",
            "esm.sh",
            "cdn.jsdelivr.net",
        }
    )

    # Everything npm, pnpm and yarn will execute around an install. `prepare`
    # and `prepublishOnly` are included because they run on `npm install` in a
    # git checkout, which surprises people who assume only `postinstall` matters.
    lifecycle_keys = frozenset(
        {
            "preinstall",
            "install",
            "postinstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
            "prepack",
            "postpack",
            "postpublish",
            "dependencies",
        }
    )

    def normalize_name(self, name: str) -> str:
        """npm names are case-insensitive and scope-aware.

        The scope is preserved. `@acme/utils` and `utils` are different
        packages, and folding the scope away would make a scoped internal
        package look identical to an unscoped public one -- which is precisely
        the confusion a dependency-confusion attack exploits.
        """
        return name.strip().lower()

    # -- Manifest --------------------------------------------------------

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.basename in ("deno.json", "deno.jsonc"):
            return DenoManifest.parse(content, self.id)
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                parse_error=f"invalid JSON: {exc}",
            )
        declared: list[DeclaredDependency] = []
        for field_name, scope in SCOPE_FIELDS.items():
            section = data.get(field_name)
            if not isinstance(section, dict):
                continue
            for name, spec in sorted(section.items()):
                if isinstance(spec, str):
                    # `"scheduler-0-13": "npm:scheduler@0.13.0"` installs `scheduler` under
                    # another directory name; the package and its version are the alias target.
                    real_name, real_spec = str(name), spec
                    alias = re.fullmatch(
                        r"npm:((?:@[^/@\s]{1,214}/)?[^/@\s]{1,214})(?:@(.{0,256}))?", spec.strip()
                    )
                    if alias:
                        real_name, real_spec = alias.group(1), alias.group(2) or "*"
                    declared.append(
                        DeclaredDependency(
                            name=real_name,
                            spec=real_spec,
                            scope=scope,
                            field_name=field_name,
                            alias=str(name) if alias else None,
                        )
                    )

        scripts = data.get("scripts")
        hooks: tuple[Hook, ...] = ()
        if isinstance(scripts, dict):
            hooks = tuple(self.lifecycle_hooks(scripts, content.path))

        overrides: dict[str, str] = {}
        for key in ("overrides", "resolutions"):
            section = data.get(key)
            if isinstance(section, dict):
                for name, spec in section.items():
                    if isinstance(spec, str):
                        overrides[str(name)] = spec

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=str(data["name"]) if isinstance(data.get("name"), str) else None,
            version=str(data["version"]) if isinstance(data.get("version"), str) else None,
            dependencies=tuple(declared),
            hooks=hooks,
            overrides=overrides,
            private=bool(data.get("private", False)),
            repository=NpmManifest._repository_of(data),
        )

    # -- Lockfiles -------------------------------------------------------

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        name = content.basename
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            return self._parse_npm_lock(content)
        if name == "pnpm-lock.yaml":
            return PnpmLock.parse(content, self.id)
        if name == "yarn.lock":
            return YarnLock.parse(content, self.id)
        if name == "bun.lock":
            return BunLock.parse(content, self.id)
        if name == "deno.lock":
            return DenoLock.parse(content, self.id)
        return LockGraph(
            path=content.path, ecosystem=self.id, parse_error=f"unsupported lockfile: {name}"
        )

    def _parse_npm_lock(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )

        entries: list[LockEntry] = []

        # Lockfile v2 and v3 use a flat `packages` map keyed by install path.
        packages = data.get("packages")
        if isinstance(packages, dict):
            # What the project itself asked for. A v2/v3 lockfile records the
            # root's own dependency lists in the "" entry, so direct-ness is
            # stated rather than inferred -- and the depth heuristic below is
            # wrong for exactly the packages that matter: npm hoists a
            # transitive dependency to the top level, where `node_modules/x`
            # looks identical to something the project depends on. Reachability
            # only lowers a transitive finding, so calling everything direct
            # meant nothing was ever lowered.
            root_entry = packages.get("")
            root: dict[str, object] = root_entry if isinstance(root_entry, dict) else {}
            declared: set[str] = set()
            for field in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                section = root.get(field)
                if isinstance(section, dict):
                    declared.update(str(name) for name in section)
            hashed = {
                location
                for location, meta in packages.items()
                if isinstance(meta, dict) and meta.get("integrity")
            }
            # The name each install directory holds. An alias installs `chalk` at
            # `node_modules/chalk-four`, and every edge to it says `chalk-four`; the edge is
            # followed to the package actually there.
            installed_as: dict[str, str] = {}
            members: list[str] = []
            for location, meta in packages.items():
                if not location or not isinstance(meta, dict):
                    continue
                directory = NpmEcosystem._name_from_location(location)
                real = meta.get("name") if isinstance(meta.get("name"), str) else None
                if "node_modules/" in location and real and real != directory:
                    installed_as.setdefault(directory, str(real))
                if not location.startswith("node_modules/") and "/node_modules/" not in location:
                    members.append(location)
            # A workspace member's own declarations count as direct, like the root's.
            for location in members:
                member = packages.get(location)
                for field in (
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ):
                    section = member.get(field) if isinstance(member, dict) else None
                    if isinstance(section, dict):
                        declared.update(str(name) for name in section)
            # What each linked directory is installed AS: `node_modules/kase-core` linking to
            # `packages_imported/kase-core/3.2.3`, whose own entry carries no `name`, is
            # kase-core -- named by its last path segment it was a package called `3.2.3`.
            linked_as = {
                str(meta["resolved"]): NpmEcosystem._name_from_location(location)
                for location, meta in packages.items()
                if isinstance(meta, dict)
                and meta.get("link") is True
                and isinstance(meta.get("resolved"), str)
            }
            for location, meta in sorted(packages.items()):
                if not location or not isinstance(meta, dict):
                    continue  # "" is the root project itself
                if meta.get("link") is True:
                    # `node_modules/local-util` pointing at `packages/util`: the member itself
                    # is the entry, listed under its own directory. Counting both made one
                    # workspace package two dependencies.
                    continue
                directory = NpmEcosystem._name_from_location(location)
                name = meta.get("name") or linked_as.get(location) or directory
                if not name:
                    continue
                resolved = NpmEcosystem._str_or_none(meta.get("resolved"))
                edges: set[str] = set()
                for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                    section = meta.get(field)
                    if isinstance(section, dict):
                        edges.update(
                            NpmEcosystem._resolve_edge(packages, location, str(d))
                            or installed_as.get(str(d), str(d))
                            for d in section
                        )
                entries.append(
                    LockEntry(
                        name=str(name),
                        version=str(meta.get("version", "")),
                        integrity=NpmEcosystem._str_or_none(meta.get("integrity")),
                        resolved_from=resolved,
                        scope=NpmEcosystem._lock_scope(meta),
                        dependencies=tuple(sorted(edges)),
                        # Named by the root when the root says; otherwise the
                        # depth heuristic, which is all a partial lockfile
                        # supports.
                        # Only an install at the top of a node_modules tree is what a project
                        # asked for: `node_modules/debug/node_modules/ms` is debug's ms, whatever
                        # version of ms the root also names.
                        direct=(
                            (str(name) in declared or directory in declared)
                            and location.count("node_modules/") == 1
                            if declared
                            else location.count("node_modules/") == 1
                        ),
                        local=NpmEcosystem._is_local_package(location, meta, resolved),
                        bundled=NpmEcosystem._is_bundled(location, meta, resolved, hashed),
                        license=NpmEcosystem._str_or_none(meta.get("license")),
                        platform=NpmEcosystem._platform(meta),
                        alias=directory
                        if "node_modules/" in location and directory != name
                        else None,
                    )
                )
            return LockGraph(
                path=content.path,
                ecosystem=self.id,
                entries=tuple(entries),
                workspaces=tuple(sorted(members)),
            )

        # Lockfile v1 nests under `dependencies`.
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            entries.extend(self._walk_v1(deps, depth=0))

        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    @staticmethod
    def _resolve_edge(packages: dict[str, Any], location: str, dependency: str) -> str | None:
        """`name@version` of the copy `location` gets for `dependency`, as Node resolves it.

        Node looks in the package's own `node_modules`, then each enclosing one up to the root:
        `node_modules/debug` asking for `ms` finds `node_modules/debug/node_modules/ms` before the
        root's `node_modules/ms`. Two versions of one package are told apart only this way."""
        base = location
        for _ in range(64):
            candidate = (
                f"{base}/node_modules/{dependency}" if base else f"node_modules/{dependency}"
            )
            meta = packages.get(candidate)
            if isinstance(meta, dict):
                if meta.get("link") is True and isinstance(meta.get("resolved"), str):
                    target = packages.get(meta["resolved"])
                    meta = target if isinstance(target, dict) else meta
                name = meta.get("name") if isinstance(meta.get("name"), str) else dependency
                version = meta.get("version")
                return f"{name}@{version}" if isinstance(version, str) and version else str(name)
            if not base:
                return None
            cut = base.rfind("/node_modules/")
            base = base[:cut] if cut >= 0 else ""
        return None

    @staticmethod
    def _lock_scope(meta: dict[str, Any]) -> Scope:
        """npm's own flags: `dev`, `optional`, `devOptional` (needed only by a dev or optional
        path) and `peer` (installed because something declared it as a peer)."""
        if meta.get("dev") is True:
            return Scope.DEV
        if meta.get("devOptional") is True:
            return Scope.DEV
        if meta.get("optional") is True:
            return Scope.OPTIONAL
        if meta.get("peer") is True:
            return Scope.PEER
        return Scope.RUNTIME

    @staticmethod
    def _platform(meta: dict[str, Any]) -> tuple[str, ...]:
        """`os`, `cpu` and `libc` as conditions: `os: darwin`, `cpu: !arm`."""
        out: list[str] = []
        for field in ("os", "cpu", "libc"):
            values = meta.get(field)
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                listed = [str(v) for v in values if isinstance(v, (str, int))]
                if listed:
                    out.append(f"{field}: {', '.join(listed)}")
        engines = meta.get("engines")
        if isinstance(engines, dict) and isinstance(engines.get("node"), str):
            out.append(f"node: {engines['node']}")
        return tuple(out)

    @staticmethod
    def _is_local_package(location: str, meta: dict[str, Any], resolved: str | None) -> bool:
        """Whether this `packages` entry is the project's own code.

        Three shapes, and a workspace produces all three at once:

        * a key that is not under `node_modules/` at all -- `apps/shared`, `web`, and
          every other workspace directory, which npm lists so that its dependencies
          are resolved;
        * `"link": true`, which is the `node_modules/@scope/name` entry pointing at
          one of those directories;
        * a `resolved` that is a path rather than a URL, which is what a `file:` or
          workspace dependency records.

        None of them has an integrity hash, because there is nothing to fetch. The
        npm parser recorded none of them as local, so `POLICY.LOCKFILE.INTEGRITY.001`
        reported every workspace member of every monorepo as a package pinned without
        a hash: `NousResearch/hermes-agent` supplied fourteen in one file, and the rule
        was 119 findings across 34 of the first 228 repositories measured.
        """
        if meta.get("link") is True:
            return True
        if not location.startswith("node_modules/") and "/node_modules/" not in location:
            return True
        return bool(resolved) and "://" not in str(resolved)

    @staticmethod
    def _is_bundled(
        location: str, meta: dict[str, Any], resolved: str | None, hashed: frozenset[str] | set[str]
    ) -> bool:
        """Whether this entry arrives inside a hashed parent's tarball.

        npm says so outright when the parent declared `bundleDependencies`, and often
        does not. What it always writes is the shape: a NESTED path, a version, and
        nothing else -- no `resolved`, no `integrity`, not even the `license` and
        `engines` it copies from a tarball it actually read. A package npm fetched
        separately gets both fields; one it only found inside another archive has
        nothing to fetch and nothing of its own to hash.

        The enclosing package must itself be hashed, which is the condition that makes
        this safe rather than convenient. Without it the rule would excuse a whole
        unhashed subtree on the strength of its shape.

        Nesting alone is not enough either: npm nests a package whenever two versions
        of it are needed, and those are fetched and hashed like any other. Only the
        entries missing both fields are covered.
        """
        if meta.get("inBundle") is True:
            return True
        if resolved or meta.get("integrity"):
            return False
        if location.count("node_modules/") < 2:
            return False
        parent = location
        while True:
            cut = parent.rfind("/node_modules/")
            if cut == -1:
                return False
            parent = parent[:cut]
            if parent in hashed:
                return True

    def _walk_v1(self, section: dict[str, Any], depth: int) -> list[LockEntry]:
        out: list[LockEntry] = []
        for name, meta in sorted(section.items()):
            if not isinstance(meta, dict):
                continue
            # v1 writes an alias in the version (`"npm:scheduler@0.13.0"`) and a path
            # dependency there too (`"file:../shared"`, `"link:..."`).
            version = str(meta.get("version", ""))
            real_name = str(name)
            if version.startswith("npm:") and "@" in version[5:]:
                real_name, _, version = version[4:].rpartition("@")
            out.append(
                LockEntry(
                    name=real_name,
                    version=version,
                    integrity=NpmEcosystem._str_or_none(meta.get("integrity")),
                    resolved_from=NpmEcosystem._str_or_none(meta.get("resolved")),
                    local=version.startswith(("file:", "link:")),
                    scope=NpmEcosystem._lock_scope(meta),
                    alias=str(name) if real_name != str(name) else None,
                    dependencies=tuple(sorted((meta.get("requires") or {}).keys()))
                    if isinstance(meta.get("requires"), dict)
                    else (),
                    # Never `depth == 0`. Lockfile v1 hoists the resolved tree
                    # to the top level, so a package there may be a direct
                    # dependency or one four levels down and the file does not
                    # say which. Claiming every hoisted entry is direct
                    # inflated the count that orders registry queries and feeds
                    # scope reasoning. With none marked, `to_dependencies`
                    # treats them all as roots, which is what the format
                    # actually supports.
                    direct=False,
                )
            )
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                out.extend(self._walk_v1(nested, depth + 1))
        return out

    @staticmethod
    def _pnpm_split_key(key: str) -> tuple[str, str] | None:
        """A pnpm package key as `(name, version)`, across the formats in use.

        pnpm has written the key three ways. Lockfile 5 separates with a slash
        and leads with one (`/lodash/4.17.21`, `/@babel/core/7.21.0`); 6 and 9
        separate with `@` (`/@babel/core@7.21.0`, `lodash@4.17.21`). Splitting on
        the last `@` alone reads every version-5 key as nameless and dropped the
        whole file, silently, because an empty graph and a project with no
        dependencies looked the same.

        A peer-suffixed key (`foo@1.0.0(bar@2.0.0)`) keeps only its own version:
        the suffix names the peer the entry was resolved against, not part of
        what this entry is.
        """
        text = key.strip().strip("'\"")
        if not text:
            return None

        head = text.split("(", 1)[0]
        scoped = head.startswith("/@") or head.startswith("@")
        body = head[1:] if head.startswith("/") else head

        at = body.rfind("@")
        if at > 0:
            name, version = body[:at], body[at + 1 :]
            if name and version and "/" not in version:
                return (name, version)

        # Lockfile 5: the version is the last slash-separated segment, and a
        # scoped name keeps the slash that belongs to its scope.
        cut = body.rfind("/")
        if cut > 0:
            name, version = body[:cut], body[cut + 1 :]
            if name and version and (not scoped or "/" in name):
                return (name, version)
        return None


__all__ = ["NpmEcosystem", "PnpmLock", "YarnLock"]


class LockScopes:
    """Which scope a package has, from the scopes of the declarations that reach it.

    A package reached from any runtime declaration is runtime, whatever else also reaches it; one
    reached only through optional declarations is optional; only through dev ones, dev. pnpm 9 and
    Yarn record no per-package `dev` flag, so the scope is the graph's answer, not a field's.
    """

    #: When several kinds of declaration reach one package, the one closest to what ships wins:
    #: anything reached at runtime is runtime; a build tool reached by tests is still a build tool.
    ORDER: tuple[Scope, ...] = (
        Scope.RUNTIME,
        Scope.PEER,
        Scope.OPTIONAL,
        Scope.BUILD,
        Scope.TOOL,
        Scope.TEST,
        Scope.DEV,
    )

    @staticmethod
    def rank(scope: Scope) -> int:
        """Position in `ORDER`; a scope outside it (platform) ranks last."""
        return LockScopes.ORDER.index(scope) if scope in LockScopes.ORDER else len(LockScopes.ORDER)

    @staticmethod
    def propagate(
        roots: dict[str, set[Scope]], edges: dict[str, set[str]], limit: int = 2_000_000
    ) -> dict[str, Scope]:
        reached: dict[str, set[Scope]] = {key: set(scopes) for key, scopes in roots.items()}
        queue = list(roots)
        steps = 0
        while queue and steps < limit:
            steps += 1
            key = queue.pop()
            for child in edges.get(key, ()):
                known = reached.setdefault(child, set())
                missing = reached[key] - known
                if missing:
                    known |= missing
                    queue.append(child)
        return {
            key: next((s for s in LockScopes.ORDER if s in scopes), Scope.RUNTIME)
            for key, scopes in reached.items()
        }


class PnpmLock:
    """pnpm's lockfile, versions 5, 6 and 9, read as the YAML document it is.

    Line-matching it kept names and hashes and lost everything else: the edges, which scope
    reached a package (pnpm 9 records no `dev` flag; only the importers say), the platform fields
    (`os`, `cpu`, `libc`), aliases (`chalk-four: {version: chalk@4.1.2}`), links to workspace
    members, and git sources (a key of `is-number@https://codeload.github.com/...` read as the
    package `is-number@https://codeload.github.com/...` and pinned the URL's hash as its version).

    ```
      importers:  <member path> -> dependencies / devDependencies / optionalDependencies
                  -> name -> {specifier, version}        (v6, v9; v5 keeps a bare version)
      packages:   <key> -> resolution {integrity | tarball | type: git, repo, commit},
                  os, cpu, libc, engines, version (for non-registry keys), dev, optional
      snapshots:  <key with peer suffix> -> dependencies, optionalDependencies   (v9 only)
    ```
    """

    SECTIONS: ClassVar[dict[str, Scope]] = {
        "dependencies": Scope.RUNTIME,
        "optionalDependencies": Scope.OPTIONAL,
        "devDependencies": Scope.DEV,
    }

    @staticmethod
    def _identity(key: str, meta: dict[str, Any]) -> tuple[str, str]:
        """`(name, version)` of a package key in any of pnpm's layouts."""
        text = key.strip().strip("'\"").split("(", 1)[0]
        body = text[1:] if text.startswith("/") else text
        at = body.find("@", 1 if body.startswith("@") else 0)
        if at > 0:
            remainder = body[at + 1 :]
            if "://" in remainder or remainder.startswith(("link:", "file:", "git+", "github:")):
                name = body[:at]
                version = str(meta.get("version") or remainder)
                return str(meta.get("name") or name), version
        split = NpmEcosystem._pnpm_split_key(text)
        if split is not None:
            name, version = split
            return str(meta.get("name") or name), str(meta.get("version") or version)
        return str(meta.get("name") or body), str(meta.get("version") or "")

    @staticmethod
    def _candidates(name: str, reference: str) -> list[str]:
        bare = reference.split("(", 1)[0]
        return [
            f"{name}@{reference}",
            f"{name}@{bare}",
            f"/{name}@{reference}",
            f"/{name}@{bare}",
            f"/{name}/{reference}",
            f"/{name}/{bare}",
        ]

    @staticmethod
    def _target(name: str, reference: str) -> tuple[str, str, str | None]:
        """`(real name, reference, alias)` for a dependency written `name: reference`.

        `chalk-four: chalk@4.1.2` is an alias: the package is `chalk`, at 4.1.2."""
        reference = reference.strip()
        if reference.startswith(("link:", "file:", "http:", "https:", "git+", "github:")):
            return name, reference, None
        head = reference.split("(", 1)[0]
        at = head.find("@", 1 if head.startswith("@") else 0)
        if at > 0 and not head[:at].replace(".", "").isdigit():
            return head[:at], reference[at + 1 :], name
        return name, reference, None

    DOCUMENT_BREAK: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^---[ \t]*\r?$")

    @classmethod
    def _project_document(cls, content: FileContent) -> Any:
        """The lockfile as one mapping. pnpm 10 writes two YAML documents into `pnpm-lock.yaml`:
        first the package manager's own environment (`packageManagerDependencies`: pnpm and its
        `@pnpm/exe` builds), then, after `---`, the project. Read as one document the second was
        dropped, and the project's whole dependency tree with it. Each document is read, and the
        ones whose importers declare dependencies are merged; the environment is the tool that
        installs, not a dependency of the project."""
        from cordon_scanner.core.datayaml import DataYaml

        pieces = [p for p in cls.DOCUMENT_BREAK.split(content.text) if p.strip()]
        if len(pieces) <= 1:
            return DataYaml.load(content.text, source=content.path)
        documents = [
            d
            for d in (DataYaml.load(p, source=content.path) for p in pieces)
            if isinstance(d, dict)
        ]
        projects = [
            d
            for d in documents
            if isinstance(d.get("importers"), dict)
            and any(
                isinstance(i, dict) and any(i.get(s) for s in cls.SECTIONS)
                for i in d["importers"].values()
            )
        ] or documents
        merged: dict[str, Any] = dict(projects[0])
        for document in projects[1:]:
            for key in ("importers", "packages", "snapshots"):
                if isinstance(document.get(key), dict):
                    merged[key] = {**document[key], **(merged.get(key) or {})}
        return merged

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        from cordon_scanner.core.datayaml import DataYamlError

        try:
            data = cls._project_document(content)
        except DataYamlError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid YAML: {exc}"
            )
        if not isinstance(data, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="top level is not a mapping"
            )
        raw_importers = data.get("importers")
        importers: dict[str, Any] = (
            raw_importers
            if isinstance(raw_importers, dict)
            else {".": {k: data.get(k) for k in (*cls.SECTIONS, "specifiers")}}
        )
        raw_packages, raw_snapshots = data.get("packages"), data.get("snapshots")
        packages: dict[str, Any] = raw_packages if isinstance(raw_packages, dict) else {}
        snapshots: dict[str, Any] = raw_snapshots if isinstance(raw_snapshots, dict) else {}

        metas: dict[str, dict[str, Any]] = {}
        for key, meta in packages.items():
            metas[str(key).split("(", 1)[0]] = meta if isinstance(meta, dict) else {}
        for key in snapshots:
            metas.setdefault(str(key).split("(", 1)[0], {})

        def resolve(name: str, reference: str) -> tuple[str | None, str | None, str]:
            """`(package key, alias, real name)` a reference lands on, or no key for a link."""
            real, ref, alias = cls._target(name, reference)
            if ref.startswith("link:"):
                return None, alias, real
            for candidate in cls._candidates(real, ref):
                base = candidate.split("(", 1)[0]
                if base in metas:
                    return base, alias, real
            return None, alias, real

        edges: dict[str, set[str]] = {}
        names: dict[str, str] = {}
        aliases: dict[str, str] = {}
        for key, meta in [*packages.items(), *snapshots.items()]:
            base = str(key).split("(", 1)[0]
            if not isinstance(meta, dict):
                continue
            for field in ("dependencies", "optionalDependencies"):
                section = meta.get(field)
                if not isinstance(section, dict):
                    continue
                for dep, reference in section.items():
                    target, alias, real = resolve(str(dep), str(reference))
                    if target is not None:
                        edges.setdefault(base, set()).add(target)
                        names[target] = real
                        if alias:
                            aliases.setdefault(target, alias)

        roots: dict[str, set[Scope]] = {}
        direct: set[str] = set()
        local: list[LockEntry] = []
        members = sorted(str(k) for k in importers if str(k) not in (".", ""))
        for sections in importers.values():
            if not isinstance(sections, dict):
                continue
            for field, scope in cls.SECTIONS.items():
                section = sections.get(field)
                if not isinstance(section, dict):
                    continue
                for dep, value in section.items():
                    reference = str(value.get("version") if isinstance(value, dict) else value)
                    target, alias, real = resolve(str(dep), reference)
                    if target is None:
                        if reference.startswith("link:"):
                            local.append(
                                LockEntry(
                                    name=real,
                                    version="",
                                    resolved_from=reference,
                                    scope=scope,
                                    direct=True,
                                    local=True,
                                    alias=alias,
                                )
                            )
                        continue
                    roots.setdefault(target, set()).add(scope)
                    direct.add(target)
                    names[target] = real
                    if alias:
                        aliases.setdefault(target, alias)

        scopes = LockScopes.propagate(roots, edges)
        entries: list[LockEntry] = list(local)
        unreadable = 0
        for key, meta in sorted(metas.items()):
            name, version = cls._identity(key, meta)
            name = names.get(key, name)
            if not version:
                unreadable += 1
                continue
            raw_resolution = meta.get("resolution")
            resolution: dict[str, Any] = raw_resolution if isinstance(raw_resolution, dict) else {}
            integrity = (
                resolution.get("integrity")
                if isinstance(resolution.get("integrity"), str)
                else None
            )
            resolved = (
                resolution.get("tarball") if isinstance(resolution.get("tarball"), str) else None
            )
            if resolution.get("type") == "git" and resolution.get("repo"):
                resolved = f"git+{resolution['repo']}#{resolution.get('commit', '')}"
            scope = scopes.get(key, Scope.RUNTIME)
            if meta.get("dev") is True:
                scope = Scope.DEV
            elif meta.get("optional") is True and scope is Scope.RUNTIME and key not in roots:
                scope = Scope.OPTIONAL
            snapshot = snapshots.get(key)
            if isinstance(snapshot, dict) and snapshot.get("optional") is True and key not in roots:
                scope = Scope.OPTIONAL
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=integrity,
                    resolved_from=resolved,
                    scope=scope,
                    dependencies=tuple(
                        sorted(
                            {
                                names.get(t, cls._identity(t, metas.get(t, {}))[0])
                                for t in edges.get(key, ())
                            }
                        )
                    ),
                    direct=key in direct,
                    local=str(resolved or "").startswith(("link:", "file:"))
                    or resolution.get("type") == "directory",
                    platform=NpmEcosystem._platform(meta),
                    alias=aliases.get(key),
                )
            )
        if not entries and (unreadable or packages):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"the lockfile declares packages and none could be read ({unreadable} unreadable key(s))",
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            workspaces=tuple(members),
        )


class YarnLock:
    """Yarn's lockfile: Classic (v1, its own format) and Berry (2+, YAML).

    Both key an entry by the descriptors that resolved to it (`"lodash@^4.17.20, lodash@^4.17.21"`)
    and list each entry's dependencies as descriptors, so the edges are followed descriptor to
    entry -- which is also how an alias (`chalk-four@npm:chalk@4.1.2`) is seen to be `chalk`.

    Code that is not fetched carries no hash and is the project's own: Berry's `workspace:`,
    `link:`, `portal:`, `file:` and `exec:` protocols, a `linkType: soft`, and `patch:` (Yarn
    applying a built-in compatibility patch to a package that carries its own checksum one entry
    away). Every Berry lockfile also holds the root workspace itself (`app@workspace:.`); that is
    the project, not one of its dependencies, so it contributes the direct edges and no entry.
    """

    LOCAL_PROTOCOLS = ("workspace:", "link:", "portal:", "file:", "exec:", "patch:")
    LOCAL_VERSION = "0.0.0-use.local"

    @staticmethod
    def descriptor_name(descriptor: str) -> tuple[str, str]:
        """`(name, range)` of `name@range`, keeping a scope's leading `@`."""
        text = descriptor.strip().strip('"')
        at = text.find("@", 1 if text.startswith("@") else 0)
        if at <= 0:
            return text, ""
        return text[:at], text[at + 1 :]

    @staticmethod
    def alias_target(reference: str) -> str | None:
        """`npm:chalk@4.1.2` names `chalk`; `npm:^4.1.0` names nothing."""
        if not reference.startswith("npm:"):
            return None
        body = reference[4:]
        at = body.find("@", 1 if body.startswith("@") else 0)
        return body[:at] if at > 0 else None

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        text = content.text
        # Berry is YAML: `__metadata:` in a whole file, `version: 1.2.3` (with a colon) in any
        # entry. Classic writes `version "1.2.3"`.
        if "__metadata:" in text or re.search(r"(?m)^ {2}(?:version|resolution|checksum):\s", text):
            return cls._berry(content, ecosystem)
        return cls._classic(content, ecosystem)

    @classmethod
    def _graph(
        cls,
        content: FileContent,
        ecosystem: str,
        blocks: list[tuple[list[str], dict[str, Any]]],
        *,
        berry: bool,
    ) -> LockGraph:
        by_descriptor: dict[str, int] = {}
        for index, (descriptors, _) in enumerate(blocks):
            for descriptor in descriptors:
                by_descriptor[descriptor] = index
        names: list[str] = []
        root_indices: set[int] = set()
        members: list[str] = []
        for descriptors, meta in blocks:
            resolution = str(meta.get("resolution") or "")
            name = cls.descriptor_name(resolution)[0] if resolution else ""
            if not name:
                first, reference = cls.descriptor_name(descriptors[0])
                name = cls.alias_target(reference) or first
            names.append(name)
        edges: dict[int, set[int]] = {}
        for index, (_descriptors, meta) in enumerate(blocks):
            resolution = str(meta.get("resolution") or "")
            protocol = cls.descriptor_name(resolution)[1] if resolution else ""
            if protocol == "workspace:.":
                root_indices.add(index)
            elif protocol.startswith("workspace:"):
                members.append(protocol[len("workspace:") :])
            for field in ("dependencies", "optionalDependencies"):
                section = meta.get(field)
                if not isinstance(section, dict):
                    continue
                for dep, reference in section.items():
                    descriptor = f"{dep}@{reference}"
                    if berry and not str(reference).startswith(
                        tuple(
                            p
                            for p in (
                                "npm:",
                                "workspace:",
                                "patch:",
                                "link:",
                                "portal:",
                                "file:",
                                "exec:",
                                "git",
                                "http",
                                "github:",
                            )
                        )
                    ):
                        descriptor = f"{dep}@npm:{reference}"
                    target = by_descriptor.get(descriptor)
                    if target is None:
                        target = by_descriptor.get(f"{dep}@{reference}")
                    if target is not None:
                        edges.setdefault(index, set()).add(target)
        direct = {t for r in root_indices for t in edges.get(r, ())}
        for index, (_, meta) in enumerate(blocks):
            resolution = str(meta.get("resolution") or "")
            if (
                cls.descriptor_name(resolution)[1].startswith("workspace:")
                and index not in root_indices
            ):
                direct |= edges.get(index, set())
        entries: list[LockEntry] = []
        for index, (descriptors, meta) in enumerate(blocks):
            if index in root_indices:
                continue
            resolution = str(meta.get("resolution") or "")
            protocol = cls.descriptor_name(resolution)[1] if resolution else ""
            version = str(meta.get("version") or "")
            local = (
                any(protocol.startswith(p) for p in cls.LOCAL_PROTOCOLS)
                or any(
                    cls.descriptor_name(d)[1].startswith(cls.LOCAL_PROTOCOLS) for d in descriptors
                )
                or meta.get("linkType") == "soft"
                or version == cls.LOCAL_VERSION
            )
            declared_names = {cls.descriptor_name(d)[0] for d in descriptors}
            alias = next((n for n in sorted(declared_names) if n != names[index]), None)
            resolved = meta.get("resolved") if isinstance(meta.get("resolved"), str) else None
            if berry and protocol and not protocol.startswith("npm:") and not local:
                resolved = protocol
            integrity = meta.get("integrity") or meta.get("checksum")
            platform: list[str] = []
            conditions = meta.get("conditions")
            if isinstance(conditions, str):
                platform.extend(c.strip().replace("=", ": ", 1) for c in conditions.split("&"))
            entries.append(
                LockEntry(
                    name=names[index],
                    version="" if version == cls.LOCAL_VERSION else version,
                    integrity=str(integrity) if isinstance(integrity, str) else None,
                    resolved_from=resolved,
                    dependencies=tuple(sorted({names[t] for t in edges.get(index, ())})),
                    direct=index in direct,
                    local=local,
                    platform=tuple(platform),
                    alias=alias,
                )
            )
        # Berry records a workspace member twice when the root also names it by path
        # (`local-util@workspace:packages/util` and `local-util@file:packages/util`): one
        # package, kept once, with the version the member's own manifest gives it.
        kept: dict[str, LockEntry] = {}
        out: list[LockEntry] = []
        for entry in entries:
            if not entry.local:
                out.append(entry)
                continue
            previous = kept.get(entry.name)
            if previous is None or (not previous.version and entry.version):
                kept[entry.name] = entry
        out.extend(kept.values())
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(out),
            workspaces=tuple(sorted(members)),
        )

    @classmethod
    def _berry(cls, content: FileContent, ecosystem: str) -> LockGraph:
        from cordon_scanner.core.datayaml import DataYaml, DataYamlError

        try:
            data = DataYaml.load(content.text, source=content.path)
        except DataYamlError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid YAML: {exc}"
            )
        if not isinstance(data, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="top level is not a mapping"
            )
        blocks = [
            ([d.strip() for d in str(key).split(",") if d.strip()], meta)
            for key, meta in data.items()
            if key != "__metadata" and isinstance(meta, dict)
        ]
        if not blocks and len(data) > 1:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no entry could be read"
            )
        return cls._graph(content, ecosystem, blocks, berry=True)

    _CLASSIC_FIELD = re.compile(r'^(\s+)("?[^"\s]+"?)\s+"?([^"]*)"?\s*$')

    @classmethod
    def _classic(cls, content: FileContent, ecosystem: str) -> LockGraph:
        blocks: list[tuple[list[str], dict[str, Any]]] = []
        current: dict[str, Any] | None = None
        section: dict[str, str] | None = None
        unreadable = 0
        for raw in content.text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if not raw[0].isspace():
                header = raw.strip().rstrip(":")
                descriptors = [d.strip().strip('"') for d in header.split(",") if d.strip()]
                if not raw.rstrip().endswith(":") or not descriptors:
                    unreadable += 1
                    current = None
                    continue
                current = {}
                section = None
                blocks.append((descriptors, current))
                continue
            if current is None:
                continue
            indent = len(raw) - len(raw.lstrip())
            stripped = raw.strip()
            if stripped.endswith(":") and " " not in stripped:
                section = {}
                current[stripped[:-1]] = section
                continue
            match = cls._CLASSIC_FIELD.match(raw)
            if not match:
                continue
            key, value = match.group(2).strip('"'), match.group(3)
            if indent > 2 and section is not None:
                section[key] = value
            else:
                section = None
                current[key] = value
        if unreadable and not blocks:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} entry header(s) could not be read",
            )
        return cls._graph(content, ecosystem, blocks, berry=False)


class BunLock:
    """Bun's text lockfile (`bun.lock`, the default since Bun 1.2).

    JSON with trailing commas. `workspaces` holds each workspace's declared dependencies, keyed by
    its path (`""` is the root); `packages` maps an install path to an array whose first element
    is `name@version`. A registry package's array is `[spec, registry, metadata, integrity]`, with
    an empty registry meaning the default; a workspace, `file:` or `link:` package is the project's
    own code, and a git or tarball package resolves somewhere other than a registry.
    """

    LOCAL_PREFIXES = ("workspace:", "file:", "link:")
    REMOTE_PREFIXES = ("github:", "git+", "git:", "http://", "https://")

    @staticmethod
    def without_trailing_commas(text: str) -> str:
        """The document with every comma that closes an object or array removed, outside strings."""
        out: list[str] = []
        in_string = escaped = False
        pending = ""
        for char in text:
            if in_string:
                out.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if pending:
                if char in " \t\r\n":
                    pending += char
                    continue
                out.append(pending[1:] if char in "}]" else pending)
                pending = ""
            if char == ",":
                pending = ","
                continue
            if char == '"':
                in_string = True
            out.append(char)
        out.append(pending)
        return "".join(out)

    @staticmethod
    def split_spec(spec: str) -> tuple[str, str]:
        """`@scope/name@1.2.3` as (`@scope/name`, `1.2.3`); the version is everything after the
        `@` that follows the name."""
        at = spec.find("@", 1)
        return (spec, "") if at <= 0 else (spec[:at], spec[at + 1 :])

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(cls.without_trailing_commas(content.text))
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid bun.lock: {exc}"
            )
        raw_workspaces = data.get("workspaces")
        workspaces: dict[str, Any] = raw_workspaces if isinstance(raw_workspaces, dict) else {}
        declared: set[str] = set()
        development: set[str] = set()
        for workspace in workspaces.values():
            if not isinstance(workspace, dict):
                continue
            for field in (
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "devDependencies",
            ):
                section = workspace.get(field)
                if isinstance(section, dict):
                    declared.update(str(name) for name in section)
                    if field == "devDependencies":
                        development.update(str(name) for name in section)
        # Dev only when no workspace also asks for it at runtime.
        development_only = development - {
            name
            for workspace in workspaces.values()
            if isinstance(workspace, dict)
            for field in ("dependencies", "optionalDependencies", "peerDependencies")
            if isinstance(workspace.get(field), dict)
            for name in workspace[field]
        }
        optional_only = {
            name
            for workspace in workspaces.values()
            if isinstance(workspace, dict)
            and isinstance(workspace.get("optionalDependencies"), dict)
            for name in workspace["optionalDependencies"]
        } - {
            name
            for workspace in workspaces.values()
            if isinstance(workspace, dict)
            for field in ("dependencies", "peerDependencies", "devDependencies")
            if isinstance(workspace.get(field), dict)
            for name in workspace[field]
        }
        member_versions = {
            str(w.get("name")): str(w.get("version") or "")
            for path, w in workspaces.items()
            if path and isinstance(w, dict) and w.get("name")
        }
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return LockGraph(path=content.path, ecosystem=ecosystem)
        entries: list[LockEntry] = []
        for location, value in sorted(packages.items()):
            if not isinstance(value, list) or not value or not isinstance(value[0], str):
                continue
            name, version = cls.split_spec(value[0])
            if not name:
                continue
            local = version.startswith(cls.LOCAL_PREFIXES)
            remote = version.startswith(cls.REMOTE_PREFIXES)
            registry = value[1] if len(value) > 1 and isinstance(value[1], str) else ""
            metadata = next((v for v in value[1:] if isinstance(v, dict)), {})
            integrity = value[3] if len(value) > 3 and isinstance(value[3], str) else None
            requires: set[str] = set()
            for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                section = metadata.get(field)
                if isinstance(section, dict):
                    requires.update(str(dep) for dep in section)
            top = "/" not in location.removeprefix(name)
            if top and name in development_only:
                scope = Scope.DEV
            elif top and name in optional_only:
                scope = Scope.OPTIONAL
            else:
                scope = Scope.RUNTIME
            entries.append(
                LockEntry(
                    name=name,
                    version=member_versions.get(name, "") if local else ("" if remote else version),
                    integrity=integrity if integrity and integrity.startswith("sha") else None,
                    resolved_from=version if remote else (registry or None),
                    scope=scope,
                    dependencies=tuple(sorted(requires)),
                    direct=top and name in declared,
                    local=local,
                    platform=NpmEcosystem._platform(metadata),
                )
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            workspaces=tuple(sorted(p for p in workspaces if p)),
        )


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

    @staticmethod
    def _direct(data: dict[str, Any], specifiers: dict[str, Any]) -> frozenset[str]:
        """The npm packages the project names itself: the workspace's own list where Deno records
        one, otherwise every `npm:` specifier (each is something an import or config named)."""
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


class NpmManifest:
    """What a package.json claims about where it comes from."""

    @staticmethod
    def _repository_of(data: dict[str, object]) -> str | None:
        """The source repository a `package.json` claims.

        npm accepts either a string or an object with a `url`, and both are common.
        Returned verbatim; normalising for comparison is the caller's job, because
        what counts as "the same repository" is a question about the comparison
        rather than about the manifest.
        """
        field = data.get("repository")
        if isinstance(field, str) and field:
            return field
        if isinstance(field, dict):
            url = field.get("url")
            if isinstance(url, str) and url:
                return url
        return None
