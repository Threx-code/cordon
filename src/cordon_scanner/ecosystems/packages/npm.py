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
from typing import TYPE_CHECKING, Any

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
    ReleaseFile,
)
from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.content import FileContent

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

    def declared_dependencies(self, files: Sequence[ReleaseFile]) -> frozenset[str]:
        """A published tarball's runtime dependencies: its package.json's, optional ones too."""
        manifest = next((f for f in files if f.path.endswith("!package/package.json")), None)
        try:
            document = json.loads(manifest.content.text) if manifest is not None else {}
        except ValueError:
            return frozenset()
        if not isinstance(document, dict):
            return frozenset()
        names: set[str] = set()
        for section in ("dependencies", "optionalDependencies"):
            value = document.get(section)
            if isinstance(value, dict):
                names.update(str(k) for k in value)
        return frozenset(names)

    def namespace(self, name: str, alias: str | None = None) -> str | None:
        return name.split("/", 1)[0] if name.startswith("@") and "/" in name else None

    def is_held_version(self, version: str) -> bool:
        # npm's tombstone for a name its security team took over: the releases removed, and
        # `0.0.1-security` published in their place.
        return bool(re.match(r"^\d+\.\d+\.\d+-security$", version))

    def has_install_scripts(self) -> bool:
        return True

    def has_scoped_names(self) -> bool:
        return True

    def squat_comparisons(self) -> tuple[str, ...]:
        return ("pypi", "rubygems", "cargo")

    purl_type = "npm"
    manifest_globs: tuple[str, ...] = ("**/package.json", "**/deno.json", "**/deno.jsonc")
    #: bundledDependencies: npm installs a tarball's own `node_modules` with it as shipped, and
    #: `require()` loads them -- where a payload can hide in a dependency. Theirs too, recursively.
    installed_with_package: tuple[str, ...] = (
        "node_modules/*/package.json",
        "node_modules/@*/*/package.json",
        "node_modules/**/node_modules/*/package.json",
        "node_modules/**/node_modules/@*/*/package.json",
    )
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
            # Public mirrors of the npm registry, serving its packages under its names: npmmirror's
            # earlier hosts (Taobao, cnpm) and the cloud providers' mirrors. In the long tail they
            # were a common cause of `SUSPECT.LOCKFILE.SOURCE.001` (review 98), and a package
            # resolved from one is the registry's package, so advisories match it as one.
            "registry.npm.taobao.org",
            "npm.taobao.org",
            "r.cnpmjs.org",
            "registry.cnpmjs.org",
            "mirrors.cloud.tencent.com/npm",
            "repo.huaweicloud.com/repository/npm",
            "mirrors.huaweicloud.com/repository/npm",
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
        from cordon_scanner.ecosystems.packages.javascript.deno import DenoManifest

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
        from cordon_scanner.ecosystems.packages.javascript.bun import BunLock
        from cordon_scanner.ecosystems.packages.javascript.deno import DenoLock
        from cordon_scanner.ecosystems.packages.javascript.pnpm import PnpmLock
        from cordon_scanner.ecosystems.packages.javascript.yarn import YarnLock

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
            installed_as, members, linked_as = NpmEcosystem._workspaces(packages, declared)
            NpmEcosystem._v2_entries(packages, linked_as, installed_as, entries, declared, hashed)
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
    def _workspaces(
        packages: dict[Any, Any], declared: set[str]
    ) -> tuple[dict[str, str], list[str], dict[str, str]]:
        """The workspace members, and the name each linked location installs as."""
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
        return installed_as, members, linked_as

    @staticmethod
    def _v2_entries(
        packages: dict[Any, Any],
        linked_as: dict[str, str],
        installed_as: dict[str, str],
        entries: list[LockEntry],
        declared: set[str],
        hashed: set[Any],
    ) -> None:
        """One entry per installed package of a v2 or v3 lockfile, with its edges, scope and integrity."""
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
                    alias=directory if "node_modules/" in location and directory != name else None,
                )
            )

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
        scoped = head.startswith(("/@", "@"))
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


__all__ = ["NpmEcosystem"]


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
