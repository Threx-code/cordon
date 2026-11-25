"""The learning loop's facts export, `facts/v1`: what a scan found out about a package, as facts and counts.

Cordon Cloud's analysis fleet scans every captured release with `--format facts`, and the learning loop
(`reviews/self-improving/10-LEARNING-LOOP.md`, row LL-1) learns from these records, never from a package's
bytes. So the record carries no text the package wrote: no path, no file name, no message, no evidence, no
host. What it does carry is the scanner's own vocabulary about the package:

* per file, keyed by a digest of its path: its extension class (from a closed list), the places it runs from
  (an install hook, an import entry, an agent's tool handler ...), whether any place reaches it and how (`reach`: placed,
  declared_entry, hook_command, require_chain, path_string, stem_only or unreached, or not_code, with its `reach_depth`;
  `decide/reach.py`), the rule ids that
  fired on it with their counts (suppressed ones counted again apart), its capabilities (every file the capability
  detector read, reached or not), the salted digests of the URL hosts and domains a file that reaches the network names
  (never the names), and, for a file left unread, the rule of its gap;
* per package: the scan's completeness and the rules of its gaps, the files scanned and unread, how many files
  each place holds, each lifecycle hook's kind and the programs it runs (from a closed list of tools), dependency
  counts, the number of files scanned under each extension class (a quiet native file no finding lists is still counted), the number
  under each size class, how many encoded literals the text files hold of each kind (base64, hex, hex escapes, unicode escapes: counts, never the
  literals), how many agent instruction files there are, how many tools a package declares as data, and the package-level rule ids. The scanner has
  no source for the age of a publisher: whoever captures the release records it.

Every name in the record comes from a closed vocabulary: a rule id only from a Cordon pack, a program or an
extension only from its list; anything else is OTHER. Counts and the file list are bounded.

The record is canonical (sorted keys, no whitespace, no timestamp) and carries the digest of its own canonical
form, so two scans of the same content by the same scanner give the same bytes and the same digest.
`facts_version` changes whenever a field changes meaning; a fact the loop learned from an older version is
not read against a newer one."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.reach import MAX_DEPTH, FileReach
from cordon_scanner.foundation.files.extension import FileExtension
from cordon_scanner.foundation.files.file_facts import FileFacts
from cordon_scanner.foundation.results import INTERNAL_PREFIX
from cordon_scanner.report.base import BaseReporter, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.foundation.results import ScanResult

FACTS_VERSION: Final = "6"
PACKAGE_SCOPE: Final = "."
"""The path a finding about the whole package carries (`engine.pipeline.constants.REPOSITORY_SCOPE`)."""

_SEGMENT: Final = re.compile(r"&&|\|\||[;|&\n]")
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_RULE_ID: Final = re.compile(r"[A-Z0-9_.\-]{1,96}")
OTHER: Final = "OTHER"
MAX_FILES: Final = 5_000
"""File entries in one record at most: files with a capability, a finding or an unread state first; the rest are
counted (`files_omitted`), so a package of a hundred thousand files cannot make a record of megabytes."""
REACH_KINDS: Final = frozenset(FileReach.KINDS)
"""How a file is reached, from `FileReach` (a closed list): a file that is not code is `not_code`; anything else is OTHER."""
MAX_BINARIES: Final = 256
"""Native file digests in one record at most; `package.binaries_truncated` says when there were more or one could not be hashed."""
MAX_COUNT: Final = 1_000
"""A count above this is recorded as this: a package that emits a million hits is not a distinguishing number."""
MAX_FILE_COUNT: Final = 1_000_000
"""A count of files in one size class is recorded as no more than this."""

PROGRAMS: Final = frozenset(
    {
        "node", "nodejs", "npm", "npx", "pnpm", "yarn", "bun", "bunx", "deno", "python", "python3", "pip", "pip3",
        "uv", "sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh", "node-gyp", "node-pre-gyp", "node-gyp-build",
        "prebuild", "prebuild-install", "cmake-js", "husky", "tsc", "tsx", "ts-node", "esbuild", "webpack",
        "rollup", "vite", "babel", "patch-package", "opencollective", "opencollective-postinstall", "echo", "exit",
        "true", "false", "cp", "mv", "rm", "mkdir", "chmod", "ln", "touch", "cat", "test", "cd", "curl", "wget",
        "git", "make", "cmake", "go", "cargo", "rustc", "gcc", "cc", "java", "ruby", "perl", "php", "dotnet",
        "electron-rebuild", "electron-builder", "ngcc", "lerna", "nx", "turbo", "rimraf", "shx", "cross-env",
        "prisma", "playwright", "puppeteer", "setup.py", "install.js", "postinstall.js", "preinstall.js",
    }
)  # fmt: skip
"""The programs a hook record may name: well-known tools and the conventional hook script names. Anything else (a
private script, a project's own tool) is recorded as OTHER: the record never carries a name a package chose."""

EXTENSIONS: Final = frozenset(
    {
        "js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx", "py", "pyw", "pyi", "pth", "sh", "bash", "zsh",
        "ps1", "psm1", "bat", "cmd", "vbs", "rb", "php", "go", "rs", "java", "kt", "cs", "c", "h", "cc", "cpp",
        "hpp", "m", "swift", "lua", "pl", "pm", "r", "json", "yaml", "yml", "toml", "ini", "cfg", "xml", "md",
        "mdc", "txt", "rst", "html", "htm", "css", "wasm", "node", "so", "dll", "dylib", "exe", "bin", "jar",
        "class", "pyc", "whl", "zip", "tgz", "gz", "tar", "map", "lock", "env", "sql", "graphql", "proto", "svg",
        "png", "jpg", "jpeg", "gif", "ico", "woff", "woff2", "ttf",
    }
)  # fmt: skip
"""The extension classes a file record may name; any other extension is recorded as `other`."""

CORDON_PACKS: Final = ("cordon-builtin", "cordon.", "learned.")
"""The rule packs whose rule ids a record copies: the bundled packs and the learning loop's own. A rule from any
other pack (an organisation's own) is recorded as OTHER, so its id, which can name a project, never leaves."""


class ScanFacts:
    """Builds the `facts/v1` record of a scan result. Stateless; call `of`."""

    @staticmethod
    def file_key(path: str) -> str:
        """A path's key in the record: the first 16 hex digits of its sha256, never the path."""
        return hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()[:16]

    @staticmethod
    def extension(path: str) -> str:
        """The extension class of a path: empty for none, its extension when it is on the closed list, else `other`."""
        extension = FileExtension.of(path)
        return extension if not extension or extension in EXTENSIONS else "other"

    @staticmethod
    def extension_counts(counts: Mapping[str, int]) -> dict[str, int]:
        """The scan's per-extension file counts (`ScanResult.extensions`) as the record holds them: every scanned file under a class of the
        closed list, `none` for a name with no extension and `other` for the rest, so a native file no finding or capability lists is
        still counted."""
        classed: dict[str, int] = {}
        for raw, count in counts.items():
            name = "none" if not raw else (raw if raw in EXTENSIONS else "other")
            classed[name] = classed.get(name, 0) + int(count)
        return dict(sorted(classed.items()))

    @staticmethod
    def file_counts(result: ScanResult) -> dict[str, Any]:
        """What the scan counted about its files: by size class, the encoded literals by kind, the agent instruction files, and the tools declared as data."""
        return {
            "size_classes": ScanFacts.size_classes(result.size_classes or {}),
            "encoded_literals": ScanFacts.encoded_literals(result.encoded_literals or {}),
            "instruction_files": result.instruction_files or 0,
            "mcp_tools": len(result.tool_list or ()),
        }

    @staticmethod
    def size_classes(counts: Mapping[str, int]) -> dict[str, int]:
        """The scan's files by size class: every class of the closed list is in the answer, a class with no file at zero."""
        names = [name for name, _bound in FileFacts.SIZE_CLASSES] + [FileFacts.HUGE]
        return {name: min(int(counts.get(name, 0)), MAX_FILE_COUNT) for name in names}

    @staticmethod
    def encoded_literals(counts: Mapping[str, int]) -> dict[str, int]:
        """The encoded literals the scan counted, by kind: every kind of the closed list is in the answer, a kind with none at zero, a count capped."""
        return {kind: min(int(counts.get(kind, 0)), MAX_COUNT) for kind in FileFacts.ENCODINGS}

    @staticmethod
    def programs(command: str) -> list[str]:
        """The programs a hook command runs: the first word of each segment, without arguments or a path, named
        only when it is in `PROGRAMS`, else OTHER."""
        names = []
        for segment in _SEGMENT.split(command):
            words = [w for w in segment.split() if not _ASSIGNMENT.match(w)]
            if not words:
                continue
            first = words[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            names.append(first if first in PROGRAMS else OTHER)
        return names

    @staticmethod
    def rule_id(rule: str, pack: str = "cordon-builtin") -> str:
        """A rule id as it may appear in the record: copied only when a Cordon pack made it (`CORDON_PACKS`) and it
        has the scanner's form; anything else is counted under OTHER rather than copied."""
        ours = pack == CORDON_PACKS[0] or pack.startswith(CORDON_PACKS[1:])
        return rule if ours and _RULE_ID.fullmatch(rule) else OTHER

    @staticmethod
    def of(result: ScanResult) -> dict[str, Any]:
        places = result.places or {}
        located: dict[str, set[str]] = defaultdict(set)
        for place, paths in places.items():
            for path in paths:
                located[path].add(place)

        rules: dict[str, Counter[str]] = defaultdict(Counter)
        suppressed: dict[str, Counter[str]] = defaultdict(Counter)
        capabilities: dict[str, set[str]] = defaultdict(set)
        package_rules: Counter[str] = Counter()
        package_suppressed: Counter[str] = Counter()
        findings = result.unfiltered if result.unfiltered is not None else result.findings
        for finding in findings:
            # A suppressed finding is still a fact (a suppression the package or its configuration carries must not
            # blind the learning loop); it is counted again apart, so the record says it was hidden.
            if finding.rule_id.startswith(INTERNAL_PREFIX):
                continue
            path = finding.location.path
            rule = ScanFacts.rule_id(finding.rule_id, finding.rulepack)
            count = max(1, finding.occurrences)
            package = not path or path == PACKAGE_SCOPE
            (package_rules if package else rules[path])[rule] += count
            if finding.is_suppressed:
                (package_suppressed if package else suppressed[path])[rule] += count
            if not package:
                capabilities[path].update(str(c) for c in finding.capabilities)

        for path, names in (result.capabilities or {}).items():
            capabilities[path].update(names)
        files, unreached_capability_files, omitted, files_unread = ScanFacts.files(
            result, located, rules, suppressed, capabilities
        )
        reached_by = Counter(
            ScanFacts.reach_kind(kind) for kind, _depth in (result.reach or {}).values()
        )

        repository = result.repository
        hooks = []
        for hook in repository.hooks if repository is not None else ():
            hooks.append({"kind": hook.kind, "programs": ScanFacts.programs(hook.command)})
        hooks.sort(key=lambda h: (h["kind"], h["programs"]))

        dependencies = result.dependencies
        record: dict[str, Any] = {
            "facts_version": FACTS_VERSION,
            "engine_version": result.engine_version,
            "rulepack_hash": result.rulepack_hash,
            "config_hash": result.config_hash,
            "target_kind": result.target_kind,
            "complete": result.complete,
            "content_complete": result.content_complete,
            "gaps": dict(
                sorted(
                    Counter(ScanFacts.rule_id(rule) for rule, _path in result.content_gaps).items()
                )
            ),
            "package": {
                "files_scanned": result.stats.files_scanned,
                "extensions": ScanFacts.extension_counts(result.extensions or {}),
                **ScanFacts.file_counts(result),
                "places": {place: len(paths) for place, paths in sorted(places.items())},
                "hooks": hooks,
                "dependencies": {
                    "total": len(dependencies),
                    "direct": sum(1 for d in dependencies if d.direct),
                    "local": sum(1 for d in dependencies if d.local),
                },
                "reach": dict(sorted(reached_by.items())),
                "rules": ScanFacts.capped(package_rules),
                "suppressed": ScanFacts.capped(package_suppressed),
                "unreached_capability_files": unreached_capability_files,
                "hosts_distinct": len(
                    {h for hosts, _domains in (result.destinations or {}).values() for h in hosts}
                ),
                "domains_distinct": len(
                    {d for _hosts, domains in (result.destinations or {}).values() for d in domains}
                ),
                "files_unread": files_unread,
                "files_omitted": omitted,
                "binaries": ScanFacts.binaries(result),
                "binaries_truncated": ScanFacts.binaries_truncated(result),
                "tool_list": ScanFacts.tool_list(result),
            },
            "files": files,
        }
        record["package"].update(ScanFacts.reuse(result))
        record["digest"] = hashlib.sha256(ScanFacts.canonical(record)).hexdigest()
        return record

    @staticmethod
    def files(
        result: ScanResult,
        located: Mapping[str, set[str]],
        rules: Mapping[str, Counter[str]],
        suppressed: Mapping[str, Counter[str]],
        capabilities: Mapping[str, set[str]],
    ) -> tuple[list[dict[str, Any]], int, int, int]:
        """The file entries (bounded, files with a capability or an unread state first), the count of files with a
        capability nothing reaches, the count left out, and the count unread."""
        reach = result.reach or {}
        destinations = result.destinations or {}
        unread: dict[str, set[str]] = defaultdict(set)
        for rule, path in result.content_gaps:
            if path and path != PACKAGE_SCOPE:
                unread[path].add(ScanFacts.rule_id(rule))
        entries = []
        for path in set(rules) | set(capabilities) | set(unread) | set(destinations):
            entries.append(
                {
                    "key": ScanFacts.file_key(path),
                    "ext": ScanFacts.extension(path),
                    "places": sorted(located.get(path, ())),
                    "reached": bool(located.get(path)),
                    "reach": ScanFacts.reach_kind(reach.get(path, ("not_code", 0))[0]),
                    "reach_depth": min(reach.get(path, ("not_code", 0))[1], MAX_DEPTH),
                    "rules": ScanFacts.capped(rules.get(path, {})),
                    "suppressed": ScanFacts.capped(suppressed.get(path, {})),
                    "capabilities": sorted(capabilities.get(path, ())),
                    "hosts": list(destinations.get(path, ((), ()))[0]),
                    "domains": list(destinations.get(path, ((), ()))[1]),
                    "unread": sorted(unread.get(path, ())),
                }
            )
        unreached_capability_files = sum(
            1 for f in entries if not f["reached"] and f["capabilities"]
        )
        entries.sort(key=lambda f: (not (f["capabilities"] or f["unread"]), f["key"], f["ext"]))
        omitted = max(0, len(entries) - MAX_FILES)
        entries = sorted(entries[:MAX_FILES], key=lambda f: (f["key"], f["ext"]))

        return entries, unreached_capability_files, omitted, len(unread)

    @staticmethod
    def reuse(result: ScanResult) -> dict[str, Any]:
        """`{"reuse": ...}`: the package's code-reuse keys (fingerprint crix1) and whether they are all of them, only
        when the scan was asked for them (`reuse_keys`); `{}` otherwise, so every other record's bytes are unchanged."""
        if result.reuse_code is None:
            return {}
        return {
            "reuse": {
                "fingerprint": "crix1",
                "code": list(result.reuse_code),
                "hook": list(result.reuse_hooks or ()),
                "complete": result.reuse_complete,
            }
        }

    @staticmethod
    def binaries(result: ScanResult) -> list[str] | None:
        """The SHA-256 of each native executable or library the scan read, sorted and at most `MAX_BINARIES`; None when the
        scan did not collect them."""
        return None if result.binaries is None else sorted(result.binaries)[:MAX_BINARIES]

    @staticmethod
    def binaries_truncated(result: ScanResult) -> bool:
        """Whether `binaries` is a part of the native files read: more than the cap, or one that could not be hashed whole."""
        return result.binaries is not None and (
            not result.binaries_complete or len(result.binaries) > MAX_BINARIES
        )

    @staticmethod
    def tool_list(result: ScanResult) -> dict[str, Any] | None:
        """How many tools the package declares as data and the digest of that list (`ArtifactDigests.of_tool_list`, the
        function the platform uses), or None when it declares no whole list. Never the tools' names or descriptions: the
        record carries no text a package wrote."""
        if not result.tool_list:
            return None
        return {
            "count": len(result.tool_list),
            "digest": ArtifactDigests.of_tool_list(result.tool_list),
        }

    @staticmethod
    def reach_kind(kind: str) -> str:
        """A reach kind as it may appear in the record: one of `FileReach.KINDS`, `not_code`, else OTHER."""
        return kind if kind in REACH_KINDS or kind == "not_code" else OTHER

    @staticmethod
    def capped(counts: Mapping[str, int]) -> dict[str, int]:
        return {rule: min(n, MAX_COUNT) for rule, n in sorted(counts.items())}

    @staticmethod
    def canonical(record: dict[str, Any]) -> bytes:
        """The record's canonical bytes: sorted keys, no whitespace, the digest field left out."""
        body = {k: v for k, v in record.items() if k != "digest"}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )


class FactsReporter(BaseReporter):
    """`--format facts`: the `facts/v1` record of the scan, one canonical JSON line."""

    id = "facts"
    media_type = "application/json"
    file_extension = ".facts.json"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        record = ScanFacts.of(result)
        yield json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        yield b"\n"


__all__ = ["EXTENSIONS", "FACTS_VERSION", "MAX_FILES", "PROGRAMS", "FactsReporter", "ScanFacts"]
