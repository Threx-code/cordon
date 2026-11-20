"""The learning loop's facts export, `facts/v1`: what a scan found out about a package, as facts and counts.

Cordon Cloud's analysis fleet scans every captured release with `--format facts`, and the learning loop
(`reviews/self-improving/10-LEARNING-LOOP.md`, row LL-1) learns from these records, never from a package's
bytes. So the record carries no text the package wrote: no path, no file name, no message, no evidence, no
host. What it does carry is the scanner's own vocabulary about the package:

* per file, keyed by a digest of its path: its extension class (from a closed list), the places it runs from
  (an install hook, an import entry, an agent's tool handler ...), whether any place reaches it, the rule ids that
  fired on it with their counts (suppressed ones counted again apart), its capabilities (every file the capability
  detector read, reached or not), and, for a file left unread, the rule of its gap;
* per package: the scan's completeness and the rules of its gaps, the files scanned and unread, how many files
  each place holds, each lifecycle hook's kind and the programs it runs (from a closed list of tools), dependency
  counts, and the package-level rule ids.

Every name in the record comes from a closed vocabulary: a rule id only from a Cordon pack, a program or an
extension only from its list; anything else is OTHER. Counts and the file list are bounded.

The record is canonical (sorted keys, no whitespace, no timestamp) and carries the digest of its own canonical
form, so two scans of the same content by the same scanner give the same bytes and the same digest.
`facts_version` changes whenever a field changes meaning; a fact the loop learned from an older version is
not read against a newer one (LL-104)."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.foundation.results import INTERNAL_PREFIX
from cordon_scanner.report.base import BaseReporter, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.foundation.results import ScanResult

FACTS_VERSION: Final = "1"
PACKAGE_SCOPE: Final = "."
"""The path a finding about the whole package carries (`engine.pipeline.constants.REPOSITORY_SCOPE`)."""

_EXTENSION: Final = re.compile(r"\.([a-z0-9]{1,8})$")
_SEGMENT: Final = re.compile(r"&&|\|\||[;|&\n]")
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_RULE_ID: Final = re.compile(r"[A-Z0-9_.\-]{1,96}")
OTHER: Final = "OTHER"
MAX_FILES: Final = 5_000
"""File entries in one record at most: files with a capability, a finding or an unread state first; the rest are
counted (`files_omitted`), so a package of a hundred thousand files cannot make a record of megabytes."""
MAX_COUNT: Final = 1_000
"""A count above this is recorded as this: a package that emits a million hits is not a distinguishing number."""

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
        """The lower-cased extension of the path's last part when it is short and plain, else empty."""
        base = path.rsplit("!", 1)[-1].rsplit("/", 1)[-1].lower()
        dot = base.rfind(".")
        if dot <= 0:
            return ""
        match = _EXTENSION.search(base)
        extension = match.group(1) if match else ""
        return extension if extension in EXTENSIONS else "other"

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
                "places": {place: len(paths) for place, paths in sorted(places.items())},
                "hooks": hooks,
                "dependencies": {
                    "total": len(dependencies),
                    "direct": sum(1 for d in dependencies if d.direct),
                    "local": sum(1 for d in dependencies if d.local),
                },
                "rules": ScanFacts.capped(package_rules),
                "suppressed": ScanFacts.capped(package_suppressed),
                "unreached_capability_files": unreached_capability_files,
                "files_unread": files_unread,
                "files_omitted": omitted,
            },
            "files": files,
        }
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
        unread: dict[str, set[str]] = defaultdict(set)
        for rule, path in result.content_gaps:
            if path and path != PACKAGE_SCOPE:
                unread[path].add(ScanFacts.rule_id(rule))
        entries = []
        for path in set(rules) | set(capabilities) | set(unread):
            entries.append(
                {
                    "key": ScanFacts.file_key(path),
                    "ext": ScanFacts.extension(path),
                    "places": sorted(located.get(path, ())),
                    "reached": bool(located.get(path)),
                    "rules": ScanFacts.capped(rules.get(path, {})),
                    "suppressed": ScanFacts.capped(suppressed.get(path, {})),
                    "capabilities": sorted(capabilities.get(path, ())),
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
