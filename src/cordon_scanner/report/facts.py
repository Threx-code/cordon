"""The learning loop's facts export, `facts/v1`: what a scan found out about a package, as facts and counts.

Cordon Cloud's analysis fleet scans every captured release with `--format facts`, and the learning loop
(`reviews/self-improving/10-LEARNING-LOOP.md`, row LL-1) learns from these records, never from a package's
bytes. So the record carries no text the package wrote: no path, no file name, no message, no evidence, no
host. What it does carry is the scanner's own vocabulary about the package:

* per file, keyed by a digest of its path: its extension class, the places it runs from (an install hook, an
  import entry, an agent's tool handler ...), whether any place reaches it, the rule ids that fired on it with
  their counts, and the capabilities those findings name;
* per package: the scan's completeness and the rules of its gaps, the files scanned, how many files each
  place holds, each lifecycle hook's kind and the programs it runs (the first word of each command segment,
  a bare name), dependency counts, and the package-level rule ids.

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

from cordon_scanner.report.base import BaseReporter, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.foundation.results import ScanResult

FACTS_VERSION: Final = "1"
PACKAGE_SCOPE: Final = "."
"""The path a finding about the whole package carries (`engine.pipeline.constants.REPOSITORY_SCOPE`)."""

_EXTENSION: Final = re.compile(r"\.([a-z0-9]{1,8})$")
_PROGRAM: Final = re.compile(r"[A-Za-z0-9._+-]{1,32}")
_SEGMENT: Final = re.compile(r"&&|\|\||[;|&\n]")
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_RULE_ID: Final = re.compile(r"[A-Z0-9_.\-]{1,96}")


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
        match = _EXTENSION.search(base)
        return match.group(1) if match and base != "." + match.group(1) else ""

    @staticmethod
    def programs(command: str) -> list[str]:
        """The programs a hook command runs: the first word of each segment, without arguments or a path,
        kept only when it is a plain name (the masked-digest terms for lifecycle hooks)."""
        names = []
        for segment in _SEGMENT.split(command):
            words = [w for w in segment.split() if not _ASSIGNMENT.match(w)]
            if not words:
                continue
            first = words[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if _PROGRAM.fullmatch(first):
                names.append(first)
        return names

    @staticmethod
    def rule_id(rule: str) -> str:
        """A rule id as it may appear in the record: the scanner's own ids only (a delivered pack's ids
        follow the same form); anything else is counted under one name rather than copied."""
        return rule if _RULE_ID.fullmatch(rule) else "OTHER"

    @staticmethod
    def of(result: ScanResult) -> dict[str, Any]:
        places = result.places or {}
        located: dict[str, set[str]] = defaultdict(set)
        for place, paths in places.items():
            for path in paths:
                located[path].add(place)

        rules: dict[str, Counter[str]] = defaultdict(Counter)
        capabilities: dict[str, set[str]] = defaultdict(set)
        package_rules: Counter[str] = Counter()
        for finding in result.findings:
            if finding.is_suppressed:
                continue
            path = finding.location.path
            rule = ScanFacts.rule_id(finding.rule_id)
            if not path or path == PACKAGE_SCOPE:
                package_rules[rule] += max(1, finding.occurrences)
                continue
            rules[path][rule] += max(1, finding.occurrences)
            capabilities[path].update(str(c) for c in finding.capabilities)

        files = []
        for path in set(rules) | set(located):
            files.append(
                {
                    "key": ScanFacts.file_key(path),
                    "ext": ScanFacts.extension(path),
                    "places": sorted(located.get(path, ())),
                    "reached": bool(located.get(path)),
                    "rules": dict(sorted(rules[path].items())) if path in rules else {},
                    "capabilities": sorted(capabilities.get(path, ())),
                }
            )
        files.sort(key=lambda f: (f["key"], f["ext"]))

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
                "rules": dict(sorted(package_rules.items())),
                "unreached_capability_files": sum(
                    1 for f in files if not f["reached"] and f["capabilities"]
                ),
            },
            "files": files,
        }
        record["digest"] = hashlib.sha256(ScanFacts.canonical(record)).hexdigest()
        return record

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


__all__ = ["FACTS_VERSION", "FactsReporter", "ScanFacts"]
