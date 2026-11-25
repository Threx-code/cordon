"""The mutable state of one scan: the findings so far, whether coverage stayed complete, whether every
dependency met an advisory source, and the counters the result reports.

Local to a single run. The engine itself holds no per-scan state, which is what makes one Scanner
instance reusable and safe to share; each phase that adds to a scan is handed this.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.engine.pipeline.constants import INCOMPLETE_WHEN_REPORTED
from cordon_scanner.foundation.files.declared_tools import DeclaredTools
from cordon_scanner.foundation.files.extension import FileExtension
from cordon_scanner.foundation.files.file_facts import FileFacts
from cordon_scanner.foundation.files.native import NativeFile
from cordon_scanner.foundation.models import Finding, Severity
from cordon_scanner.foundation.results import NOT_CONTENT_GAPS, Dependency, OperationalFinding
from cordon_scanner.foundation.taxonomy import AttackCategory

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.content import FileContent


NOTICES = ("OPERATIONAL.INTEL.", "OPERATIONAL.ADVISORY.")
"""Operational findings about the advisory side, which `advisory_complete` reports: none of them
says that a file's content went unexamined."""


@dataclass
class Accumulator:
    """Mutable state for one scan.

    Deliberately local to a single run. The engine itself holds no per-scan
    state, which is what makes one Scanner instance reusable and safe to share.
    """

    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    """Every file's content was read: nothing refused, truncated, pruned or timed out."""
    advisory_complete: bool = True
    """Every dependency was checked against an advisory or registry source, and the threat intel
    was current. A missing feed is reported and never blocks a package for malware purposes
    (review 98, REC-5): the two halves are kept apart so the gate can tell them apart."""
    rejected_archives: set[str] = field(default_factory=set)
    """Archives already reported as read in part (`OPERATIONAL.ARCHIVE.REJECTED`), which the
    truncation notice would only repeat."""
    files_scanned: int = 0
    extensions: dict[str, int] = field(default_factory=dict)
    """Every scanned file counted under its extension (`FileExtension.of`: empty for none, `other` for an odd one). Read by the facts
    export (`package.extensions`), which classes it against its closed list; the keys are bounded by `MAX_EXTENSIONS`."""
    size_classes: dict[str, int] = field(default_factory=dict)
    """Every scanned file counted under its size class (`FileFacts.size_class`). Read by the facts export (`package.size_classes`)."""
    encoded_literals: dict[str, int] = field(default_factory=dict)
    """The encoded literals the scanned text files hold, counted by kind (`FileFacts.encoded_literals`): counts, never the literals. Read by the facts export."""
    instruction_files: int = 0
    """How many scanned files are an agent's instruction files (`FileFacts.is_instruction`). Read by the facts export."""
    binaries: set[str] = field(default_factory=set)
    """The SHA-256 of every native executable or library scanned (`NativeFile`), by the whole file's digest. Read by
    the facts export (`package.binaries`); bounded by `MAX_BINARIES`."""
    binaries_complete: bool = True
    """False when a native file could not be hashed whole (a truncated one with no digest of its whole) or there were
    more than `MAX_BINARIES`: the list is then a part, and says so."""
    reuse_keys: bool = False
    """Whether to collect the package's code-reuse keys (`Config.reuse_keys`): off, nothing below is computed."""
    reuse_code: set[str] = field(default_factory=set)
    """Each code file's `ReuseIndex.fingerprint` (hex), when `reuse_keys`. Read by the facts export (`package.reuse`)."""
    reuse_hooks: set[str] = field(default_factory=set)
    """Each install hook's `HookShape` key (hex) in the package's own package.json, when `reuse_keys`."""
    reuse_complete: bool = True
    campaign_paths: list[str] = field(default_factory=list)
    """Every member path of the package, for its campaign fingerprint's layout (`reuse_keys`); bounded."""
    campaign_paths_complete: bool = True
    """False once a package has more members than `MAX_CAMPAIGN_PATHS`: its layout facet is then not computed."""
    campaign_manifest: tuple[str, str] | None = None
    """`(ecosystem, path)` of the package's root manifest; its facets come from the worker that read it."""
    """False when a code file could not be hashed whole, or past `MAX_REUSE` keys: the keys are then a part, and say so."""
    tool_lists: list[list[dict[str, Any]]] = field(default_factory=list)
    """Each JSON file that declares a whole MCP tool list (`DeclaredTools`), for the facts export (`package.tool_list`)."""
    files_skipped: int = 0
    bytes_scanned: int = 0
    rules_evaluated: int = 0

    facts: dict[str, dict[str, list[Any]]] = field(default_factory=dict)
    """Per-file facts the workers sent back (item 56, `engine/isolation/facts.py`), by path: plain data
    the parent joins across files without parsing any of them."""
    reach: dict[str, tuple[str, int]] | None = None
    """How each code file is reached from a place that runs (`decide/reach.py`), worked out once, before the package-scope rules read it and
    the result carries it."""
    facts_bytes: int = 0
    """The bytes those facts took, against the scan's bound."""
    facts_content: int = 0
    """The bytes of content detection read, which the bound grows with (`Facts.budget`)."""
    verdict_facts: dict[str, float] | None = None
    """The facts the package verdict reads, when the rule file's deferred pass gathered them
    already (`engine/pipeline/facts`): the verdict reuses them instead of computing twice."""
    labels: dict[str, Any] = field(default_factory=dict)
    """The capability labels computed with those facts, which the intent observation reuses."""

    finding_cap: int = 0
    """Ceiling on retained findings, from `limits.max_findings`.

    Zero disables it. The limit was declared and documented -- "a hostile
    repository can otherwise turn a scan into an out-of-memory failure by
    arranging for every line to match. Reaching this cap is itself reported" --
    and never checked anywhere.
    """

    capped: bool = False

    content_gaps: list[tuple[str, str]] = field(default_factory=list)
    """(rule, path) of each coverage finding whose cause is the scanned content (every cause but `NOT_CONTENT_GAPS`),
    recorded where the scan stopped being complete: the gate blocks on these (item 27)."""
    _gap_keys: set[tuple[str, str]] = field(default_factory=set, repr=False)

    ledger_tree: list[str] = field(default_factory=list)
    """Every file the walk presented and every archive member listed, by path, in order: what the
    coverage ledger (item 38, `CoverageLedger`) accounts for."""
    ledger_read: set[str] = field(default_factory=set)
    """Paths whose unit was inspected: by a worker, or answered from the cache."""
    ledger_unstarted: set[str] = field(default_factory=set)
    """Paths of units the pool never started because the scan's budget ran out (GAPPED by path)."""

    not_installed: list[Dependency] = field(default_factory=list)
    """Dependency records only a file outside the inventory's scope declares (`DependencyScope`):
    reported with `installed=False`, never read by an install-set check or the verdict."""

    not_installed_findings: list[Finding] = field(default_factory=list)
    """Findings a member detector made about a file outside the inventory's scope, held out of the
    verdict at their info twins (`NotInstalledFiles`) and added after it."""

    late: bool = False
    """Whether `out_of_time` has reported the spent budget."""

    def incomplete(self, finding: Finding) -> bool:
        """The one way a scan stops being complete: `finding` says what went unread and why, and
        its rule is the cause the gate reads (every cause but `NOT_CONTENT_GAPS`, item 27). Retained as `append`."""
        self.complete = False
        self._gap(finding.rule_id, finding.location.path)
        return self.append(finding)

    def gap(self, finding: Finding) -> Finding:
        """`incomplete` for a finding the caller keeps itself (a list of a file's findings added
        later): the scan stops being complete and the cause is recorded, here; `finding` is
        returned to be kept where the caller keeps the rest."""
        self.complete = False
        self._gap(finding.rule_id, finding.location.path)
        return finding

    def out_of_time(self, ctx: Any, where: str, step: str) -> bool:
        """Whether the scan's budget is spent (`ScanContext.out_of_time`), checked before work after
        detection: then `step` does not run, and the scan says so, once, as a blocking gap (item 64:
        past the deadline the release checks loaded the whole advisory index, tens of seconds under
        load, while the scan was already over its budget)."""
        if ctx is None or not ctx.out_of_time():
            return False
        if not self.late:
            self.late = True
            self.incomplete(
                OperationalFinding.build(
                    path=where,
                    rule_id="OPERATIONAL.SCAN.TIMEOUT",
                    message=f"The scan's budget was spent before {step}, which did not run, nor did "
                    "any later step after detection.",
                    remediation="Rescan with more time (--timeout), or on a less loaded machine.",
                    severity=Severity.MEDIUM,
                )
            )
        return True

    def ended_late(self, ctx: Any, where: str) -> None:
        """A scan that ends past its deadline is never complete, whatever it finished (item 64: one ran
        nine times past its budget and exited 0, called complete)."""
        if ctx is not None and ctx.out_of_time() and self.complete:
            self.out_of_time(ctx, where, "the end of the scan")

    def coverage(self) -> dict[str, Any]:
        """The result's coverage fields, as `ScanResult` takes them."""
        return {
            "complete": self.complete and self.advisory_complete,
            "content_complete": self.complete,
            "content_gaps": tuple(self.content_gaps),
            "advisory_complete": self.advisory_complete,
        }

    def named_elsewhere(self, rule: str, path: str) -> None:
        """`incomplete` where the finding that names the cause is made by another step (a
        lockfile's OPERATIONAL.LOCKFILE.UNPARSED by its detector, the walk's limit by the walk's
        own notes): the scan stops being complete and the cause is recorded, with no second
        finding saying it again."""
        self.complete = False
        self._gap(rule, path)

    def absorb(self, complete: bool, gaps: tuple[tuple[str, str], ...]) -> None:
        """A worker's verdict on one unit, as this accumulator's own (item 28): the worker inspected
        the unit through `Detection.run` into an accumulator of its own, and its completeness and
        gaps cross back as data. One implementation, so the two processes cannot disagree."""
        if not complete:
            self.complete = False
        for rule, path in gaps:
            self._gap(rule, path)

    def _gap(self, rule: str, path: str) -> None:
        # Once per (rule, path): a finding both reported-incomplete and passed to `incomplete` is
        # one gap, not two.
        if rule not in NOT_CONTENT_GAPS and (rule, path) not in self._gap_keys:
            self._gap_keys.add((rule, path))
            self.content_gaps.append((rule, path))

    def append(self, finding: Finding) -> bool:
        """Retain one finding if the cap allows it.

        Enforced here rather than at render time, which is where
        `ReportOptions.max_findings` applies -- by then everything is already in
        memory and the limit has prevented nothing.
        """
        if finding.rule_id in INCOMPLETE_WHEN_REPORTED:
            self.complete = False
            self._gap(finding.rule_id, finding.location.path)
        if self.finding_cap and len(self.findings) >= self.finding_cap:
            if not self.capped:
                self._gap("OPERATIONAL.SCAN.FINDING_LIMIT", ".")  # a flood the content chose
            self.capped = True
            self.complete = False
            return False
        self.findings.append(finding)
        return True

    def capability_names(self) -> dict[str, tuple[str, ...]]:
        """Each file's capability names from its worker's facts (`cap.all`), sorted."""
        return {
            path: tuple(sorted(set(held.get("cap.all", ()))))
            for path, held in sorted(self.facts.items())
            if held.get("cap.all")
        }

    MAX_EXTENSIONS: ClassVar[int] = 256
    MAX_BINARIES: ClassVar[int] = 4096
    MAX_REUSE: ClassVar[int] = 4096
    MAX_CAMPAIGN_PATHS: ClassVar[int] = 20_000

    @classmethod
    def for_config(cls, config: Any) -> Accumulator:
        """A scan's accumulator under `config`: its finding cap, and reuse keys when it asks for them."""
        return cls(finding_cap=config.limits.max_findings, reuse_keys=config.reuse_keys)

    def scanned(
        self, path: str, content: FileContent | None = None, opens: str | None = None
    ) -> None:
        """One more file scanned, counted under its extension; past `MAX_EXTENSIONS` distinct ones, the rest count as `other`.
        With its content, a native file is also recorded by the digest of the whole file (`binaries`), and a JSON file
        that declares a whole tool list is kept (`tool_lists`)."""
        self.files_scanned += 1
        ext = FileExtension.of(path)
        if ext not in self.extensions and len(self.extensions) >= self.MAX_EXTENSIONS:
            ext = "other"
        self.extensions[ext] = self.extensions.get(ext, 0) + 1
        if content is None:
            return
        size = FileFacts.size_class(content.size)
        self.size_classes[size] = self.size_classes.get(size, 0) + 1
        if FileFacts.is_instruction(path):
            self.instruction_files += 1
        if not content.is_binary:
            for kind, count in FileFacts.encoded_literals(content.raw).items():
                self.encoded_literals[kind] = self.encoded_literals.get(kind, 0) + count
        if NativeFile.is_native(path, content.raw[:8]):
            if content.truncated and content.whole_sha256 is None and content.streamed is None:
                self.binaries_complete = False
            elif len(self.binaries) < self.MAX_BINARIES:
                self.binaries.add(content.sha256)
            elif content.sha256 not in self.binaries:
                self.binaries_complete = False
        if self.reuse_keys:
            self._reuse(path, content, opens)
            self._campaign(path)
        declared = DeclaredTools.of(path, content.raw) if not content.truncated else None
        if declared is not None:
            self.tool_lists.append(declared)

    def _reuse(self, path: str, content: FileContent, opens: str | None = None) -> None:
        """The file's reuse keys, by the rule and from the bytes the code-reuse detector looks them up by (`ReuseKeys`):
        the whole file, from what is held, its spill, or its file on disk (`opens`)."""
        from cordon_scanner.analysis.shared.languages import LanguageRegistry
        from cordon_scanner.foundation.formats.scanned_json import ScannedJson
        from cordon_scanner.intel.registry import ReuseIndex, ReuseKeys

        keys: list[bytes] = []
        if ReuseKeys.is_code(path, content.is_binary, LanguageRegistry.of_file(path, content)):
            digest: bytes | None = None
            if not content.truncated:
                digest = ReuseIndex.fingerprint(content.raw)
            elif content.streamed is not None:
                digest = ReuseIndex.fingerprint(content.streamed)
            else:
                source = content.spill.path if content.spill is not None else opens
                if source is None:
                    self.reuse_complete = (
                        False  # the whole file is nowhere to be read: its key is unknown
                    )
                else:
                    try:
                        digest = ReuseKeys.fingerprint_file(source)
                    except OSError:
                        self.reuse_complete = False
            if digest is not None:
                self._keep(self.reuse_code, digest.hex())
        if ReuseKeys.is_root_manifest(path):
            if content.truncated or content.size > ReuseKeys.MAX_MANIFEST:
                self.reuse_complete = False
                return
            try:
                manifest = ScannedJson.loads(content.raw)
            except (ValueError, RecursionError):
                self.reuse_complete = (
                    False  # unreadable here (malformed or too deep): its hooks are unknown
                )
                return
            keys = [key for _, key in ReuseKeys.hook_keys(manifest)]
        for key in keys:
            self._keep(self.reuse_hooks, key.hex())

    def _campaign(self, path: str) -> None:
        """What the package's campaign fingerprint needs from the parent: member paths and which one is the root
        manifest. Never the manifest's content: the worker that read it sends its facets (`campaign.facet`)."""
        from cordon_scanner.intel.registry import CampaignFingerprint

        _, bang, member = path.partition("!")
        if bang and "!" not in member:
            if len(self.campaign_paths) < self.MAX_CAMPAIGN_PATHS:
                self.campaign_paths.append(member)
            else:
                self.campaign_paths_complete = False
        if self.campaign_manifest is None:
            ecosystem = CampaignFingerprint.root_manifest(path)
            if ecosystem is not None:
                self.campaign_manifest = (ecosystem, path)

    def campaign(self) -> dict[str, Any] | None:
        """The package's campaign fingerprint, in any ecosystem: `{ecosystem, manifest, layout, deps}`; None when the
        scan was not asked for package keys or found no root manifest. The layout is None past `MAX_CAMPAIGN_PATHS`
        members, never a facet of part of the tree that could not match a whole one."""
        from cordon_scanner.intel.registry import CampaignFingerprint

        if not self.reuse_keys or self.campaign_manifest is None:
            return None
        ecosystem, path = self.campaign_manifest
        facets: dict[str, Any] = {"manifest": None, "deps": None}
        for fact in self.facts.get(path, {}).get("campaign.facet", ()):
            facets[fact[0]] = fact[1]
        layout = (
            CampaignFingerprint.layout_of(ecosystem, self.campaign_paths)
            if self.campaign_paths_complete
            else None
        )
        return {
            "ecosystem": ecosystem,
            "manifest": facets["manifest"],
            "layout": layout,
            "deps": facets["deps"],
        }

    def _keep(self, into: set[str], key: str) -> None:
        if len(self.reuse_code) + len(self.reuse_hooks) < self.MAX_REUSE:
            into.add(key)
        elif key not in into:
            self.reuse_complete = False

    def tool_list(self) -> tuple[dict[str, Any], ...] | None:
        """The one tool list the package declares as data, or None when there is none or more than one."""
        return tuple(self.tool_lists[0]) if len(self.tool_lists) == 1 else None

    def collected(self) -> dict[str, Any]:
        """The per-package collections a scan result carries: the extension counts, the native file digests and whether
        that list is whole, and the one declared tool list."""
        return {
            "extensions": dict(self.extensions),
            "size_classes": dict(self.size_classes),
            "encoded_literals": dict(self.encoded_literals),
            "instruction_files": self.instruction_files,
            "binaries": tuple(sorted(self.binaries)),
            "binaries_complete": self.binaries_complete,
            "tool_list": self.tool_list(),
            "reuse_code": tuple(sorted(self.reuse_code)) if self.reuse_keys else None,
            "reuse_hooks": tuple(sorted(self.reuse_hooks)) if self.reuse_keys else None,
            "reuse_complete": self.reuse_complete,
            "campaign": self.campaign(),
        }

    def destinations(self) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
        """Each file's destination digests from its worker's facts (`net.host`, `net.domain`), sorted."""
        return {
            path: (
                tuple(sorted(set(held.get("net.host", ())))),
                tuple(sorted(set(held.get("net.domain", ())))),
            )
            for path, held in sorted(self.facts.items())
            if held.get("net.host")
        }

    def explain_incomplete(self) -> None:
        """An incomplete scan says why: when no coverage finding names what went unexamined, a
        backstop does (`OPERATIONAL.SCAN.INCOMPLETE`). Every path that leaves a scan incomplete
        reports its own reason, so the backstop is a guarantee, never the expected path: two
        zuppa wheels ended incomplete with only a detection finding to show for it (review 98).

        A coverage finding is what the taxonomy says it is (`AttackCategory.COVERAGE`): every
        `OPERATIONAL.` finding and `POLICY.COVERAGE.PRUNED` among them. The pruned-directory note
        already says what went unread at its own, low severity; a second, medium note beside it
        would block a default scan it was written to leave quiet."""
        if self.complete or any(
            f.attack_category is AttackCategory.COVERAGE and not f.rule_id.startswith(NOTICES)
            for f in self.findings
        ):
            return
        self._gap("OPERATIONAL.SCAN.INCOMPLETE", ".")
        self.findings.append(
            OperationalFinding.build(
                path=".",
                rule_id="OPERATIONAL.SCAN.INCOMPLETE",
                message=(
                    "Part of this scan's input was not examined, and no specific reason was "
                    "recorded."
                ),
                remediation="Treat the unexamined part as unexamined, not as clean.",
                severity=Severity.MEDIUM,
            )
        )

    def add(self, produced: Iterable[Finding]) -> None:
        """Retain a batch, stopping at the cap."""
        for finding in produced:
            if not self.append(finding):
                return


__all__ = []
