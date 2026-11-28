"""`cordon-scanner review --base REF [TARGET]`: what a dependency update adds (advanced gap M8).

A pull request that bumps a lockfile is reviewed as a diff of text nobody reads: hundreds of
`integrity` lines changed, and the one package that started running code at install among them.
This reads the dependency graph twice -- at the base revision, from git, and in the working tree --
and reports the difference a reviewer actually has to judge:

    added       a package that was not there before
    upgraded    a package at a later version          downgraded   at an earlier one
    removed     a package that is gone

For every added, upgraded or downgraded package, offline: the known-malicious and known-vulnerable
records that match the new version, and the ones the update fixes. With `--online`, each changed
package's old and new releases are fetched from their own registry -- npm, PyPI, crates.io,
RubyGems, NuGet, the Go proxy, Hex, pub and Maven Central -- checked against the digest that
registry publishes (for Go, the checksum database's `h1:`), scanned without being installed or
run, and compared the way `scan --compare-with` compares two releases: new install hooks, newly
gained capabilities, new obfuscation, new binaries. An added package is scanned on its own.
Packagist publishes no archive digest, so a Composer package is listed and said not to be
compared; nothing is fetched that cannot be verified.

`--format markdown` writes the report as a pull-request comment; the exit code is 1 when the
update brings in a known-malicious release, a known vulnerability at high or critical, or a
release that gained an install hook or a decisive capability.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode
from cordon_scanner.foundation.models import Severity
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

#: Files read from the base revision: at most this many, each at most this size.
MAX_BASE_FILES = 2_000
MAX_BASE_FILE_BYTES = 32 << 20
#: Packages whose releases are fetched and compared under --online, most consequential first.
MAX_FETCHED = 40
#: Registries whose archives can be fetched and verified (`RegistryClient.package_archive`).
COMPARABLE = ArchiveSources.fetchable()


#: Why a release of an ecosystem without a verified archive source is not fetched, where there is
#: more to say than that.
NOT_COMPARED: dict[str, str] = {}


@dataclass
class PackageChange:
    """One package's difference between the base and the working tree."""

    kind: str
    """`added`, `upgraded`, `downgraded`, `changed` (versions not ordered), or `removed`."""
    ecosystem: str
    name: str
    old: str | None
    new: str | None
    direct: bool = False
    malicious: list[str] = field(default_factory=list)
    vulnerable: list[tuple[str, str]] = field(default_factory=list)
    """`(advisory id, severity)` matching the NEW version."""
    fixed: list[str] = field(default_factory=list)
    """Advisories matching the old version and not the new: what the update resolves."""
    release: list[tuple[str, str, str]] = field(default_factory=list)
    """`(rule id, severity, message)` from comparing the two releases, or scanning an added one."""
    compared: str = ""
    """Why the releases were or were not compared."""
    categories: dict[str, str] = field(default_factory=dict)
    """Each release finding's category by rule id, where the scan gave one (an added package's own scan)."""
    path: str = ""
    """The file the changed package is declared in (its lockfile, else its manifest), for an annotation's place."""
    line: int = 1

    BLOCKING: ClassVar[frozenset[str]] = frozenset({"critical", "high"})

    @property
    def blocking(self) -> bool:
        return (
            bool(self.malicious)
            or any(s in self.BLOCKING for _, s in self.vulnerable)
            or any(s in self.BLOCKING for _, s, _ in self.release)
        )

    def reasons(self) -> list[tuple[str, str]]:
        """`(reason code, why)` for each thing that makes this change blocking, in the codes `decide()` gives: known
        malware R100, a known high or critical vulnerability R404, a changed release's malicious behaviour R400 or
        other blocking behaviour R401."""
        out: list[tuple[str, str]] = [("R100", f"known malware {m}") for m in self.malicious]
        out += [("R404", f"{i} ({s})") for i, s in self.vulnerable if s in self.BLOCKING]
        out += [
            (self.code_of(rule), f"{rule} ({s}): {m}")
            for rule, s, m in self.release
            if s in self.BLOCKING
        ]
        return out

    def code_of(self, rule: str) -> str:
        """The code `decide()` gives a finding: the rule's own (`ReasonMap`), else R400 for a malicious finding, R401
        for any other (a release comparison's changes carry no category, which `decide()` reads as R401 too)."""
        from cordon_scanner.decide.decision.reason_map import ReasonMap

        return ReasonMap.of(rule) or (
            "R400" if self.categories.get(rule) == "malicious" else "R401"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "reasons": [{"code": c, "why": w} for c, w in self.reasons()],
            "kind": self.kind,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "old": self.old,
            "new": self.new,
            "direct": self.direct,
            "malicious": self.malicious,
            "vulnerable": [{"id": i, "severity": s} for i, s in self.vulnerable],
            "fixed": self.fixed,
            "release": [{"rule_id": r, "severity": s, "message": m} for r, s, m in self.release],
            "compared": self.compared,
            "blocking": self.blocking,
        }


class GraphDiff:
    """The dependency graph at a git revision, and the difference from the working tree's."""

    @staticmethod
    def at_revision(root: Path, ref: str, into: Path) -> int:
        """Write the manifests and lockfiles tracked at `ref` under `into`. Returns how many."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.sources.git import GitRepository

        if ref.startswith("-"):
            raise ConfigError(f"--base {ref!r} starts with a dash and would be read as an option")
        repository = GitRepository(root)
        listed = repository.run(["ls-tree", "-r", "-z", "--name-only", ref, "--"]).split("\0")
        wanted = [
            path
            for path in listed
            if path
            and ".." not in path.split("/")
            and (
                EcosystemRegistry.manifest_ecosystem(path)
                or EcosystemRegistry.lockfile_ecosystem(path)
            )
        ][:MAX_BASE_FILES]
        written = 0
        for path in wanted:
            size = repository.run(["cat-file", "-s", f"{ref}:{path}"], check=False).strip()
            if not size.isdigit() or int(size) > MAX_BASE_FILE_BYTES:
                continue
            body = repository.run(["show", f"{ref}:{path}"], check=False)
            target = into / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
            written += 1
        return written

    @staticmethod
    def graph(target: Path) -> tuple[Dependency, ...]:
        """The resolved graph only: lockfiles and manifests read, no detector run."""
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        return (
            Scanner(Config.default().with_overrides(use_cache=False), detectors=())
            .scan(target)
            .dependencies
        )

    @staticmethod
    def pinned_at(dependency: Dependency) -> str | None:
        """What a dependency is pinned at: its version, else the ref it is declared at (`ref:<tag or commit>`, how an
        action, a chart, a module or a flake input is pinned), so repinning one is a change the review sees. An unlocked
        range is not a version and never enters the diff as one."""
        if dependency.version:
            return dependency.version
        spec = dependency.declared_spec or ""
        return spec if spec.startswith("ref:") else None

    @staticmethod
    def diff(old: tuple[Dependency, ...], new: tuple[Dependency, ...]) -> list[PackageChange]:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.intel.advisories.versions import Versions

        where: dict[tuple[str, str], tuple[str, int]] = {}

        def index(graph: tuple[Dependency, ...]) -> dict[tuple[str, str], tuple[set[str], bool]]:
            out: dict[tuple[str, str], tuple[set[str], bool]] = {}
            for dependency in graph:
                version = GraphDiff.pinned_at(dependency)
                if not version or dependency.local:
                    continue
                ecosystem = EcosystemRegistry.get(dependency.ecosystem)
                name = (
                    ecosystem.normalize_name(dependency.name)
                    if ecosystem
                    else dependency.name.lower()
                )
                versions, direct = out.get((dependency.ecosystem, name), (set(), False))
                versions.add(version)
                where.setdefault(
                    (dependency.ecosystem, name),
                    (
                        str(dependency.declared_in or dependency.manifest_path or ""),
                        int(dependency.lockfile_line or dependency.manifest_line or 1),
                    ),
                )
                out[(dependency.ecosystem, name)] = (versions, direct or dependency.direct)
            return out

        after = index(new)
        before = index(old)
        changes: list[PackageChange] = []
        for key in sorted(set(before) | set(after)):
            ecosystem, name = key
            was, _ = before.get(key, (set(), False))
            now, direct = after.get(key, (set(), before.get(key, (set(), False))[1]))
            if was == now:
                continue
            if not was:
                changes += [
                    PackageChange("added", ecosystem, name, None, v, direct) for v in sorted(now)
                ]
                continue
            if not now:
                changes += [
                    PackageChange("removed", ecosystem, name, v, None, direct) for v in sorted(was)
                ]
                continue
            gone, came = sorted(was - now), sorted(now - was)
            for index_, version in enumerate(came):
                previous = gone[index_] if index_ < len(gone) else max(was, key=lambda v: v)
                order = Versions.compare(ecosystem, version, previous)
                kind = "upgraded" if order > 0 else "downgraded" if order < 0 else "changed"
                changes.append(PackageChange(kind, ecosystem, name, previous, version, direct))
            for version in gone[len(came) :]:
                changes.append(PackageChange("removed", ecosystem, name, version, None, direct))
        for change in changes:
            change.path, change.line = where.get((change.ecosystem, change.name), ("", 1))
        return changes


class ChangeReview:
    """What each change brings: advisories offline, release contents online."""

    @staticmethod
    def advisories(changes: list[PackageChange]) -> None:
        from cordon_scanner.intel.registry import BundledAdvisories

        database = BundledAdvisories.database()
        for change in changes:
            if change.new is None:
                continue
            for advisory in database.matching(change.ecosystem, change.name, change.new):
                if advisory.malicious:
                    change.malicious.append(advisory.identifier or advisory.reference)
                else:
                    change.vulnerable.append(
                        (
                            advisory.identifier,
                            (advisory.severity or "high").lower().replace("moderate", "medium"),
                        )
                    )
            if change.old is not None:
                new_ids = {
                    a.identifier
                    for a in database.matching(change.ecosystem, change.name, change.new)
                }
                change.fixed = sorted(
                    a.identifier
                    for a in database.matching(change.ecosystem, change.name, change.old)
                    if a.identifier and a.identifier not in new_ids and not a.malicious
                )

    @staticmethod
    def verified(*archives: Any) -> str:
        """What the archives were checked with: `digests verified` for a SHA-2 digest the registry publishes, else the weaker check named."""
        weak = sorted({a.strength for a in archives if getattr(a, "strength", "")})
        return (
            f"checked by {' and '.join(weak)} only"
            if weak
            else ("digest verified" if len(archives) == 1 else "digests verified")
        )

    @staticmethod
    def releases(changes: list[PackageChange], *, quiet: bool) -> None:
        """Fetch, verify and compare, most consequential first, up to `MAX_FETCHED` packages."""
        import sys

        from cordon_scanner import Scanner
        from cordon_scanner.detect.supply import release_diff
        from cordon_scanner.foundation.config.settings import Config
        from cordon_scanner.intel.registries.registry_client import RegistryError

        candidates = [c for c in changes if c.new is not None]
        candidates.sort(key=lambda c: (not c.direct, c.kind != "added"))
        for count, change in enumerate(candidates):
            if change.ecosystem not in COMPARABLE:
                change.compared = NOT_COMPARED.get(
                    change.ecosystem, f"no verified archive source for {change.ecosystem}"
                )
                continue
            if count >= MAX_FETCHED:
                change.compared = f"past the {MAX_FETCHED}-package limit for one review"
                continue
            config = Config.default().with_overrides(use_cache=False)
            with tempfile.TemporaryDirectory(prefix="cordon-review-") as work:
                try:
                    newer = ArchiveSources.package_archive(
                        change.ecosystem, change.name, change.new
                    )
                    new_path = Path(work) / f"new-{Path(newer.filename).name}"
                    new_path.write_bytes(newer.data)
                    new_result = Scanner(config).scan(new_path)
                    if change.old is None:
                        kept = [
                            f
                            for f in new_result.active
                            if f.severity.value >= Severity.MEDIUM.value
                            and f.category.value in ("malicious", "suspicious")
                        ][:10]
                        change.release = [
                            (f.rule_id, f.severity.name.lower(), f.message) for f in kept
                        ]
                        change.categories = {f.rule_id: f.category.value for f in kept}
                        change.compared = f"{change.name} {change.new} scanned from {change.ecosystem}, {ChangeReview.verified(newer)}"
                        continue
                    older = ArchiveSources.package_archive(
                        change.ecosystem, change.name, change.old
                    )
                    old_path = Path(work) / f"old-{Path(older.filename).name}"
                    old_path.write_bytes(older.data)
                    old_result = Scanner(config).scan(old_path)
                except (RegistryError, OSError, ValueError) as exc:
                    change.compared = f"not compared: {exc}"
                    if not quiet:
                        print(f"review: {change.ecosystem}:{change.name}: {exc}", file=sys.stderr)
                    continue
            found = release_diff.ReleaseDiff.compare(
                release_diff.Profile.of(new_result),
                release_diff.Profile.of(old_result),
                previous=f"{change.name} {change.old}",
            )
            change.release = [(c.rule_id, c.severity.name.lower(), c.message) for c in found]
            change.compared = f"{change.old} and {change.new} fetched from {change.ecosystem}, {ChangeReview.verified(newer, older)}, compared"


class ReviewReport:
    @staticmethod
    def text(changes: list[PackageChange], base: str) -> str:
        if not changes:
            return f"no dependency changes since {base}"
        lines = [f"{len(changes)} dependency change(s) since {base}", ""]
        for change in changes:
            arrow = (
                f"{change.old or ''} -> {change.new or ''}".strip(" ->")
                if change.old and change.new
                else (change.new or change.old or "")
            )
            mark = "  BLOCKING" if change.blocking else ""
            lines.append(
                f"{change.kind:10} {change.ecosystem}:{change.name} {arrow}{' (direct)' if change.direct else ''}{mark}"
            )
            lines += [f"    known malicious: {m}" for m in change.malicious]
            lines += [f"    vulnerable: {i} ({s})" for i, s in change.vulnerable]
            if change.fixed:
                lines.append(f"    fixes: {', '.join(change.fixed[:8])}")
            lines += [f"    {s}: {m}" for _, s, m in change.release]
            if change.compared:
                lines.append(f"    ({change.compared})")
        return "\n".join(lines)

    @staticmethod
    def markdown(changes: list[PackageChange], base: str) -> str:
        if not changes:
            return f"### Dependency review\n\nNo dependency changes since `{base}`."
        blocking = [c for c in changes if c.blocking]
        counts = {
            k: sum(1 for c in changes if c.kind == k)
            for k in ("added", "upgraded", "downgraded", "changed", "removed")
        }
        summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n)
        lines = [
            "### Dependency review",
            "",
            f"{summary} since `{base}`."
            + (
                f" **{len(blocking)} need attention.**"
                if blocking
                else " Nothing known-bad came in."
            ),
            "",
            "| change | package | version | findings |",
            "|---|---|---|---|",
        ]
        for change in changes:
            version = (
                f"{change.old} → {change.new}"
                if change.old and change.new
                else (change.new or change.old or "")
            )
            notes = [f"**malicious** {m}" for m in change.malicious]
            notes += [f"{i} ({s})" for i, s in change.vulnerable]
            notes += [f"{s}: {r}" for r, s, _ in change.release]
            if change.fixed:
                notes.append(f"fixes {len(change.fixed)}")
            lines.append(
                f"| {change.kind} | `{change.ecosystem}:{change.name}` | {version} | {'; '.join(notes) or '-'} |"
            )
        details = [c for c in changes if c.release]
        if details:
            lines += ["", "<details><summary>What the changed releases contain</summary>", ""]
            for change in details:
                lines.append(f"**{change.ecosystem}:{change.name}** ({change.compared})")
                lines += [f"- {s}: {m}" for _, s, m in change.release]
                lines.append("")
            lines.append("</details>")
        return "\n".join(lines)


class GithubAnnotations:
    """The review as GitHub Actions workflow commands: one `::error` annotation per reason a change blocks, titled
    with its reason code, so a pull request's check fails naming why; a `::notice` when nothing blocks."""

    @staticmethod
    def data(text: str) -> str:
        return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    @staticmethod
    def prop(text: str) -> str:
        return GithubAnnotations.data(text).replace(":", "%3A").replace(",", "%2C")

    @classmethod
    def render(cls, changes: list[PackageChange], base: str) -> str:
        from cordon_scanner.contracts.reason_codes import ReasonCodes

        lines = []
        for change in changes:
            version = (
                f"{change.old} -> {change.new}"
                if change.old and change.new
                else (change.new or change.old or "")
            )
            for code, why in change.reasons():
                title = f"{code} {ReasonCodes.lookup(code).title}"
                lines.append(
                    f"::error title={cls.prop(title)}::"
                    + cls.data(f"{change.kind} {change.ecosystem}:{change.name} {version}: {why}")
                )
        if not lines:
            lines.append(
                "::notice title="
                + cls.prop("Dependency review")
                + "::"
                + cls.data(f"{len(changes)} dependency change(s) since {base}; nothing blocks")
            )
        return "\n".join(lines)


class HostReports:
    """The review in the forms GitLab and Bitbucket show on a merge or pull request: one entry per reason a change
    blocks, titled with its reason code and placed at the file that declares the package, as the GitHub annotations
    are."""

    #: Bitbucket's annotation severities by the review's: a blocking reason is a known malicious or vulnerable release.
    BITBUCKET_SEVERITY: ClassVar[dict[str, str]] = {"R100": "CRITICAL", "R400": "CRITICAL"}
    #: Bitbucket caps an annotation's summary at 450 characters and a report at 1,000 annotations.
    SUMMARY: ClassVar[int] = 450
    ANNOTATIONS: ClassVar[int] = 1000

    @staticmethod
    def blocking(changes: list[PackageChange]) -> list[tuple[PackageChange, str, str, str]]:
        """`(change, code, title, message)` for each reason a change blocks."""
        from cordon_scanner.contracts.reason_codes import ReasonCodes

        out = []
        for change in changes:
            version = (
                f"{change.old} -> {change.new}"
                if change.old and change.new
                else (change.new or change.old or "")
            )
            for code, why in change.reasons():
                title = f"{code} {ReasonCodes.lookup(code).title}"
                message = f"{change.kind} {change.ecosystem}:{change.name} {version}: {why}"
                out.append((change, code, title, message))
        return out

    @classmethod
    def codeclimate(cls, changes: list[PackageChange], base: str) -> str:
        """GitLab's Code Quality report (`artifacts: reports: codequality`): its merge request widget lists each."""
        import hashlib

        entries = [
            {
                "type": "issue",
                "check_name": code,
                "description": f"{title}: {message}",
                "categories": ["Security"],
                "severity": "blocker" if code in cls.BITBUCKET_SEVERITY else "critical",
                "fingerprint": hashlib.sha256(f"{base}|{code}|{message}".encode()).hexdigest(),
                "location": {"path": change.path or ".", "lines": {"begin": change.line or 1}},
            }
            for change, code, title, message in cls.blocking(changes)
        ]
        return json.dumps(entries, indent=2, sort_keys=True)

    @classmethod
    def bitbucket(cls, changes: list[PackageChange], base: str) -> str:
        """A Bitbucket Code Insights report and its annotations, as the pipe sends them for the pull request's
        commit: `{"report": ..., "annotations": [...]}`."""
        found = cls.blocking(changes)
        report = {
            "title": "Cordon dependency review",
            "details": (
                f"{len(changes)} dependency change(s) since {base}; "
                + (f"{len(found)} reason(s) block." if found else "nothing blocks.")
            ),
            "report_type": "SECURITY",
            "reporter": "Cordon",
            "result": "FAILED" if found else "PASSED",
        }
        annotations = [
            {
                "external_id": f"cordon-{index}",
                "annotation_type": "VULNERABILITY",
                "summary": f"{title}: {message}"[: cls.SUMMARY],
                "severity": cls.BITBUCKET_SEVERITY.get(code, "HIGH"),
                "result": "FAILED",
                **({"path": change.path, "line": change.line or 1} if change.path else {}),
            }
            for index, (change, code, title, message) in enumerate(found[: cls.ANNOTATIONS])
        ]
        return json.dumps({"report": report, "annotations": annotations}, indent=2, sort_keys=True)


class ReviewCommand:
    #: Each output by its `--format` name.
    FORMATS: ClassVar[dict[str, Any]] = {
        "json": lambda changes, base: json.dumps(
            {"base": base, "changes": [c.as_dict() for c in changes]}, indent=2
        ),
        "markdown": lambda changes, base: ReviewReport.markdown(changes, base),
        "github": lambda changes, base: GithubAnnotations.render(changes, base),
        "codeclimate": lambda changes, base: HostReports.codeclimate(changes, base),
        "bitbucket": lambda changes, base: HostReports.bitbucket(changes, base),
        "text": lambda changes, base: ReviewReport.text(changes, base),
    }

    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        review = sub.add_parser(
            "review", help="what a dependency update adds, compared with a git revision"
        )
        review.add_argument(
            "target", nargs="?", default=".", help="repository directory (default: .)"
        )
        review.add_argument(
            "--base",
            required=True,
            metavar="REF",
            help="the revision to compare with, e.g. origin/main",
        )
        review.add_argument(
            "--format",
            choices=("text", "markdown", "json", "github", "codeclimate", "bitbucket"),
            default="text",
            help="github: one ::error annotation per blocking reason, titled with its reason code; "
            "codeclimate: GitLab's Code Quality report of the same; bitbucket: a Code Insights report and its "
            "annotations",
        )
        review.add_argument(
            "--online",
            action="store_true",
            help="fetch each changed package's old and new releases from its registry, verify, scan and compare them",
        )
        review.add_argument("--quiet", action="store_true", help="no progress on stderr")
        review.add_argument(
            "--annotations",
            metavar="FILE",
            help="also write the review as GitHub annotations (one ::error per blocking reason, titled with its "
            "reason code) to FILE, from the same pass",
        )

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        target = Path(args.target)
        if not target.is_dir():
            raise CordonError(f"review needs a repository directory: {target}")
        with tempfile.TemporaryDirectory(prefix="cordon-base-") as base_dir:
            GraphDiff.at_revision(target, args.base, Path(base_dir))
            old = GraphDiff.graph(Path(base_dir))
        new = GraphDiff.graph(target)
        changes = GraphDiff.diff(old, new)
        ChangeReview.advisories(changes)
        if args.online:
            ChangeReview.releases(changes, quiet=args.quiet)
        print(ReviewCommand.FORMATS[args.format](changes, args.base))
        if getattr(args, "annotations", None):
            Path(args.annotations).write_text(
                GithubAnnotations.render(changes, args.base) + "\n", encoding="utf-8"
            )
        return int(ExitCode.FINDINGS if any(c.blocking for c in changes) else ExitCode.CLEAN)


__all__ = [
    "ChangeReview",
    "GithubAnnotations",
    "GraphDiff",
    "HostReports",
    "PackageChange",
    "ReviewCommand",
    "ReviewReport",
]
