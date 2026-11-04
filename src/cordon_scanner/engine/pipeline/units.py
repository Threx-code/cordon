"""Every file of a scanned tree as a unit a detector reads: the walk's selection, each file loaded,
archives expanded into their members, binary files and Git LFS pointers recorded, each file's
language found, and every file the walk did not read said as a finding (out of time or memory,
unreadable, a link, too deep, pruned, excluded). Deobfuscated forms and install hooks written
inline join the units after the walk.

The memory budget is a running count over retained content: the input is attacker-controlled and
its size is not known in advance, so the ceiling is real rather than implied by the code's shape.
"""

from __future__ import annotations

import functools
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
from cordon_scanner.analysis.shared.languages import LanguageRegistry
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.engine.pipeline.constants import REPOSITORY_SCOPE
from cordon_scanner.engine.pipeline.graph import ParsedManifests
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.foundation.content import FileContent, Skipped
from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.files.walk import (
    INSTALLED_CODE_PRUNE_DIRS,
    WalkEntry,
    Walker,
)
from cordon_scanner.foundation.models import AUTHOR_TIME_HOOKS, Category, Severity
from cordon_scanner.foundation.results import OperationalFinding, Repository
from cordon_scanner.sources.registry import ArchiveReader

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator, Sequence

    from cordon_scanner.engine.engine import Engine


@dataclass(frozen=True, slots=True)
class Expansion:
    """An archive found in a directory scan, opened once per distinct content (`Units.opened`): its
    members (None where it was refused), why it was refused, and the members it refused, each
    relative to the archive's own path, so every copy of the bytes is recorded at its own."""

    members: list[tuple[str, bytes]] | None
    refused: tuple[str, str] | None = None
    """(message, remediation) of the refusal, where the archive was not opened."""
    rejected: tuple[tuple[str, str, str], ...] = ()
    """(suffix after the archive's path, reason, detail) of each member the reader refused."""
    truncated: bool = False
    import_library: frozenset[str] = frozenset()
    """Suffixes of the members of an import library (`ImportLibrary`, notes/75)."""

    def record(self, rel_path: str, acc: Accumulator) -> None:
        """The outcome, at this copy's own path: its refusal and every refused member's."""
        if self.refused is not None:
            if self.truncated:
                acc.rejected_archives.add(rel_path)
            message, remediation = self.refused
            acc.incomplete(
                OperationalFinding.build(
                    path=rel_path,
                    rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                    message=message,
                    remediation=remediation,
                    severity=Severity.MEDIUM,
                )
            )
        for suffix, reason, detail in self.rejected:
            ArchiveMembers.refuse(acc, rel_path + suffix, reason, detail)


class Units:
    """Reads a tree's files into the units detectors read."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._archive_stats = engine._archive_stats
        self._expansions = engine._expansions
        self.config = engine.config
        self.coverage = engine.coverage
        self.shadowed = engine.shadowed
        self.source = engine.source

    def read(
        self,
        root: Path,
        inventory: Repository,
        acc: Accumulator,
        deadline: float,
        *,
        walked: Sequence[WalkEntry] | None = None,
        walker: Walker | None = None,
    ) -> Iterator[FileUnit]:
        """Produce one unit per scannable file.

        A generator, but `scan` collects it into a list, because manifest hooks
        are discovered during this pass and change the context every later
        finding is scored against -- so detection cannot begin until the pass is
        complete. The generator therefore does not bound memory on its own, and
        the docstring here used to claim it did.

        What bounds it is `limits.max_memory_bytes`, enforced below as a running
        budget over retained content. The input is attacker-controlled and its
        size is not known in advance, so the ceiling has to be real rather than
        implied by the shape of the code.
        """
        walker = walker if walker is not None else self.engine._walker()

        # A file an install hook executes is that interpreter's language,
        # whatever the file is called.
        implied_languages = Hooks.languages_from_hooks(inventory)

        # Files classified as binary artefacts. Counted so the scan can say how
        # many files it did not examine as source: a file that was skipped and a
        # file that was examined and found clean must not look the same.
        binary: list[str] = []
        lfs_pointers: list[str] = []
        # Archives left closed because expansion is off. See `expand_archives`.
        unopened: list[str] = []

        selection: Iterable[WalkEntry] = (
            walked if walked is not None else self.source.entries(root, walker)
        )
        # The walk stops early (out of time or memory) without its closing notes, as it always has.
        stopped, selected = yield from self.walk(
            selection, implied_languages, acc, deadline, binary, lfs_pointers, unopened
        )
        if stopped:
            return

        self.gaps(unopened, acc, walker, root, selected, binary, lfs_pointers)

        self.exclusions(acc, walker)

    def walk(
        self,
        selection: Iterable[WalkEntry],
        implied_languages: dict[str, str],
        acc: Accumulator,
        deadline: float,
        binary: list[str],
        lfs_pointers: list[str],
        unopened: list[str],
    ) -> Generator[FileUnit, None, tuple[bool, int]]:
        """Each selected file as a unit, and each archive member after its archive. Returns whether
        the walk stopped early, and how many files were selected."""
        # Counted here rather than read from walker.stats, because the source
        # sits between the walker and this loop. A git mode narrows the walker's
        # output, and that narrowing is invisible to the walker's own counters:
        # `--tracked` in a repository where nothing is tracked once yielded zero
        # files while the stats reported a full traversal, so the scan examined
        # nothing and reported clean.
        selected = 0
        # Bytes of file content this scan is holding. `max_memory_bytes` was
        # declared, documented and checked nowhere.
        retained = 0
        for entry in selection:
            selected += 1

            # `>=`, not `>`. A budget of zero means no time is allowed, and on
            # platforms with a coarse monotonic clock the first reading can equal
            # the start time exactly, so a strict comparison silently never
            # trips. That made --timeout 0 a no-op on Windows.
            if time.monotonic() >= deadline:
                self.out_of_time(acc)
                return True, selected

            acc.ledger_tree.append(entry.rel_path)
            if entry.is_symlink:
                Units.symlink_skipped(acc, entry)
                continue

            loaded = self.source.load(entry, self.config.limits)
            if isinstance(loaded, Skipped):
                Units.unreadable(acc, entry, loaded)
                continue

            expanded = self.sort_loaded(
                entry, loaded, acc, deadline, unopened, binary, lfs_pointers
            )

            Units.note_truncation(loaded, acc, entry)

            retained += len(loaded.streamed or loaded.raw)
            if 0 < self.config.limits.max_memory_bytes <= retained:
                self.over_memory(acc)
                return True, selected

            acc.files_scanned += 1
            acc.bytes_scanned += len(loaded.raw)

            language = Units.language_of(entry, implied_languages, loaded)

            yield FileUnit(content=loaded, language=language, opens=str(entry.real_path.absolute()))

            # Members after the archive itself, each budgeted like a file: an
            # archive is the cheapest way to put a lot of content in front of a
            # scanner, so its members count against the same memory ceiling.
            for member in expanded or ():
                retained += len(member.content.raw)
                if 0 < self.config.limits.max_memory_bytes <= retained:
                    self.archive_over_memory(acc, entry)
                    return True, selected
                acc.files_scanned += 1
                acc.bytes_scanned += len(member.content.raw)
                acc.ledger_tree.append(member.path)
                yield member
        return False, selected

    def sort_loaded(
        self,
        entry: WalkEntry,
        loaded: FileContent,
        acc: Accumulator,
        deadline: float,
        unopened: list[str],
        binary: list[str],
        lfs_pointers: list[str],
    ) -> list[FileUnit] | None:
        """An archive expanded (or noted unopened), a binary file and a Git LFS pointer recorded."""
        expanded: list[FileUnit] | None = None
        claimed = ArchiveReader.is_archive(entry.rel_path)
        if claimed and not self.config.expand_archives:
            unopened.append(entry.rel_path)
        elif self.config.expand_archives and (
            # Its name says archive, or its bytes do (item 36): a zip named notes.txt. A whole
            # header is read, never a magic alone, so one that fails to open is reported unread.
            claimed or ArchiveReader.opens_by_bytes(loaded.raw)
        ):
            expanded = self.expand_members(entry.rel_path, loaded, acc, deadline)

        # A named archive's refusal is its expansion's; with archives not expanded, an unopenable
        # format is the operator's choice as every archive is (NOT_EXPANDED), never both.
        if expanded is None and not claimed and self.config.expand_archives:
            Units.unsupported_archive(entry.rel_path, loaded, acc)
        if loaded.is_binary and expanded is None:
            binary.append(entry.rel_path)

        if loaded.is_lfs_pointer:
            lfs_pointers.append(entry.rel_path)
        return expanded

    @staticmethod
    def unsupported_archive(rel_path: str, loaded: FileContent, acc: Accumulator) -> None:
        """A file in an archive format no reader here opens is a gap at its path (item 53)."""
        refused: list[tuple[str, str, str]] = []
        if ArchiveReader.unsupported(rel_path, loaded.raw, refused):
            for path, reason, detail in refused:
                ArchiveMembers.refuse(acc, path, reason, detail)

    def out_of_time(self, acc: Accumulator) -> None:
        """The scan's time budget ran out: the scan is incomplete, and says so."""
        # A partial result a human can act on beats a stack trace, and
        # marking it partial is what stops it being read as a pass.
        acc.incomplete(
            OperationalFinding.build(
                path=REPOSITORY_SCOPE,
                rule_id="OPERATIONAL.SCAN.TIMEOUT",
                message=(
                    f"The scan exceeded its {self.config.limits.total_timeout:.0f}s "
                    f"budget and stopped early. Results are partial."
                ),
                remediation=(
                    "Raise limits.total_timeout, narrow the scan with --include, "
                    "or scan projects individually."
                ),
            )
        )

    @staticmethod
    def symlink_skipped(acc: Accumulator, entry: WalkEntry) -> None:
        """A symbolic link: recorded, never followed. It has no content of its own, so the coverage
        ledger counts it read (its target, if in the tree, is its own entry)."""
        acc.files_skipped += 1
        acc.ledger_read.add(entry.rel_path)
        acc.append(
            OperationalFinding.build(
                path=entry.rel_path,
                rule_id="OPERATIONAL.FILE.SYMLINK",
                message="Symbolic link was recorded but not followed.",
                remediation="No action needed. Links are never dereferenced.",
                severity=Severity.INFO,
            )
        )

    @staticmethod
    def unreadable(acc: Accumulator, entry: WalkEntry, loaded: Skipped) -> None:
        """A file that could not be read: skipped, and the scan incomplete."""
        acc.files_skipped += 1
        acc.incomplete(
            OperationalFinding.build(
                path=entry.rel_path,
                rule_id="OPERATIONAL.FILE.UNREADABLE",
                message=f"File could not be read ({loaded.reason}); it was not scanned.",
                remediation="Check permissions, or exclude the path deliberately.",
            )
        )

    def over_memory(self, acc: Accumulator) -> None:
        """Retained content reached the memory budget: the scan is incomplete, and says so."""
        acc.incomplete(
            OperationalFinding.build(
                path=REPOSITORY_SCOPE,
                rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                message=(
                    f"Retained content reached the "
                    f"{self.config.limits.max_memory_bytes} byte budget after "
                    f"{acc.files_scanned} files, so the remaining files were "
                    f"not examined. Results are partial."
                ),
                remediation=(
                    "Raise limits.max_memory_bytes, exclude generated or "
                    "vendored directories, or scan the repository in parts."
                ),
            )
        )

    @staticmethod
    def note_truncation(loaded: FileContent, acc: Accumulator, entry: WalkEntry) -> None:
        """A file read only in part: the scan is incomplete unless the windows read it to its end."""
        if loaded.truncated:
            # A file examined in part is not a file examined. Truncation was
            # reported at INFO and left `complete` true, so
            # `fail_on_incomplete` -- the one organisation control that
            # catches the timeout variant of this -- did not catch the
            # sharpest one: `max_file_bytes: 65536` in a repository's own
            # config, which reads as ordinary tuning and pads a payload out
            # of reach. Unless the windows read it to its end: then every text rule saw
            # every byte, and only the whole-file parsers stopped at the limit.
            # Said here, for every such file. It was said by the capability detector, which
            # returns before it for a binary file and for one no rule applies to -- so a
            # repository with a 12 MB font was incomplete, failed the Action's default gate,
            # and gave no reason.
            note = ArchiveMembers.truncated_note(entry.rel_path, loaded)
            if not ArchiveMembers.read_to_end(loaded):
                note = acc.gap(note)
            if entry.rel_path not in acc.rejected_archives:
                acc.append(note)

    @staticmethod
    def language_of(
        entry: WalkEntry, implied_languages: dict[str, str], loaded: FileContent
    ) -> str | None:
        """A file's language: the interpreter a hook runs it with, then its name, then its shebang,
        then its content.

        The hook's interpreter first: `node lib/run.md` runs JavaScript whatever the file is called,
        and the file is inspected as what runs (item 36). The name answered first, so a payload named
        .md, .txt or nothing, run by a hook, was read by no language rule while the same bytes in
        run.js blocked (the evasion suite's text-type names; five npm misses on 3cad016d)."""
        language = Hooks.hook_language(
            implied_languages.get(entry.rel_path),
            LanguageRegistry.identify_language(entry.rel_path),
        )
        if language is None:
            # An extensionless script -- `install`, `preinstall`,
            # `configure` -- got `language=None` and therefore only the
            # language-agnostic rules, although its shebang says exactly
            # what it is. Extensionless install scripts are a normal
            # shipping form and a normal place for a payload.
            language = LanguageRegistry.language_from_interpreter(loaded.shebang or "")
        if language is None and not loaded.is_binary:
            # And, last, what the content looks like. A file with neither a
            # known extension nor a shebang got no language at all, so a
            # payload in `postinstall` or `payload.dat` was examined by none
            # of the language rules while the identical bytes in
            # `postinstall.sh` were CRITICAL. See
            # `LanguageRegistry.identify_from_content` for why this is the
            # last step and never overrides a filename.
            language = LanguageRegistry.identify_from_content(loaded.text)
        return language

    def archive_over_memory(self, acc: Accumulator, entry: WalkEntry) -> None:
        """An archive's members reached the memory budget: the scan is incomplete, and says so."""
        acc.incomplete(
            OperationalFinding.build(
                path=entry.rel_path,
                rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                message=(
                    f"Retained content reached the "
                    f"{self.config.limits.max_memory_bytes} byte budget while "
                    f"expanding this archive, so the remaining files were not "
                    f"examined. Results are partial."
                ),
                remediation=(
                    "Raise limits.max_memory_bytes, or exclude vendored artefacts deliberately."
                ),
            )
        )

    def gaps(
        self,
        unopened: list[str],
        acc: Accumulator,
        walker: Walker,
        root: Path,
        selected: int,
        binary: list[str],
        lfs_pointers: list[str],
    ) -> None:
        """Files the walk could not open, a file-count limit reached, directories too deep, and walk errors."""
        if unopened:
            # An archive that was not opened is content that was not examined, and the scan says
            # so: incomplete, with every archive named. The operator's own choice (`--no-expand`
            # buys speed, not a clean result), which no package can make, so it blocks only with
            # fail_on_incomplete (`NOT_CONTENT_GAPS`). An archive a limit left unread is refused
            # (ARCHIVE.REJECTED, MEMBER_REJECTED), the package's doing, and blocks.
            acc.incomplete(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.ARCHIVE.NOT_EXPANDED",
                    message=(
                        f"{len(unopened)} archive(s) were not opened because archive "
                        f"expansion is off, so their contents were not examined: "
                        f"{', '.join(sorted(unopened))}."
                    ),
                    remediation="Scan without --no-expand, or set scan.expand_archives: true.",
                )
            )

        if walker.stats.limit_hit:
            acc.incomplete(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.SCAN.LIMIT",
                    message=f"Traversal stopped early: {walker.stats.limit_hit}",
                    remediation="Raise the relevant limit or narrow the scan.",
                )
            )

        # -- Configuration that reduced coverage ---------------------------
        #
        # The scan target is untrusted input, and its configuration file is part
        # of it. Without an organisation policy there is no ceiling, so a
        # repository can legitimately exclude paths and disable detectors -- and
        # a hostile one can do the same to blind the scan entirely.
        #
        # That cannot be prevented without a policy, so it is made loud instead.
        # Every one of these findings exists because a scan that examined
        # nothing and a scan that found nothing must never look alike.
        acc.add(
            self.coverage.findings(
                walker.stats,
                root,
                selected,
                complete=acc.complete,
                binary=binary,
                lfs_pointers=lfs_pointers,
                examined=acc.files_scanned,
            )
        )

        self.depth_and_errors(walker, acc)

    def depth_and_errors(self, walker: Walker, acc: Accumulator) -> None:
        """Directories deeper than the walk goes, and the walk's own errors."""
        # L5 - traversal limits that dropped paths without a word.
        # `max_path_depth` incremented `dirs_pruned` and `max_path_bytes` pushed
        # the path into `stats.errors`; neither reached a finding, so both were
        # silent skips against the limits module's own invariant that reaching a
        # limit is never one.
        #
        # Only the second half landed. `dirs_pruned` is shared with
        # `node_modules` and every configured exclusion, so a depth cut stayed
        # invisible: a payload under seventy directories gave `files_scanned:
        # 1`, `complete: true`, no findings and exit 0. The walker now records
        # those paths separately, and this is where they are said out loud.
        if walker.stats.too_deep:
            sample = ", ".join(walker.stats.too_deep[:5])
            more = (
                f" and {len(walker.stats.too_deep) - 5} more"
                if len(walker.stats.too_deep) > 5
                else ""
            )
            acc.incomplete(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.WALK.TOO_DEEP",
                    message=(
                        f"{len(walker.stats.too_deep)} directory tree(s) went deeper than "
                        f"the configured limit of {self.config.limits.max_path_depth} and "
                        f"everything below them was not examined: {sample}{more}."
                    ),
                    remediation=(
                        "Raise scan.limits.max_path_depth, or scan the deep tree "
                        "directly. Nothing under the cut was read, so nothing under "
                        "it was found clean -- and making a tree deep is the "
                        "cheapest way to put a file out of a scanner's reach."
                    ),
                )
            )

        # Every path the walk could not reach is a gap of its own, which blocks whatever its cause
        # (item 27): a machine's cause can be provoked too, a mode-000 directory is EACCES. The
        # cause, read from the errno or the walker's own reason and never from a message, decides
        # only what the finding says to do.
        for errors, rule, remediation in (
            (
                [e for e in walker.stats.errors if e.the_machines],
                "OPERATIONAL.WALK.ERROR",
                "The host refused or failed the read (a permission, I/O, the process's own limits): "
                "retry where the scan can read the whole tree. A path the walker could not reach is "
                "not a path that was found clean. If the tree's own permissions hide it, the package "
                "is hiding content.",
            ),
            (
                [e for e in walker.stats.errors if not e.the_machines],
                "OPERATIONAL.WALK.SHAPE",
                "The tree's own shape put these paths out of reach (a name too long, a loop of "
                "links, a path past scan.limits.max_path_bytes): the package is hiding content from "
                "the scan. Inspect them directly, or accept the gap for that path deliberately.",
            ),
        ):
            if not errors:
                continue
            for error in errors:
                acc.named_elsewhere(rule, error.path)
            sample = ", ".join(e.path[:120] for e in errors[:5])
            more = f" and {len(errors) - 5} more" if len(errors) > 5 else ""
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id=rule,
                    message=(
                        f"{len(errors)} path(s) could not be traversed and were "
                        f"not examined: {sample}{more}."
                    ),
                    remediation=remediation,
                    severity=Severity.MEDIUM,
                )
            )

    def exclusions(self, acc: Accumulator, walker: Walker) -> None:
        """Plugins that tried to shadow a built-in, directories pruned, and exclusion patterns that matched nothing."""
        for group, name, provider in self.shadowed:
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.PLUGIN.SHADOWED",
                    category=Category.POLICY,
                    severity=Severity.HIGH,
                    message=(
                        f"The package {provider!r} registers {name!r} in {group}, which "
                        f"is the name of a built-in. It was not loaded; the built-in "
                        f"ran. A package that can replace a detector can disable it."
                    ),
                    remediation=(
                        "Uninstall the package, or report it if you did not install it "
                        "deliberately."
                    ),
                )
            )

        self.pruned_directories(walker, acc)

        # An exclusion matching nothing is either a mistake or a hole held open
        # for a file that does not exist yet. Both are worth surfacing: commit a
        # file at that path and it would be skipped by the very check meant to
        # examine it.
        for pattern in walker.stats.unmatched_patterns:
            acc.append(
                OperationalFinding.build(
                    path=pattern,
                    rule_id="POLICY.EXCLUDE.UNMATCHED",
                    category=Category.POLICY,
                    severity=Severity.LOW,
                    message=(
                        f"Exclusion pattern {pattern!r} matched nothing. An exclusion "
                        f"for a path that does not exist silently skips any file later "
                        f"committed there."
                    ),
                    remediation="Remove the pattern, or correct it to match its intended path.",
                )
            )

    def pruned_directories(self, walker: Walker, acc: Accumulator) -> None:
        """Directories the walk pruned, said once with how many files they held."""
        # Directories the built-in prune list skipped. Reported, because they
        # were not: a file never walked was indistinguishable in the output from
        # one scanned and found clean, which is the failure this whole file
        # exists to prevent, applied to the tool's own defaults.
        #
        # `node_modules` is why this matters rather than being tidy. It is where
        # an installed malicious dependency's code and lifecycle scripts live,
        # so a scan run after `npm install` could not see the dependency code it
        # was there to examine and said nothing about that.
        if walker.stats.pruned_dirs:
            names = sorted(walker.stats.pruned_dirs)
            sample = ", ".join(names[:6])
            more = f" and {len(names) - 6} more" if len(names) > 6 else ""
            pruned = OperationalFinding.build(
                path=REPOSITORY_SCOPE,
                rule_id="POLICY.COVERAGE.PRUNED",
                category=Category.POLICY,
                severity=Severity.LOW,
                message=(
                    f"{len(names)} director(ies) were skipped by the built-in prune "
                    f"list and not examined: {sample}{more}. These normally hold "
                    f"build output or an installed dependency tree, which is "
                    f"reproducible from the manifests that were scanned -- but "
                    f"installed dependency code is also where a malicious package's "
                    f"payload actually runs from."
                ),
                remediation=(
                    "Pass --include with a pattern covering the directory to scan "
                    "it, for example --include 'node_modules/**'."
                ),
            )
            # An installed dependency tree or an editor execution vector was
            # skipped, so code that runs was not read. A default scan still only
            # carries the low note above, but the result is marked incomplete so
            # `--fail-on-incomplete` fails on it -- the same stance the walker
            # takes toward an archive pruned past its depth limit, applied to
            # the directory where an installed malicious package's payload runs.
            skipped_code = set(walker.stats.pruned_dirs) & set(INSTALLED_CODE_PRUNE_DIRS)
            # A narrowed scan (`--staged`, `--tracked`, `--git-diff`) still walks the working
            # tree once, for the repository inventory, and that walk prunes `node_modules/` on
            # every developer machine. Marking the scan incomplete for it failed a pre-commit
            # hook under any policy with `fail_on_incomplete` - on every commit, for a directory
            # holding nothing the commit contained. What decides it for a narrowed scan is
            # whether a path it was ASKED to read lies under a pruned directory.
            narrowed_to: frozenset[str] | None = getattr(self.source, "selected_paths", None)
            if narrowed_to is not None:
                skipped_code = {
                    name
                    for name in skipped_code
                    if any(name in path.split("/")[:-1] for path in narrowed_to)
                }
            if skipped_code:
                acc.incomplete(pruned)  # the operator's scope: blocks only with the flag
            else:
                acc.append(pruned)

    def opened(self, rel_path: str, loaded: FileContent, deadline: float) -> Expansion:
        """An archive's bytes opened by the bounded reader: its members, or why it was refused, and
        the members it refused, each relative to the archive's own name. Records nothing: every
        copy records the outcome at its own path (`Expansion.record`)."""
        refusal = "Treat a refused archive as unexamined. If the limits are wrong for this input, raise them deliberately."
        if loaded.truncated:
            return Expansion(
                None,
                (
                    "The archive is larger than limits.max_file_bytes, so it was read in part and "
                    "could not be opened. Its contents were not examined.",
                    "Raise limits.max_file_bytes, or scan the archive directly.",
                ),
                truncated=True,
            )
        rejected: list[tuple[str, str, str]] = []
        collected: list[tuple[str, bytes]] = []
        prefix = rel_path.rsplit("/", 1)[-1]
        members: list[tuple[str, bytes]] | None = collected
        refused: tuple[str, str] | None = None
        stubs: set[str] = set()
        try:
            for member_path, member_data in ArchiveReader.walk_archive(
                loaded.raw,
                path=prefix,
                limits=self.config.limits,
                rejected=rejected,
                deadline=deadline if self.config.limits.total_timeout > 0 else None,
                import_library=stubs,
            ):
                collected.append((member_path[len(prefix) :], member_data))
        except ArchiveError as exc:
            members = None
            refused = (f"The archive was refused and not scanned: {exc.message}", refusal)
        relative = tuple((path[len(prefix) :], reason, detail) for path, reason, detail in rejected)
        marked = frozenset(path[len(prefix) :] for path in stubs)
        return Expansion(members, refused, rejected=relative, import_library=marked)

    def expand_members(
        self, rel_path: str, loaded: FileContent, acc: Accumulator, deadline: float
    ) -> list[FileUnit] | None:
        """The members of an archive found during a directory scan, as units.

        A vendored `.whl`, `.jar`, `.tgz` or `.nupkg` is part of what a repository
        ships, and one reported as "not examined" let a malicious artefact pass the
        default gate. Members are expanded in memory by the same bounded reader a
        scanned archive uses, named `archive!member` exactly as they are when the
        archive is the target, and never written to disk.

        Expanded once per distinct content per scan: the same wheel vendored in ten
        places is read ten times from disk but opened once. Returns None when the
        archive was refused, so the caller reports it as unexamined rather than as
        opened.
        """
        started = time.monotonic()
        expansion = self._expansions.get(loaded.sha256)
        if expansion is None:
            expansion = self.opened(rel_path, loaded, deadline)
            self._expansions[loaded.sha256] = expansion
            if expansion.members is not None:
                self._archive_stats[0] += 1
        # Every copy answers for itself, at its own path, whether its bytes were opened here or
        # before: a refusal recorded only at the first copy let accepting that copy's gap pass every
        # other copy unread.
        expansion.record(rel_path, acc)
        self._archive_stats[2] += int((time.monotonic() - started) * 1000)
        members = expansion.members
        if members is None:
            return None
        units: list[FileUnit] = []
        for suffix, data in members:
            member_path = rel_path + suffix
            content = FileContent.from_member(member_path, data, self.config.limits)
            if content.truncated:
                note = ArchiveMembers.truncated_note(member_path, content)
                acc.append(note if ArchiveMembers.read_to_end(content) else acc.gap(note))
            units.append(
                FileUnit(
                    content=content,
                    language=LanguageRegistry.of_file(member_path, content),
                    import_library=suffix in expansion.import_library,
                )
            )
        self._archive_stats[1] += len(units)
        return units

    _DEOBFUSCATION_MARKERS: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"while\s*\(\s*!!\[\]\s*\)|\batob\s*\(|\bBuffer\s*\.\s*from\s*\(\s*['\"`][A-Za-z0-9+/=_\-]{16}"
        rb"|fromCharCode\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*,|\xf3\xa0[\x80-\x87]|\xef\xb8[\x80-\x8f]"
        rb"|fromCharCode|\bBuffer\s*\.\s*from\s*\(\s*[A-Za-z_$]|\.\s*reverse\s*\(\s*\)\s*\.\s*join"
    )
    """Bytes without which no reversal in `core.deobfuscation` applies: most files pay one search."""

    def deobfuscated(self, units: list[FileUnit]) -> list[FileUnit]:
        """Each obfuscated JavaScript file reversed statically, as a unit of its own.

        Read by every detector with the context of the file it came from (`_lifted_inherit`), so
        what the code does is graded rather than that it was hidden. A file that cannot be
        reversed, or only in part, is not lifted, and its obfuscation finding keeps its grade.
        """
        from cordon_scanner.analysis.shared.deobfuscator import Deobfuscator

        lifted: list[FileUnit] = []
        for unit in units:
            if (
                unit.content.is_binary
                or unit.language not in ("javascript", "typescript")
                or "#" in unit.path
                or not Units._DEOBFUSCATION_MARKERS.search(unit.content.raw)
            ):
                continue
            recovery = Deobfuscator.recover(unit.content.text, unit.language)
            if recovery is None or recovery.resolved == 0:
                continue
            if recovery.remaining > max(3, recovery.resolved // 20):
                continue
            path = unit.path + Hooks.DEOBFUSCATED
            content = FileContent.from_bytes(
                path, recovery.text.encode("utf-8"), self.config.limits
            )
            lifted.append(FileUnit(content=content, language="javascript"))
        return lifted

    def content_readings(self, units: list[FileUnit]) -> list[FileUnit]:
        """Each file whose bytes are another language than its name says, read as that one too.

        `run.js` holding Python is still read as JavaScript, and is also a unit of its own,
        `run.js#as-python.py`, read by every detector with the context of the file it is
        (`Hooks.lifted_inherit`). See `ContentLanguage` for when, and why never in place of the
        name's reading.
        """
        from cordon_scanner.analysis.shared.content_language import ContentLanguage
        from cordon_scanner.foundation.paths import ContainerPaths

        readings: list[FileUnit] = []
        for unit in units:
            if unit.content.is_binary or "#" in unit.path:
                continue
            other = ContentLanguage.second_reading(
                unit.content.text_head(LanguageRegistry.MAX_SNIFF_BYTES),
                unit.language,
                functools.partial(getattr, unit.content, "text"),
            )
            if other is None:
                continue
            path = ContainerPaths.reading(unit.path, other)
            content = FileContent.from_bytes(path, unit.content.raw, self.config.limits)
            readings.append(FileUnit(content=content, language=other, project=unit.project))
        return readings

    def inline_hooks(self, units: list[FileUnit]) -> list[FileUnit]:
        """The programs install hooks carry inline, each as a unit of its own.

        `node -e "<program>"` in a `postinstall` is install-time code like the file
        `node install.js` runs, and is read the same way: by every content detector, with the
        hook's escalation. See `core.inline_programs`. Author-time hooks are left alone, as
        their files are.
        """
        lifted: list[FileUnit] = []
        known = {unit.path for unit in units}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None or ecosystem_id == "image" or unit.content.is_binary:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                hooks = ParsedManifests.manifest_alone(
                    ecosystem, unit
                ).hooks  # a raise, recorded once
            except Exception:  # noqa: BLE001, S112
                continue
            for hook in hooks:
                if not hook.command or hook.name.lower() in AUTHOR_TIME_HOOKS:
                    continue
                for program in InlinePrograms.lifted(unit.path, hook.name, hook.command):
                    if program.path in known:
                        continue
                    known.add(program.path)
                    content = FileContent.from_bytes(
                        program.path, program.source.encode("utf-8"), self.config.limits
                    )
                    lifted.append(
                        FileUnit(
                            content=content,
                            language=LanguageRegistry.of_file(program.path, content),
                        )
                    )
        return lifted


__all__ = ["Units"]
