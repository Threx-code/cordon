"""What a scan did not cover, said as findings: files skipped by size, type or exclusion, a broad
exclusion that removed most of the tree, a walk cut short, a source the scan could not fully read.

A file that was not examined is indistinguishable in the output from one examined and found clean,
so every gap in coverage is reported, never left to be inferred.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.engine.pipeline.constants import (
    BLINDING_SETTINGS,
    BROAD_EXCLUSION_MIN_FILES,
    BROAD_EXCLUSION_SHARE,
    REPOSITORY_SCOPE,
)
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.engine.walker import WalkStats
from cordon_scanner.foundation.models import (
    Category,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.engine.engine import Engine


class Coverage:
    """Findings about what a scan did not cover."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.config = engine.config
        self.source = engine.source

    def findings(
        self,
        stats: WalkStats,
        root: Path,
        selected: int,
        *,
        complete: bool,
        binary: Sequence[str] = (),
        lfs_pointers: Sequence[str] = (),
        examined: int = 0,
    ) -> list[Finding]:
        """Report configuration that reduced what was examined.

        None of this is prevented, because a repository has legitimate reasons
        to exclude generated directories and to turn off a detector that does
        not apply. What is guaranteed is that the reduction appears in the
        output, so a reviewer can see that a clean result was produced by not
        looking.
        """
        findings: list[Finding] = []

        # Files that exist but hold no source to examine. One aggregated finding
        # rather than one per file: a repository with four hundred icons would
        # otherwise drown the report, and a report nobody reads is the same
        # outcome as not reporting.
        #
        # Reported at INFO and not treated as incompleteness. A PNG is not a
        # degraded scan, it is a file with nothing for a source rule to match.
        # Marking every repository with an image as incomplete would make
        # `fail_on_incomplete` unusable, and an unusable control is worse than
        # an absent one.
        # Git LFS pointers, aggregated for the same reason binaries are. A repository
        # that tracks its assets through LFS has hundreds, and a checkout without LFS -
        # which is what `actions/checkout` does by default - turns every one of them
        # into a 130-byte text file naming content that is still on a server.
        #
        # Reported rather than passed over, because a file that was not examined must
        # not look like a file that was examined and found clean. Not treated as
        # incompleteness: a repository's images being absent is not a degraded scan of
        # its source, and marking it so would make `fail_on_incomplete` unusable for
        # every project that uses LFS.
        #
        # `unionlabs/union` tracks `*.png`, `*.pdf` and `*.psd`, and a shallow clone of
        # it produced 907 format-mismatch findings before this: every tracked asset
        # reported as a file contradicting its own extension.
        if lfs_pointers:
            sample = ", ".join(sorted(lfs_pointers)[:5])
            more = f" and {len(lfs_pointers) - 5} more" if len(lfs_pointers) > 5 else ""
            findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.FILE.LFS_POINTER",
                    severity=Severity.INFO,
                    message=(
                        f"{len(lfs_pointers)} file(s) are Git LFS pointers, so the bytes "
                        f"they name were not fetched and nothing about their content was "
                        f"examined: {sample}{more}."
                    ),
                    remediation=(
                        "Clone with LFS content if these files matter to the scan. "
                        "`actions/checkout` needs `lfs: true`, which is off by default."
                    ),
                )
            )

        if binary:
            sample = ", ".join(sorted(binary)[:5])
            more = f" and {len(binary) - 5} more" if len(binary) > 5 else ""
            findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.FILE.BINARY",
                    severity=Severity.INFO,
                    message=(
                        f"{len(binary)} file(s) were not examined as source because "
                        f"they are binary artefacts: {sample}{more}."
                    ),
                    remediation=(
                        "No action needed for genuine binaries. The classification "
                        "is made from the file's extension and leading bytes, never "
                        "from its contents, so a source file cannot be excluded from "
                        "scanning by what it contains."
                    ),
                )
            )

        # Anything the *scan target's own* configuration removed, at any share.
        #
        # BROAD_EXCLUSION below only fires past 80 percent of a tree of at least
        # 25 files, which is right for "this repository excludes most of
        # itself" and useless against the actual attack: one line excluding the
        # one file that carries the finding. That produced output byte-for-byte
        # identical to a clean scan.
        #
        # HIGH, not MEDIUM, because the default gate fails at HIGH. A repository
        # removing a file from its own scan is not a note.
        if self.config.untrusted_exclusions:
            removed = {
                pattern: count
                for pattern, count in stats.excluded_by_pattern.items()
                if pattern in set(self.config.untrusted_exclusions) and count
            }
            dropped = stats.files_dropped_by_config
            if removed or dropped:
                listed = ", ".join(
                    f"{pattern!r} ({count})" for pattern, count in sorted(removed.items())
                ) or ", ".join(repr(p) for p in sorted(self.config.untrusted_exclusions))
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.TARGET_EXCLUSION",
                        category=Category.POLICY,
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration removed {dropped} "
                            f"file(s) from this scan: {listed}. A file the scan target "
                            f"excluded is a file it chose not to have examined, which "
                            f"is reported whatever the count -- one file is enough when "
                            f"it is the right one."
                        ),
                        remediation=(
                            "Confirm each pattern is intended. Exclusions an operator "
                            "needs belong on the command line or in a config passed "
                            "with --config, where they are not supplied by the thing "
                            "being scanned."
                        ),
                    )
                )

        # Nothing at all was examined, but the tree is not empty.
        #
        # The count that matters is what reached a detector and was read, not
        # what the walker selected. Those diverge whenever selected files fail
        # to load, and that gap was the whole bug: make every file in a
        # repository unreadable and each one produced an INFO note, `selected`
        # stayed at its full value, this check never fired, and the scan exited
        # 0. A repository nothing could be read from reported exactly like a
        # repository with nothing in it -- which is the one outcome this tool
        # is built to prevent.
        if examined == 0 and stats.files_seen > 0:
            # Always reported, never silent. An empty *selection* may be
            # ordinary -- an empty staged set is a normal commit -- but files
            # that were selected and then could not be read is never ordinary,
            # whatever the source, so the source's opinion only applies when it
            # selected nothing in the first place.
            unreadable = selected > 0
            normal = self.source.empty_selection_is_normal and not unreadable
            cause = (
                f"{selected} file(s) were selected and none could be read"
                if unreadable
                else (
                    f"everything was removed by configuration or by the selected "
                    f"source ({self.source.describe()})"
                )
            )
            findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.COVERAGE.NOTHING_SCANNED",
                    category=Category.POLICY,
                    severity=Severity.INFO if normal else Severity.HIGH,
                    message=(
                        f"No files were examined, although {stats.files_seen} were "
                        f"present: {cause}. This result reports that nothing was "
                        f"looked at rather than that nothing was found."
                    ),
                    remediation=(
                        "Review the exclude patterns and any --staged, --tracked or "
                        "--git-diff selection, and check the permissions on the tree. "
                        "A clean scan that examined no files is not a clean scan."
                    ),
                )
            )
        elif stats.files_seen >= BROAD_EXCLUSION_MIN_FILES:
            dropped = stats.files_dropped_by_config
            share = dropped / stats.files_seen
            # A repository excluding most of itself may be correct -- a large
            # vendored tree, a generated directory -- but it is worth stating,
            # because it is also exactly what blinding the scanner looks like.
            # The floor on tree size is there so a five-file repository with one
            # generated directory does not produce this every run; a check that
            # fires constantly on correct configuration gets excluded itself.
            if share >= BROAD_EXCLUSION_SHARE:
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.BROAD_EXCLUSION",
                        category=Category.POLICY,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Configuration removed {dropped} of {stats.files_seen} "
                            f"files ({share:.0%}) before any check ran. That may be "
                            f"correct for a repository with a large generated or "
                            f"vendored tree, and it is also what blinding a scanner "
                            f"looks like, so it is reported either way."
                        ),
                        remediation=(
                            "Confirm the exclusions are intended. Narrow any that "
                            "cover more than the generated output they were written "
                            "for."
                        ),
                    )
                )

        # A detector turned off in a config that came from the scan target.
        if self.config.from_untrusted_source:
            disabled = sorted(name for name, on in self.config.detectors.items() if on is False)
            if disabled:
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.DETECTOR_DISABLED",
                        category=Category.POLICY,
                        # HIGH, because the default gate fails at HIGH and this
                        # was reported at MEDIUM: `detectors: {manifest: false}`
                        # in the scan target's own config made a CRITICAL
                        # finding disappear and the build pass.
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration disabled "
                            f"{len(disabled)} detector(s): {', '.join(disabled)}. "
                            f"Those checks did not run."
                        ),
                        remediation=(
                            "Confirm each is genuinely inapplicable. An organisation "
                            "policy can require detectors that a repository may not "
                            "disable."
                        ),
                    )
                )

            if self.config.disabled_rules:
                names = ", ".join(sorted(self.config.disabled_rules))
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.RULE_DISABLED",
                        category=Category.POLICY,
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration disabled "
                            f"{len(self.config.disabled_rules)} rule(s): {names}. "
                            f"Those checks produced nothing here whatever the code "
                            f"contains."
                        ),
                        remediation=(
                            "Confirm each is genuinely inapplicable. An organisation "
                            "policy can require rules that a repository may not "
                            "disable."
                        ),
                    )
                )

            for setting in self.config.reduced_limits:
                # An incomplete scan does not fail the build by default, and
                # that default is right: making it fatal would break pipelines
                # on the first genuinely large repository and teach people to
                # append `|| true`, which is worse than the failure it prevents.
                #
                # It is not right here. This scan is incomplete *because the
                # scan target asked for it to be*, which is not the same thing
                # as a repository that outgrew a default, so it fails.
                truncated = not complete
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.CONFIG.LIMIT_REDUCED",
                        category=Category.POLICY,
                        severity=Severity.HIGH if truncated else Severity.MEDIUM,
                        message=(
                            f"{setting} was lowered below the built-in default by the "
                            f"repository's own configuration, which narrows what the "
                            f"scan reaches. A lowered limit is an exclusion written in "
                            f"a form that produces no exclusion patterns to report, so "
                            f"it is reported here instead."
                            + (
                                " The scan did not finish, so this limit is what stopped it."
                                if truncated
                                else ""
                            )
                        ),
                        remediation=(
                            "Confirm the reduction is intended. If the scan is slow, "
                            "narrow it with exclusions, which are visible, rather than "
                            "with a limit, which is not."
                        ),
                    )
                )

            for setting in self.config.clamped_settings:
                # Weakening the failure gate is reported at HIGH, where the
                # default gate fails, rather than at LOW with the resource
                # limits. Raising a limit is a repository being greedy with the
                # scanning machine; emptying `fail_on` is a repository turning
                # the verdict off for every finding including MALICIOUS at
                # CRITICAL. Those are not the same act and must not read the
                # same in a report.
                gate = setting.startswith("policy.")
                blinding = setting in BLINDING_SETTINGS
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id=(
                            "POLICY.CONFIG.GATE_WEAKENED"
                            if gate or blinding
                            else "POLICY.CONFIG.CLAMPED"
                        ),
                        category=Category.POLICY,
                        severity=Severity.HIGH if gate or blinding else Severity.LOW,
                        message=(
                            (
                                f"The repository's own configuration tried to weaken the "
                                f"failure gate ({setting}) and was refused. A scan target "
                                f"cannot decide which of its own findings are allowed to "
                                f"fail the build; the built-in gate was used instead."
                            )
                            if gate
                            else (
                                f"The repository's own configuration set {setting}, which "
                                f"switches detection off or loads code into the scanner, and "
                                f"was refused. A scan target cannot choose how closely it is "
                                f"examined; the built-in behaviour was used instead."
                            )
                            if blinding
                            else (
                                f"{setting} was set by the repository's own configuration "
                                f"and reduced to the built-in default. A configuration "
                                f"file inside the scan target cannot raise a resource "
                                f"limit or add a rule pack, because both can be used "
                                f"against the machine running the scan."
                            )
                        ),
                        remediation=(
                            "Pass the value on the command line, which is operator "
                            "input, or set it in an organisation policy."
                        ),
                    )
                )

        return findings


__all__ = ["Coverage"]
