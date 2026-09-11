"""What the repository's own history says.

Every other detector looks at the tree as it stands. This one asks how it got
that way, because two of the cheapest supply-chain attacks leave nothing in the
final state worth flagging.

**A hook added recently.** A script under `.githooks/` or `.git/hooks/` runs on
commit, checkout and merge, on the machine of anybody who has the repository
configured -- without them running anything themselves and before any review.
The file is ordinary shell; what makes it worth a second look is that it arrived
in the last few commits rather than having been there since the project started.

**A binary added recently.** The binary detector reports committed executables
wherever they sit. History adds the fact that changes the reading: a `.so` that
has been vendored for two years is a build artefact, and one that appeared this
week alongside a version bump is a different thing entirely.

**Recency is the whole contribution, and it is a weak signal on its own.** Both
findings are reported at low or medium, because "this was added recently" is
context for a reviewer rather than a claim about intent. What it does is put the
right files in front of somebody: the checks above are worthless applied to
every hook and every binary in a mature repository, and useful applied to the
handful that changed.

**Bounded and local.** A fixed number of recent commits, read with the hardened
git wrapper the rest of the project uses, no network, and a failure to read
history is reported rather than treated as an absence of findings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    RepositoryUnit,
    ScanContext,
)
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit

RECENT_COMMITS = 40
"""How far back to look.

Far enough that a change introduced a few releases ago is still visible, short
enough that reading it costs milliseconds on a repository of any size. A
history-wide audit is a different tool with a different runtime, and pretending
this is one would be the more misleading choice."""

HOOK_PREFIXES = (".githooks/", ".git/hooks/", "hooks/")
"""Directories a git hook is found in."""

#: The names git will actually run. A file under a hooks directory whose name is
#: not one of these is not a hook: git executes a fixed set of names and ignores
#: everything else, including `README`, `*.sample` and any helper a real hook
#: sources.
#:
#: Required because `hooks/` is in the prefixes above, and `hooks/` is also where
#: every React and Vue project in existence keeps its `useSomething.ts`. Scanning
#: a front end reported `hooks/useStepUp.ts` as "a version-control hook added in
#: recent history" -- a file git has never heard of, in a directory that has
#: nothing to do with git, at medium severity. The prefix cannot be dropped,
#: because `hooks/` really is a hooks directory under `core.hooksPath`; what
#: separates the two cases is whether the FILENAME is one git runs.
GIT_HOOK_NAMES = frozenset(
    {
        "applypatch-msg",
        "commit-msg",
        "fsmonitor-watchman",
        "post-applypatch",
        "post-checkout",
        "post-commit",
        "post-merge",
        "post-receive",
        "post-rewrite",
        "post-update",
        "pre-applypatch",
        "pre-auto-gc",
        "pre-commit",
        "pre-merge-commit",
        "pre-push",
        "pre-rebase",
        "pre-receive",
        "prepare-commit-msg",
        "proc-receive",
        "push-to-checkout",
        "reference-transaction",
        "sendemail-validate",
        "update",
    }
)

#: Hooks directories a repository manages for itself, which it wires up with
#: `core.hooksPath`.
#:
#: A hook here is tracked, was reviewed in the pull request that added it, and is
#: in every clone. A hook in `.git/hooks` is none of those things: it is local to
#: one machine, invisible to review, and cannot have arrived through a merge --
#: which is precisely why it is the interesting one.
#:
#: The distinction was missing, so a repository that commits its hooks and wires
#: them deliberately -- the practice this project recommends, and the one
#: `cordon guard install` sets up -- was reported for doing it. Cordon was
#: flagging its own installation.
TRACKED_HOOK_PREFIXES = (".githooks/", "hooks/")

BINARY_SUFFIXES = (
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".o",
    ".a",
    ".node",
    ".wasm",
    ".class",
    ".jar",
    ".pyd",
)


class VcsDetector(BaseDetector):
    """Reports what recent history changed, where the change is the signal."""

    id = "vcs"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=False, repository=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return ctx.repository is not None and ctx.repository.is_git

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.VCS.HOOK_ADDED.001",
                title="Version-control hook added in recent history",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=VcsDetector.id,
                remediation=(
                    "Read the hook. It runs on commit, checkout and merge for "
                    "everyone with this repository configured, before any review."
                ),
            ),
            DeclaredRule(
                id="POLICY.VCS.BINARY_ADDED.001",
                title="Executable or archive added in recent history",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=VcsDetector.id,
                remediation=(
                    "Confirm the artefact is expected. A binary that has been "
                    "vendored for years and one that appeared this week are "
                    "different things wearing the same file extension."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.VCS.UNREADABLE.001",
                title="Repository history could not be read",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=VcsDetector.id,
                remediation=(
                    "Run the scan where the repository is complete. A shallow "
                    "clone has no history to examine."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, RepositoryUnit):
            return ()

        repository = unit.repository
        if not repository.is_git:
            return ()

        try:
            changed = self.recent_paths(repository.root)
        except Exception as exc:
            # Reported rather than swallowed. A scan that could not read the
            # history and a scan that read it and found nothing must not look
            # the same, which is the invariant this whole project is built
            # around.
            return [
                self._finding(
                    "OPERATIONAL.VCS.UNREADABLE.001",
                    ctx,
                    path="",
                    detail=(
                        f"the last {RECENT_COMMITS} commits could not be read, so "
                        f"nothing about recent history was examined: "
                        f"{type(exc).__name__}"
                    ),
                )
            ]

        findings: list[Finding] = []
        for path in changed:
            lowered = path.lower()
            if VcsDetector.is_git_hook(lowered):
                tracked = any(
                    lowered.startswith(prefix) or f"/{prefix}" in f"/{lowered}"
                    for prefix in TRACKED_HOOK_PREFIXES
                )
                findings.append(
                    self._finding(
                        "SUSPECT.VCS.HOOK_ADDED.001",
                        ctx,
                        path=path,
                        # Reported either way, and the detail says which, because
                        # the two are not the same event and a reader has to be
                        # able to tell them apart without opening the repository.
                        severity=Severity.LOW if tracked else Severity.MEDIUM,
                        detail=(
                            f"{path} was added or changed in the last {RECENT_COMMITS} commits"
                            + (
                                "; it is tracked, so it was reviewed when it landed "
                                "and is the same in every clone"
                                if tracked
                                else "; it is under .git/, so it is local to this "
                                "machine and was never reviewed"
                            )
                        ),
                    )
                )
            elif lowered.endswith(BINARY_SUFFIXES):
                findings.append(
                    self._finding(
                        "POLICY.VCS.BINARY_ADDED.001",
                        ctx,
                        path=path,
                        detail=(
                            f"{path} was added or changed in the last {RECENT_COMMITS} commits"
                        ),
                    )
                )
        return findings

    @staticmethod
    def is_git_hook(lowered_path: str) -> bool:
        """Whether this path is a file git will run as a hook.

        Both halves are required. A hooks directory alone matches every React
        project's `hooks/useThing.ts`; a hook name alone matches `src/pre-push`,
        which is a script somebody happens to have named that.
        """
        in_hooks_directory = any(
            lowered_path.startswith(prefix) or f"/{prefix}" in f"/{lowered_path}"
            for prefix in HOOK_PREFIXES
        )
        if not in_hooks_directory:
            return False
        name = lowered_path.rpartition("/")[2]
        # `.sample` is what git ships in every new repository. Those are not hooks
        # until renamed, and a fresh clone carries a dozen of them.
        return name in GIT_HOOK_NAMES

    @staticmethod
    def recent_paths(root: str) -> list[str]:
        """Paths under the scan target that the most recent commits touched.

        Uses the project's own git wrapper, which strips the environment
        variables that let a repository redirect git at something else -- the
        scan target is untrusted, and that includes the repository
        configuration it ships.

        **Scoped to what was asked for.** `git log` answers about the whole
        repository, and the scan target is frequently a subdirectory of one:
        asking about `packages/api` in a monorepo was reporting binaries and
        hooks added under `packages/web`, which is both noise and an answer to a
        question nobody asked. Paths are filtered to the target and rewritten
        relative to it, so they line up with every other finding's location.
        """
        from cordon_scanner.sources.git import GitRepository

        repository = GitRepository(root)
        try:
            output = repository.run(
                [
                    "log",
                    f"-{RECENT_COMMITS}",
                    "--name-only",
                    "--pretty=format:",
                    "--diff-filter=AM",
                ]
            )
            # Where the scan target sits inside the repository. Empty when the
            # target is the repository root, which is the common case.
            prefix = repository.run(["rev-parse", "--show-prefix"], check=False).strip()
        finally:
            repository.close()

        seen: dict[str, None] = {}
        for line in output.splitlines():
            path = line.strip()
            if not path:
                continue
            if prefix:
                if not path.startswith(prefix):
                    continue
                path = path[len(prefix) :]
            seen.setdefault(path, None)
        return list(seen)

    def _finding(
        self,
        rule_id: str,
        ctx: ScanContext,
        *,
        path: str,
        detail: str,
        severity: Severity | None = None,
    ) -> Finding:
        """One finding, at the declared severity unless the caller lowers it.

        `severity` is an override rather than a parameter every call passes,
        because the declared value is the right answer for all but one case: a
        hook under a tracked hooks directory, which is reported to be seen and not
        to block.
        """
        declared = next(r for r in self.declared_rules() if r.id == rule_id)
        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=severity or declared.severity,
            confidence=declared.confidence,
            message=detail,
            location=Location(path=path, line=1),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(path.encode("utf-8")),
                redaction=RedactionMode.HASH_ONLY,
            ),
            remediation=declared.remediation,
            explanation=Explanation(summary=detail, matched_rule=rule_id),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(in_install_hook=False, capabilities=frozenset()),
            ),
            detector=self.id,
            always_report=declared.category is Category.OPERATIONAL,
        )


__all__ = ["RECENT_COMMITS", "VcsDetector"]
