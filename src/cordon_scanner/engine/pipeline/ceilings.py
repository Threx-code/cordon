"""The ceilings a package's verdict is held under, from what the package is and how it runs: a tool a
person runs by hand, an agent's or editor's tree, a build definition, a release that runs on its
own, an image's start scripts, author-time hooks, and a download an impersonator runs. Each says
how far its findings can raise the verdict, and why.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.engine.pipeline.constants import (
    AUTHOR_TIME_FILENAMES,
    AUTHOR_TIME_PREFIXES,
    COMPILED_SOURCE,
    CONDA_LINK_SCRIPT,
    DEPENDENCY_BUILD_FILENAMES,
    MAKE_AT_INSTALL,
    MAKEFILES,
    PROJECT_BUILD_FILENAMES,
    REGISTRY_REVIEW_RULE,
    REPOSITORY_SCOPE,
    SHIPPED_DOCUMENTS,
    STANDALONE_SCRIPTS,
)
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.taxonomy import ThreatDomain


class Ceilings:
    """The package verdict and the ceilings it is held under."""

    #: Manifests the verdict reads for package context, by file name.
    _VERDICT_MANIFESTS: ClassVar[tuple[str, ...]] = (
        "package.json",
        "setup.py",
        "pyproject.toml",
        "requirements.txt",
        # A skill's claim about itself: its front matter's name and description.
        "SKILL.md",
    )

    @staticmethod
    def verdict(
        findings: list[Finding],
        units: Sequence[FileUnit],
        profile: dict[str, float] | None = None,
        intent: Any = None,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """The package verdict over everything this scan found (`core/verdict.py`), then the
        intent layer over what the package's code does (`core/intent.py`)."""
        from cordon_scanner.decide.intent import Intent
        from cordon_scanner.decide.verdict import Verdict

        paths_sizes = [(u.path, u.content.size) for u in units]
        manifests = {
            u.path: u.content.raw[:1_000_000]
            for u in units
            if u.path.rsplit("!", 1)[-1].rsplit("/", 1)[-1] in Ceilings._VERDICT_MANIFESTS
        }
        sources = [
            (u.path, u.content.raw)
            for u in units
            if u.path.rsplit("!", 1)[-1].lower().endswith((".js", ".mjs", ".cjs", ".ts", ".py"))
        ]
        graded, verdict = Verdict.decide(
            list(findings), paths_sizes, manifests, sources, profile or {}
        )
        second, line = verdict.get("registry_score"), verdict.get("registry_block")
        Ceilings.second_opinion(second, line, graded, verdict)
        score, block = verdict.get("score"), verdict.get("block")
        Ceilings.score_verdict(score, block, verdict, graded)
        area = str(verdict.get("area", ""))
        review = Intent.review(verdict.get("package", {}), area, intent)
        Ceilings.review_verdict(review, verdict, graded, area)
        return graded, verdict

    @staticmethod
    def second_opinion(
        second: Any | None, line: Any | None, graded: list[Finding], verdict: dict[str, Any]
    ) -> None:
        """A second model's score past the line: said beside the first."""
        if second is not None and line is not None and second >= line:
            # The second review: what the registry recorded about this release -- who published
            # it, when the name was made, what it added over the release before -- scores over its
            # line (`intel/registry_record.py`). Content-free malware is found here or not at all.
            graded.append(
                replace(
                    OperationalFinding.build(
                        path=".",
                        rule_id=REGISTRY_REVIEW_RULE,
                        message=(
                            f"What the registry recorded about this release scores {second:.2f} "
                            f"against the second review's line of {line:.2f} for "
                            f"{verdict.get('area', 'packages')}: its publisher, its age, its "
                            "release history and what it added are what malicious releases in the "
                            "training half looked like."
                        ),
                        remediation=(
                            "Check who published this release and why; pin a release from before "
                            "it until that is explained."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.MEDIUM,
                    always_report=False,
                    detector="registry-review",
                )
            )

    @staticmethod
    def score_verdict(
        score: Any | None, block: Any | None, verdict: dict[str, Any], graded: list[Finding]
    ) -> None:
        """A package whose score reaches the block line: said, with what reached it."""
        from cordon_scanner.decide.verdict import Verdict

        if score is not None and block is not None and score >= block:
            # The package over its line blocks as a package, whether or not one finding would
            # alone: the combination is the evidence. MalSkillBench's malicious skills were
            # flagged 98.3% of the time and blocked 80.1%, because no one of their findings was
            # strong alone (review 98).
            rules = sorted(verdict.get("rules", {}), key=lambda r: -verdict["rules"][r])
            graded.append(
                replace(
                    OperationalFinding.build(
                        path=".",
                        rule_id=Verdict.RULE,
                        message=(
                            f"Taken together, this package's findings ({', '.join(rules[:5])}"
                            f"{', ...' if len(rules) > 5 else ''}) and what kind of package it "
                            f"is score {score:.2f} against the blocking line of {block:.2f} for "
                            f"{verdict.get('area', 'packages')}: the combination is what malicious "
                            "packages in the training half looked like."
                        ),
                        remediation="Read each finding listed. Do not install until explained.",
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.MEDIUM,
                    always_report=False,
                    detector="verdict",
                )
            )

    @staticmethod
    def review_verdict(
        review: dict[str, Any] | None, verdict: dict[str, Any], graded: list[Finding], area: str
    ) -> None:
        """A package held for review: said, with the reason."""
        from cordon_scanner.decide.intent import RULE as INTENT_RULE
        from cordon_scanner.decide.intent import Intent

        if review is not None:
            # After the verdict, so nothing here is held as a warning by it, and nothing it adds
            # lowers or lifts a finding the rules made (E4). "unknown" -- a running file not
            # read (E5) -- stays in the verdict with its cause: never a pass, and no rule of
            # its own (one rule id, 19 step 0).
            verdict["intent"] = review
            if review.get("decision") == "block":
                graded.append(
                    replace(
                        OperationalFinding.build(
                            path=".",
                            rule_id=INTENT_RULE,
                            message=Intent.message(review, area),
                            remediation=(
                                "Read each listed effect and check it against what the package "
                                "says it is for. Do not install until each one is explained."
                            ),
                            category=Category.SUSPICIOUS,
                            severity=Severity.HIGH,
                        ),
                        confidence=Confidence.MEDIUM,
                        always_report=False,
                        detector="intent",
                    )
                )

    @staticmethod
    def hardening_tier(findings: list[Finding], policy: Policy) -> list[Finding]:
        """Record pipeline, container and infrastructure hardening findings at LOW.

        See `Policy.hardening`: those domains (`Policy.advisory_domains`) describe how a project
        configured itself, and by default they are reported in full and below the warning level.
        A MALICIOUS finding in them is never lowered; nor is anything when `--hardening` is on.
        """
        if policy.hardening:
            return findings
        from cordon_scanner.foundation.taxonomy import Taxonomy

        out: list[Finding] = []
        for finding in findings:
            domain = Taxonomy.domain_of(finding.rule_id)
            if finding.category is Category.SUSPICIOUS:
                # A generic code finding inside a container build file or a pipeline definition
                # is about how the project builds and ships, whatever rule read it: the RUN line
                # that downloads, unpacks and runs a toolchain is `SUSPECT.CONTAINER.*`'s
                # finding, and reading the same text as shell does not make it an attack on
                # whoever scans the repository (review 98: 45 benign units blocked by a dropper in
                # a Dockerfile, against no malware sample).
                domain = Ceilings._build_definition_domain(finding.location.path) or domain
            if (
                finding.category is not Category.MALICIOUS
                and finding.severity > Severity.LOW
                and domain in policy.advisory_domains
            ):
                finding = replace(
                    finding,
                    severity=Severity.LOW,
                    message=finding.message
                    + " Hardening finding: recorded at LOW by default; `--hardening` reports it "
                    "at its own severity.",
                )
            out.append(finding)
        return out

    _PIPELINE_FILES: ClassVar[frozenset[str]] = frozenset(
        {
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
            "bitbucket-pipelines.yml",
            "cloudbuild.yml",
            "cloudbuild.yaml",
            ".drone.yml",
            ".woodpecker.yml",
        }
    )

    @staticmethod
    def _build_definition_domain(path: str) -> ThreatDomain | None:
        """CONTAINER for a container build file, CICD for a pipeline definition, else None."""
        from cordon_scanner.foundation.taxonomy import ThreatDomain

        member = "/" + path.rpartition("!")[2]
        name = member.rpartition("/")[2]
        lower = name.lower()
        if lower.startswith(("dockerfile", "containerfile")) or lower.endswith(
            (".dockerfile", ".containerfile")
        ):
            return ThreatDomain.CONTAINER
        if (
            lower in Ceilings._PIPELINE_FILES
            or name.startswith("Jenkinsfile")
            or (lower.endswith((".yml", ".yaml")) and "/.github/workflows/" in member)
            or any(f"/{d}/" in member for d in (".circleci", ".buildkite", ".azure-pipelines"))
        ):
            return ThreatDomain.CICD
        return None

    #: Directories whose files a tool runs when the project is opened or committed to: editor
    #: tasks, dev containers, agent settings and hooks, git hooks.
    _OPENED_DIRECTORIES: ClassVar[tuple[str, ...]] = (
        "/.vscode/",
        "/.devcontainer/",
        "/.claude/",
        "/.cursor/",
        "/.windsurf/",
        "/.idea/",
        "/.husky/",
        "/.githooks/",
        "/.git/hooks/",
        "/.gemini/",
        "/.codex/",
        "/.continue/",
    )

    _OPENED_FILES: ClassVar[frozenset[str]] = frozenset(
        {".envrc", ".mcp.json", "mcp.json", "devcontainer.json", ".pre-commit-config.yaml"}
    )

    @staticmethod
    def _runs_on_its_own(path: str, ctx: ScanContext) -> bool:
        """Whether a repository file runs without a person naming it: installing the project
        (lifecycle hooks and what they import), building it (build definitions), opening it
        (editor tasks, direnv, dev containers, git and agent hooks), or an agent using it (MCP
        servers, skill scripts)."""
        if (
            path in ctx.install_hook_paths
            or path in ctx.agent_run_paths
            or path in ctx.install_entry_paths
            or path in ctx.consumer_install_paths
        ):
            return True
        member = path.rpartition("!")[2]
        if any(
            hook.kind in ("build", "startup", "projectbuild", "githook")
            for hook in Hooks.hooks_for(member)
        ):
            return True
        slashed = "/" + member
        name = ContainerPaths.basename(member)
        return (
            name in Ceilings._OPENED_FILES
            or any(d in slashed for d in Ceilings._OPENED_DIRECTORIES)
            or name in PROJECT_BUILD_FILENAMES
            or name in DEPENDENCY_BUILD_FILENAMES
            or name.endswith((".bzl", ".gradle", ".gradle.kts", ".mk"))
            or name in ("BUILD", "BUILD.bazel", "WORKSPACE", "MODULE.bazel", "CMakeLists.txt")
            or name in ("flake.nix", "default.nix", "shell.nix", "configure", "package.json")
        )

    _MCP_SDK_DECLARED: ClassVar[re.Pattern[str]] = re.compile(
        r"@modelcontextprotocol/sdk|^\s*(?:fastmcp|mcp)\s*[<>=~\[\"',]|^\s*rmcp\s*=|\"(?:fastmcp|mcp)[<>=~\[]",
        re.MULTILINE,
    )

    @staticmethod
    def _agent_or_editor_tree(units: Sequence[FileUnit], ctx: ScanContext) -> bool:
        """A tree an agent host or an editor starts: a skill (`SKILL.md`), an MCP server (its code
        runs on the agent's tool calls, `agent_run_paths`, or its manifest declares an MCP SDK),
        or an editor extension."""
        if ctx.agent_run_paths:
            return True
        for unit in units:
            member = unit.path.rpartition("!")[2]
            name = ContainerPaths.basename(member)
            if name == "SKILL.md" or SourcePaths.is_editor_extension(unit.path):
                return True
            if name in ("package.json", "pyproject.toml", "requirements.txt", "Cargo.toml") and (
                Ceilings._MCP_SDK_DECLARED.search(unit.content.text[:100_000])
            ):
                return True
        return False

    _SHELL_DOTFILES: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:\.|dot_)?(?:bashrc|bash_profile|bash_aliases|bash_logout|profile|zshrc|zshenv|"
        r"zprofile|zlogin|aliases|functions|exports|inputrc)$|\.(?:bashrc|zshrc|fish)$|^config\.fish$"
    )

    @staticmethod
    def _a_tool_a_person_runs(path: str, unit: FileUnit | None) -> bool:
        """Whether a repository file is a tool someone starts by name, rather than the project's
        source: a shell, PowerShell or batch script, an extensionless executable script (a
        shebang), a container build file, or a shell startup file a dotfiles repository keeps."""
        member = path.rpartition("!")[2]
        name = ContainerPaths.basename(member)
        lower = name.lower()
        if lower.endswith(STANDALONE_SCRIPTS) or Ceilings._SHELL_DOTFILES.search(lower):
            return True
        if lower.startswith(("dockerfile", "containerfile")) or lower.endswith(
            (".dockerfile", ".containerfile")
        ):
            return True
        return (
            "." not in name
            and unit is not None
            and not unit.content.is_binary
            and unit.content.raw[:2] == b"#!"
        )

    @staticmethod
    def person_run_ceiling(
        findings: list[Finding], units: list[FileUnit], ctx: ScanContext
    ) -> list[Finding]:
        """Suspicious findings in a repository file nothing runs on its own, reported below the
        gate (review 98, option A, 2026-10-17).

        A repository is scanned before someone builds or opens it. What runs then, unasked, is
        the attack surface: the install hooks and what they import, the build definitions, the
        editor tasks, dev container, git and agent hooks that fire on open, and the servers and
        skills an agent starts. A release script, a dotfile, a provisioning script or a tool under
        `bin/` runs when a person runs it by name, and the finding is still reported -- as a
        warning. A file one of the auto-run files names (`sh ./scripts/x.sh` in a Makefile) is
        auto-run too. A MALICIOUS finding is never lowered, wherever it is.
        """
        if Ceilings._agent_or_editor_tree(units, ctx):
            # An agent skill, an MCP server or an editor extension: the agent host or the editor
            # starts it, so none of it waits for a person to run it by name.
            return findings
        from cordon_scanner.foundation.taxonomy import Taxonomy, ThreatDomain

        auto = [u for u in units if Ceilings._runs_on_its_own(u.path, ctx)]
        named: dict[str, bool] = {}

        def named_by_auto_run(path: str) -> bool:
            name = ContainerPaths.basename(path.rpartition("!")[2])
            if len(name) < 4:
                return False
            if name not in named:
                named[name] = any(
                    u.path != path and not u.content.is_binary and name in u.content.text
                    for u in auto
                )
            return named[name]

        by_path = {u.path: u for u in units}
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            if (
                finding.category is Category.SUSPICIOUS
                and finding.severity > Severity.MEDIUM
                and path
                and path != REPOSITORY_SCOPE
                # A leaked key is leaked whoever runs the file it sits in.
                and not finding.rule_id.startswith("SECRET.")
                # Wiping a home directory harms whoever runs the script, a person included.
                and not finding.rule_id.startswith("SUSPECT.DESTROY.")
                # An agent reads its instruction and configuration files on open, unasked.
                and Taxonomy.domain_of(finding.rule_id) is not ThreatDomain.AGENT
                and Ceilings._a_tool_a_person_runs(path, by_path.get(path))
                and not Ceilings._runs_on_its_own(path, ctx)
                and not named_by_auto_run(path)
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " Nothing in this repository runs this file on its own -- it is not an "
                    "install or build step, not run when the project is opened, and not named by "
                    "one -- so it runs when a person runs it, and is reported below the gate.",
                )
            out.append(finding)
        return out

    #: Fetch-and-run findings a package-level verdict can raise.
    _RUNS_DOWNLOADS: ClassVar[frozenset[str]] = frozenset({"SUSPECT.DROPPER.001"})

    @staticmethod
    def impersonator_runs_downloads(findings: list[Finding]) -> list[Finding]:
        """A published package named one slip from a popular one that downloads and runs code.

        Each half is graded below the gate on its own: a typo-shaped name is common in the long
        tail (`SUSPECT.PACKAGE.NAME_RISK.001` records it), and a library function that fetches
        and starts a program is held at MEDIUM because it runs only when called. Together they
        are the typosquat dropper -- `fequests`, `rwquests` and `tequests` wrap every `requests`
        call in a download that is then run (review 98). The dropper finding is raised to HIGH;
        a dropper in a test, a document or generated output keeps its ceiling.
        """
        squat = any(
            f.rule_id == "SUSPECT.PACKAGE.NAME_RISK.001"
            and "one slip from the popular" in f.message
            for f in findings
        )
        if not squat:
            return findings
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            if (
                finding.rule_id in Ceilings._RUNS_DOWNLOADS
                and finding.severity < Severity.HIGH
                and not SourcePaths.is_test_material(path)
                and not SourcePaths.is_documentation(path)
                and not SourcePaths.is_generated_artefact(path)
            ):
                finding = replace(
                    finding,
                    severity=Severity.HIGH,
                    message=finding.message
                    + " The package is named one slip from a popular one, and a package that "
                    "imitates another's name while downloading and running code is a typosquat "
                    "dropper.",
                )
            out.append(finding)
        return out

    @staticmethod
    def author_time_ceiling(
        findings: list[Finding],
        units: list[FileUnit],
        distribution: str,
        runs: frozenset[str] = frozenset(),
    ) -> list[Finding]:
        """Findings in files a published package carries but nothing installing it runs.

        An sdist ships its maintainers' CI workflows, Makefile and Dockerfile, and a Python
        package with a JavaScript front end ships that front end's `package.json`; pip runs
        none of them. psutil's Makefile pipes a download into Python, jupyterlab's
        `package.json` declares npm lifecycle scripts, mcp's `.github/workflows/claude.yml`
        hands an issue to an agent -- each true of the repository, and none of it reaching a
        machine that runs `pip install`. Reported, below the gate. A MALICIOUS finding is never
        lowered.

        What counts depends on the format's installer. Compiled source is lowered only in
        Python and npm packages, whose install compiles an extension but does not run it: in a
        crate, a Go module or a jar that source IS the program the consumer runs. A Makefile
        stays a finding where installing runs make (`MAKE_AT_INSTALL`).

        A shell, PowerShell or batch script runs only when something starts it. No installer
        starts one on its own: a hook that does is in `runs` (the install-hook paths), and code
        or a manifest that does names it. A script that is neither -- a `curl | sh` release
        installer, a CI helper -- is the maintainers' (review 98: 103 of 293 benign units
        blocked by a dropper alone, against 0 of 44 malware samples). A conda link script runs at
        install and keeps its grade.
        """
        compiled_is_inert = RegistryFacts.compiled_is_inert(distribution)
        # Another ecosystem's install manifest is author-time here: npm's package.json in a wheel.
        foreign_manifests = RegistryFacts.foreign_install_manifests(distribution)
        make_is_inert = distribution not in MAKE_AT_INSTALL

        def author_time(member: str) -> bool:
            name = ContainerPaths.basename(member)
            lower = name.lower()
            other_ecosystem = name in foreign_manifests
            makefile = name in MAKEFILES or name.endswith(".mk")
            return (
                other_ecosystem
                or lower.endswith(SHIPPED_DOCUMENTS)
                or (compiled_is_inert and lower.endswith(COMPILED_SOURCE) and name != "build.rs")
                or member.startswith(AUTHOR_TIME_PREFIXES)
                or f"/{member}".find("/.github/") >= 0
                or (name in AUTHOR_TIME_FILENAMES and not makefile)
                or (makefile and make_is_inert)
                or Ceilings.is_container_file(name)
            )

        named: dict[str, bool] = {}

        def started_by_the_package(path: str, name: str) -> bool:
            """Whether code or a manifest the consumer's side runs names this script."""
            if name not in named:
                named[name] = any(
                    unit.path != path
                    and not unit.content.is_binary
                    and not SourcePaths.is_documentation(unit.path)
                    and not author_time(unit.path.rpartition("!")[2])
                    and name in unit.content.text
                    for unit in units
                )
            return named[name]

        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            member = path.rpartition("!")[2]
            name = ContainerPaths.basename(member)
            lowered = author_time(member) or (
                name.lower().endswith(STANDALONE_SCRIPTS)
                and not CONDA_LINK_SCRIPT.search(name)
                and path not in runs
                and not started_by_the_package(path, name)
            )
            if (
                lowered
                and finding.category is not Category.MALICIOUS
                and finding.severity > Severity.MEDIUM
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " This file ships in the published package but is not run by installing it,"
                    " so it is reported below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def is_container_file(name: str) -> bool:
        lower = name.lower()
        return lower.startswith(("dockerfile", "containerfile")) or lower.endswith(
            (".dockerfile", ".containerfile")
        )

    #: Form findings the recovered text repeats, because it keeps the obfuscator's variable names.
    RECOVERED_FORM: ClassVar[frozenset[str]] = frozenset(
        {"SUSPECT.OBFUSCATION.PACKED.001", "SUSPECT.OBFUSCATION.LONGLINE.001"}
    )

    #: Where an image's init systems, schedulers and shells keep what they start on their own.
    _IMAGE_STARTED: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:etc/services\.d/[^/]{1,200}/(?:run|finish)|etc/cont-(?:init|finish)\.d/[^/]{1,200}"
        r"|etc/s6-overlay/(?:s6-rc\.d/[^/]{1,200}/(?:run|up|finish)|scripts/[^/]{1,200})"
        r"|etc/supervisor(?:d\.conf|/[^\n]{1,300}\.conf)|etc/supervisord\.d/[^\n]{1,300}"
        r"|docker-entrypoint(?:-initdb)?\.d/[^/]{1,200}|etc/s(?:ervice|v)/[^/]{1,200}/run"
        r"|etc/crontabs/[^/]{1,200}|etc/cron\.(?:d|hourly|daily|weekly|monthly)/[^/]{1,200}"
        r"|var/spool/cron/[^\n]{1,300}|etc/periodic/[^\n]{1,300}|etc/profile|etc/profile\.d/[^/]{1,200}"
        r"|etc/bash\.bashrc|etc/rc\.local|etc/init\.d/[^/]{1,200}"
        r"|(?:usr/lib|etc)/systemd/system/[^\n]{1,300}"
        r"|(?:usr/local/)?bin/docker-entrypoint[^/]{0,100}|(?:docker-)?entrypoint[^/]{0,100})$"
    )

    _INTERPRETED: ClassVar[frozenset[str]] = frozenset(
        {"py", "js", "mjs", "cjs", "ts", "rb", "php", "pl", "sh", "bash", "lua", "r"}
    )

    _PATH_DIRS: ClassVar[tuple[str, ...]] = (
        "usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin",
    )  # fmt: skip

    @staticmethod
    def image_start_ceiling(findings: list[Finding], units: list[FileUnit]) -> list[Finding]:
        """Suspicious findings in an image's files that nothing in the image starts, reported
        below the gate (review 98: option A, for images).

        A container runs what its configuration starts -- the entrypoint and command, the
        healthcheck -- and what its init system, scheduler and login shell start on their own,
        and everything those name. The application the command runs lives under the working
        directory. The rest of the image -- a vendored library's Makefile, a package manager's
        cache, a script nobody calls -- runs when someone execs it. Malicious findings, secrets
        (readable by anyone who pulls the image) and agent findings keep their grade, and an
        image whose configuration cannot be read keeps every grade.
        """

        history = next(
            (u for u in units if Ceilings.image_member(u.path) == "image-config/history.txt"), None
        )
        if history is None:
            return findings
        start, workdir = Ceilings.image_start_commands(history)
        if not start:
            return findings
        members = {
            Ceilings.image_member(u.path): u
            for u in units
            if not Ceilings.image_member(u.path).startswith("image-config/")
        }
        by_name: dict[str, list[str]] = {}
        for path in members:
            by_name.setdefault(path.rpartition("/")[2], []).append(path)

        def resolve(token: str, base: str) -> set[str]:
            token = token.strip("'\"`;&|(){}")
            if not token or token.startswith("-") or "=" in token:
                return set()
            out: set[str] = set()
            if token.startswith("/"):
                if token[1:] in members:
                    out.add(token[1:])
            else:
                for root in (base, workdir):
                    candidate = posixpath.normpath(f"{root}/{token}") if root else token
                    if candidate in members:
                        out.add(candidate)
                if "/" not in token:
                    out.update(
                        f"{d}/{token}" for d in Ceilings._PATH_DIRS if f"{d}/{token}" in members
                    )
            return out

        auto: set[str] = {p for p in members if Ceilings._IMAGE_STARTED.match(p)}
        if workdir:
            # The application under the working directory, in the languages a runtime loads from
            # source. A Makefile runs at build time, and Go or Java sources never run: their
            # binary does, and is reached from the command.
            auto |= {
                p
                for p in members
                if p.startswith(workdir + "/")
                and p.rpartition(".")[2].lower() in Ceilings._INTERPRETED
                and "/vendor/" not in f"/{p}"
            }
        for command in start:
            for token in re.split(r"[\s;&|]+", command):
                auto |= resolve(token, workdir)
        # And what the started files name: a script they run or source, by path or by name.
        frontier = set(auto)
        for _ in range(6):
            found: set[str] = set()
            for path in frontier:
                unit = members.get(path)
                if unit is None or unit.content.is_binary or unit.content.size > 2_000_000:
                    continue
                text = unit.content.text
                base = path.rpartition("/")[0]
                for token in set(re.findall(r"[\w./${}-]{2,200}", text)):
                    token = token.replace("${", "").replace("}", "")
                    found |= resolve(token, base)
                    name = token.rpartition("/")[2]
                    if len(name) >= 6:
                        found.update(by_name.get(name, ()))
            frontier = found - auto
            if not frontier:
                break
            auto |= frontier
        out: list[Finding] = []
        Ceilings.unstarted_findings(findings, members, auto, out)
        return out

    @staticmethod
    def image_start_commands(history: FileUnit) -> tuple[list[str], str]:
        """The commands an image's history says start it, and the working directory they run in."""
        start: list[str] = []
        workdir = ""
        for line in history.content.text.splitlines():
            head, _, rest = line.partition(" ")
            if head in ("ENTRYPOINT", "CMD", "HEALTHCHECK"):
                start.append(rest)
            elif head == "WORKDIR":
                workdir = rest.strip().strip("/")
        return start, workdir

    @staticmethod
    def unstarted_findings(
        findings: list[Finding], members: dict[str, FileUnit], auto: set[str], out: list[Finding]
    ) -> None:
        """Findings in image files nothing starts, held to the ceiling."""
        from cordon_scanner.foundation.taxonomy import Taxonomy, ThreatDomain

        for finding in findings:
            path = Ceilings.image_member(finding.location.path or "")
            if (
                finding.category is Category.SUSPICIOUS
                and finding.severity > Severity.MEDIUM
                and path in members
                and path not in auto
                and not finding.rule_id.startswith(("SECRET.", "SUSPECT.DESTROY."))
                and Taxonomy.domain_of(finding.rule_id) is not ThreatDomain.AGENT
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " Nothing in this image starts this file -- not its entrypoint, command or "
                    "healthcheck, not its init system or scheduler, not under its working "
                    "directory, and not named by any of those -- so it runs only if someone runs "
                    "it, and is reported below the gate.",
                )
            out.append(finding)

    @staticmethod
    def image_member(path: str) -> str:
        return path.split("!", 1)[1] if "!" in path else path

    @staticmethod
    def graded_by_what_it_does(findings: list[Finding], ctx: ScanContext) -> list[Finding]:
        """Findings on recovered text (`<file>#deobfuscated.js`) that add nothing: the form rules
        the recovered text repeats because it keeps the obfuscator's names, and anything the
        original file already says under the same rule.

        The obfuscation finding itself keeps its grade. Measured on the review-98 malware set,
        lowering it when the recovered code carried nothing at the gate lost compromised
        releases whose only visible symptom was the obfuscation -- `@draftlab/auth` 0.24.2 and
        `@dirigible-ai/sdk` 0.6.3 recover to code that does nothing graded, their payload being
        elsewhere. Reversal adds what the recovered code does; it does not excuse the hiding.
        """
        del ctx
        on_original = {
            (f.location.path, f.rule_id)
            for f in findings
            if f.location.path and not f.location.path.endswith(Hooks.DEOBFUSCATED)
        }
        return [
            f
            for f in findings
            if not (
                (f.location.path or "").endswith(Hooks.DEOBFUSCATED)
                and (
                    f.rule_id in Ceilings.RECOVERED_FORM
                    or ((f.location.path or "")[: -len(Hooks.DEOBFUSCATED)], f.rule_id)
                    in on_original
                )
            )
        ]


__all__ = ["Ceilings"]
