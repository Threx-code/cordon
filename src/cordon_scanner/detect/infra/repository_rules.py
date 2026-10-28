"""The repository rules: version-control configuration (submodules, hooks, attributes) and the
build systems -- Make, CMake, MSBuild, Gradle and Maven -- that fetch and run code as they build.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.foundation import references
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    pass
from cordon_scanner.detect.infra.config_paths import (
    DOCKER_PATHS,
    IAC_PATHS,
    K8S_MARKER,
    VERIFIED_FETCH,
)
from cordon_scanner.detect.infra.config_rule import ConfigRule

MAKE_PATHS = (
    "**/Makefile",
    "**/makefile",
    "**/GNUmakefile",
    "**/*.mk",
)

CMAKE_PATHS = (
    "**/CMakeLists.txt",
    "**/*.cmake",
)

MSBUILD_PATHS = (
    "**/*.csproj",
    "**/*.vcxproj",
    "**/*.targets",
    "**/*.props",
)

GRADLE_MAVEN_PATHS = (
    "**/build.gradle",
    "**/build.gradle.kts",
    "**/pom.xml",
)

VERSION_CONTROL_RULES: tuple[ConfigRule, ...] = (
    # -- Version control --------------------------------------------------
    ConfigRule(
        rule_id="SUSPECT.SUBMODULE.UNTRUSTED.001",
        references=(references.CLEARTEXT_TRANSMISSION, references.INSUFFICIENT_VERIFICATION),
        title="Submodule fetched over an unauthenticated transport",
        message=(
            "A submodule is fetched over plain HTTP or the git:// protocol, neither of "
            "which authenticates the server or protects what it sends. Submodule content "
            "is checked out into the working tree and built with the project, so anyone "
            "on the network path controls the build."
        ),
        remediation=(
            "Use HTTPS or SSH, and let the submodule stay pinned to the commit "
            "recorded in the parent repository."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # Not `branch = ...`. The parent repository pins every submodule to a commit, and
        # `git submodule update` checks out that commit whatever branch `.gitmodules` names;
        # the branch is followed only by `git submodule update --remote`, a step some
        # pipeline chooses, not something this file does. Read as "what arrives can change",
        # it was 18 of 25 sampled benign warnings of this rule in the long tail (review 98).
        pattern=ConfigRule._p(r"url[ \t]{0,32}=[ \t]{0,32}(?:http|git)://"),
        paths=("**/.gitmodules",),
    ),
    ConfigRule(
        rule_id="SUSPECT.VCS.HOOKS_PATH.001",
        references=(references.UNTRUSTED_SEARCH_PATH, references.CODE_INJECTION),
        title="Repository configures its own git hooks directory",
        message=(
            "This repository points git at a hooks directory it ships. Those hooks "
            "run on commit, checkout and merge on the machine of anyone who "
            "configures the repository -- before any code is reviewed, and without "
            "the developer running anything themselves."
        ),
        remediation=(
            "Read every script in the configured directory before enabling it. "
            "Managed hooks are a legitimate practice and are also a way to run code "
            "on a contributor's machine."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(r"hooksPath[ \t]{0,32}="),
        paths=("**/.gitconfig", "**/.git/config", "**/gitconfig"),
    ),
    ConfigRule(
        rule_id="SUSPECT.IAC.HOST_MOUNT.001",
        references=(references.KUBERNETES_POD_SECURITY, references.IMPROPER_ACCESS_CONTROL),
        title="Host path mounted into a container",
        message=(
            "A host directory is mounted into the container. Mounting the container "
            "runtime's own socket is equivalent to granting root on the node, because "
            "anything that can talk to it can start a privileged container."
        ),
        remediation=(
            "Remove the mount. If the workload genuinely needs runtime access, use a "
            "brokered API with an explicit, auditable permission set."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            # The trailing group is optional so that `path: /` matches. It did
            # not: mounting the entire host root, which is strictly worse than
            # mounting /etc, was the one host path this rule ignored.
            r"/var/run/docker\.sock"
            r"|/var/run/containerd|/run/containerd/containerd\.sock"
            r"|hostPath:\s*\n\s*path:\s*[\"']?"
            r"/(?:etc|root|proc|sys|dev|boot|usr|home|var/run|var/lib/kubelet)?"
            r"[\"']?\s*(?:$|#)"
        ),
        paths=IAC_PATHS + DOCKER_PATHS,
        content_marker=K8S_MARKER,
    ),
)


BUILD_RULES: tuple[ConfigRule, ...] = (
    # -- Build systems (Domain 4) -----------------------------------------
    ConfigRule(
        rule_id="SUSPECT.BUILD.MAKE_FETCH_EXEC.001",
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, references.CODE_INJECTION),
        title="Makefile recipe fetches and executes remote content",
        message=(
            "A Makefile recipe downloads something and runs it. `make` is the "
            "first command run in most build pipelines, often before any "
            "dependency lock or sandbox is in effect, and what executes is "
            "whatever the remote host serves at that moment."
        ),
        remediation=(
            "Vendor the script, or pin it by digest and verify the digest before running it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # Same mitigation and the same reasoning as SUSPECT.CI.FETCH_EXEC.001:
        # a pinned or checksum-verified fetch is a step down, not silence.
        mitigation=VERIFIED_FETCH,
        pattern=ConfigRule._p(
            # Not inside make's own messages: `$(warning "... run: curl -sfL <url> | sh")` tells a
            # person what to run, and make runs nothing of it (review 98 G6: cobra's Makefile,
            # vendored).
            r"(?m)^(?![^\n]{0,400}?\$[({](?:warning|info|error)\b)[^\n]{0,400}?"
            r"(?:(?:curl|wget)[^\n|]{0,200}\|[ \t]{0,32}(?:sudo[ \t]{1,8})?(?:ba)?sh"
            r"|(?:curl|wget)[^\n]{0,200}?(?:-o|--output|-O)\s{1,4}[^\s]{1,200}"
            r"[\s\S]{0,240}?chmod\s{1,4}(?:\+x|[0-7]?(?:[1357][0-7][0-7]|[0-7][1357][0-7]|[0-7][0-7][1357])))"
        ),
        paths=MAKE_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="POLICY.BUILD.UNPINNED_DEPENDENCY.001",
        references=(
            references.OPENSSF_SCORECARD_PINNED,
            references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
        ),
        title="Build dependency resolves to whatever is newest, not a fixed version",
        message=(
            "This dependency coordinate uses a floating version: Gradle's `+` "
            "wildcard or `latest.release`, or Maven's deprecated `LATEST`/`RELEASE`. The build "
            "resolves to whatever the registry currently serves under that "
            "name, so the same coordinate can produce different, unreviewed "
            "code on every build -- and is exactly the substitution a "
            "dependency-confusion attack needs."
        ),
        remediation=(
            "Pin an exact version. If a range is genuinely needed, use a "
            "bounded one your build tool locks against a resolved version file."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(
            # Gradle: `'group:artifact:1.+'` or `'group:artifact:+'`, single or
            # double quoted. The version segment ends in a bare `+`. Or one of
            # Gradle's `latest.<status>` selectors, which float the same way.
            r"""['"][A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+:[0-9A-Za-z.\-]*\+['"]"""
            r"""|['"][A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+:latest\.(?:release|integration|milestone)['"]"""
            # Maven: the deprecated meta-versions, still seen in older POMs.
            r"|<version>\s*(?:LATEST|RELEASE)\s*</version>"
        ),
        paths=GRADLE_MAVEN_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001",
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
        title="CMake fetches a URL with nothing verifying what it downloaded",
        message=(
            "This `ExternalProject_Add` or `FetchContent_Declare` call fetches "
            "a URL with no `URL_HASH` anywhere nearby, so nothing confirms the "
            "bytes it links into the build are the ones the author reviewed. "
            "The host, or anything between it and the build, can substitute "
            "different content and the build would not notice."
        ),
        remediation=(
            "Add `URL_HASH SHA256=<digest>` (or the equivalent for your CMake "
            "version), or switch to `GIT_REPOSITORY`/`GIT_TAG` pinned to a "
            "commit."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            # Inside the call the message names, with `URL` as that call's own keyword, and no
            # hash anywhere in the call. Each bounded repeat consumes one character, so this is
            # linear in the window, not the backtracking shape the pattern-safety sweep
            # (tests/unit/rules/test_pattern_safety.py) exists to catch.
            #
            # It used to be any `URL https://` up to the next `)`: `HOMEPAGE_URL` in a
            # `project()`, `set(JSON_TEST_DATA_URL ...)`, a documentation link in a Find
            # module, and `GITLAB_URL` in vcpkg's `vcpkg_from_gitlab`, which verifies a SHA512.
            # It warned on 249 of the long tail's benign units, 160 of them for nothing else (review
            # 98).
            r"(?:ExternalProject_Add|FetchContent_Declare)[ \t]{0,8}\("
            r"(?:(?!URL_HASH)(?!URL_MD5)[^)]){0,500}?(?<![\w$])URL[ \t\r\n]{1,16}[\"']?https?://"
            r"(?:(?!URL_HASH)(?!URL_MD5)[^)]){0,500}\)"
        ),
        paths=CMAKE_PATHS,
        capabilities=(Capability.EGRESS,),
    ),
    ConfigRule(
        rule_id="SUSPECT.BUILD.MSBUILD_FETCH_EXEC.001",
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, references.CODE_INJECTION),
        title="MSBuild target fetches and executes remote content",
        message=(
            "An `<Exec>` target downloads something and pipes or hands it "
            "straight to an interpreter. This runs during `dotnet build` or "
            "`msbuild`, often on a developer machine or a CI runner with "
            "publish credentials, and what runs is decided by whoever answers "
            "the download at build time."
        ),
        remediation=(
            "Vendor the script, or pin it by digest and verify the digest before running it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        mitigation=VERIFIED_FETCH,
        pattern=ConfigRule._p(
            r"(?:curl|wget|Invoke-WebRequest|iwr)[^\n\"]{0,200}\|[ \t]{0,32}"
            r"(?:iex|Invoke-Expression|sh|bash|cmd(?:\.exe)?)"
        ),
        paths=MSBUILD_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
)


__all__ = [
    "BUILD_RULES",
    "CMAKE_PATHS",
    "GRADLE_MAVEN_PATHS",
    "MAKE_PATHS",
    "MSBUILD_PATHS",
    "VERSION_CONTROL_RULES",
]
