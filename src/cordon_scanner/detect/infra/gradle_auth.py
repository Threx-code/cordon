"""A Gradle build's own credentials, as against credentials a build script harvests (review 98, FP-14).

An Android or JVM build reads its signing passwords, publishing tokens and API keys from the
environment and hands them to the build: `storePassword = System.getenv("STORE_PASSWORD")`,
`token.set(System.getenv("PUBLISH_TOKEN"))`, `buildConfigField("String", "KEY", "\\"$key\\"")`. The
same file downloads `protoc` or reads a public update feed. Read together, a credential and an
egress in one build script made `MALWARE.EXFIL.001` -- "reads credentials and transmits them" -- for
35 of 1,535 real Gradle repositories, none of which sent a credential anywhere.

A credential read is the build's own when it is read from the environment or a property AND every
place its value goes is one of the build's authentication sinks. Anything else -- the value in a
URL, a request, `exec`/`commandLine`, a file the build writes -- and it remains a credential read.
A credential FILE (`~/.ssh`, `~/.aws`) is never excused.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final

GRADLE_SUFFIXES: Final = (".gradle", ".gradle.kts")

ENV_READ: Final = re.compile(
    r"System\.getenv\s*\(|\bfindProperty\s*\(|\bgetProperty\s*\(|\bproviders\s*\.\s*"
    r"(?:environmentVariable|gradleProperty)\s*\(|\bproject\s*\.\s*property\s*\(|"
    r"\bproperties\s*\[|\bSystem\.getProperty\s*\("
)
"""Where a build reads a value it was given: the environment, a Gradle or system property."""

SINK: Final = re.compile(
    r"\b(?:storePassword|keyPassword|keyAlias|storeFile|password|username|token|apiKey|"
    r"signingKey|signingPassword|signingKeyId|secretKey|accessKey|key|keyId|user|pass)\s*"
    r"(?:=|\.set\s*\(|\()"
    r"|\bcredentials\s*[({]|\bbuildConfigField\s*\(|\bresValue\s*\(|\buseInMemoryPgpKeys\s*\("
    r"|\bmanifestPlaceholders\b|\bsigningConfigs?\b|\bsigning\s*\{|\bauthentication\s*\{"
    r"|\bsetProperty\s*\(|\bextra\s*\[|\bext\s*\.\s*\w+\s*=",
    re.IGNORECASE,
)
"""Where a build hands a credential to itself: signing, a repository's credentials, plugin
publishing, generated build config."""

LEAVES: Final = re.compile(
    r"https?://|\bURL\s*\(|\bURI\s*\(|\buri\s*\(|openConnection|\bHttp\w*|\bOkHttp|\bWebClient"
    r"|\bexec\s*[({]|\bcommandLine\s*\(|ProcessBuilder|Runtime\.getRuntime|\bcurl\b|\bwget\b"
    r"|\bwriteText\s*\(|\bappendText\s*\(|\bwriteBytes\s*\(|\.write\s*\(|\bprintln\s*\(|"
    r"\blogger\.\w+\s*\(",
    re.IGNORECASE,
)
"""Where a value leaves the build's own configuration."""

DECLARED: Final = re.compile(
    r"^\s*(?:(?:private|internal|public)\s+)?(?:val|var|def|final)\s+(?:\w+\s+)?"
    r"(?P<name>[A-Za-z_]\w*)\s*(?::\s*[\w?<>.]+\s*)?=(?!=)"
)
"""A local name taking a value. Never a sink itself: where the NAME goes decides."""


class GradleBuildAuth:
    @staticmethod
    def is_build_script(path: str) -> bool:
        return path.lower().endswith(GRADLE_SUFFIXES)

    @staticmethod
    def drop_build_auth(text: str, hits: Sequence[Any], credential: Any) -> list[Any]:
        """`hits` without the credential reads whose every use is the build authenticating."""
        lines = text.splitlines()
        return [
            hit
            for hit in hits
            if not (hit.capability is credential and GradleBuildAuth._own(lines, hit.line))
        ]

    @staticmethod
    def _own(lines: list[str], number: int) -> bool:
        if not 0 < number <= len(lines):
            return False
        line = lines[number - 1]
        if not ENV_READ.search(line) or LEAVES.search(line):
            return False
        declared = DECLARED.match(line)
        if declared is None:
            # Read straight into a sink: `storePassword = System.getenv(..)`, `token.set(..)`.
            return bool(SINK.search(line))
        return GradleBuildAuth._flows_to_sinks(lines, number, declared.group("name"), 0)

    @staticmethod
    def _flows_to_sinks(lines: list[str], number: int, name: str, depth: int) -> bool:
        """Whether every later use of `name` is a sink, or passes it to a name that is."""
        if depth > 3:
            return False
        use = re.compile(rf"(?<![\w.]){re.escape(name)}(?!\w)")
        uses = [i for i, text in enumerate(lines, 1) if i != number and use.search(text)]
        if not uses:
            return False
        for i in uses:
            text = lines[i - 1]
            if LEAVES.search(text):
                return False
            passed = DECLARED.match(text)
            if passed is not None and passed.group("name") != name:
                if not GradleBuildAuth._flows_to_sinks(lines, i, passed.group("name"), depth + 1):
                    return False
                continue
            if not SINK.search(text):
                return False
        return True
