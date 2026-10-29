"""What a scanned package's release says about it before any of its code is read: its identity (name,
version, registry), a placeholder or throwaway release, a release known to be malicious, native
code in a wheel that declares itself pure, install code nothing examined, an MCP server that borrows
a well-known service's name, and how a release differs from the one before it.
"""

from __future__ import annotations

import io
import re
from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.detect.registry import ServerSources
from cordon_scanner.engine.pipeline.constants import (
    KNOWN_MALICIOUS_RELEASE_RULE,
    MACHO_MAGIC,
    NATIVE_IN_PURE_WHEEL_RULE,
    NATIVE_LOAD,
    NATIVE_MAGIC,
    NPM_PLACEHOLDER_VERSION,
    PURE_WHEEL,
    SWEPT_NOTE,
    UNEXAMINED_INSTALL_RULE,
)
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Sequence


class ReleaseChecks:
    """Checks on a package release as a whole."""

    @staticmethod
    def unexamined_install_code(findings: Sequence[Finding], ctx: ScanContext) -> list[Finding]:
        """Install-time code the scan could not read to the end.

        A truncation or a timeout is a coverage note anywhere else. In a file that runs at
        install it is the evasion: aioconsol's `setup.py` is 22 MB on one line -- an executable
        written out as a bytes literal -- past the size limit and the per-file budget, so the
        payload and the call that runs it were never read. Install scripts are kilobytes.
        """
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        out: list[Finding] = []
        seen: set[str] = set()
        for finding in findings:
            path = finding.location.path
            if (
                finding.rule_id not in ("OPERATIONAL.FILE.TRUNCATED", "OPERATIONAL.FILE.TIMEOUT")
                or path in seen
                or path not in ctx.install_hook_paths
            ):
                continue
            if (
                SourcePaths.is_editor_extension(path) or path in ctx.agent_run_paths
            ) and finding.message.startswith(SWEPT_NOTE):
                # An extension ships its code as one bundle, and ten or twenty megabytes is what a
                # language extension's bundle weighs; this one was read whole by the high-signal
                # sweep. An install script is kilobytes, so for one the size is still the finding.
                continue
            seen.add(path)
            out.append(
                replace(
                    OperationalFinding.build(
                        path=path,
                        rule_id=UNEXAMINED_INSTALL_RULE,
                        message=(
                            "This file runs at install time and is larger, or slower to read, "
                            "than the scan's limits allow, so part of it was never examined. "
                            "Install scripts are kilobytes; one padded past the limits keeps its "
                            "payload out of reach of every check."
                        ),
                        remediation=(
                            "Do not install this package until the file has been read in full. "
                            "Raise limits.max_file_bytes and limits.per_file_timeout to examine it."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.HIGH,
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                    detector="manifest",
                )
            )
        return out

    #: Names an agent host's users expect to find: the reference servers and the services the
    #: most-installed MCP servers front. A server published under one is chosen by that name.
    EXPECTED_SERVER_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "github",
            "gitlab",
            "slack",
            "notion",
            "gmail",
            "google-drive",
            "gdrive",
            "filesystem",
            "postgres",
            "sqlite",
            "brave-search",
            "puppeteer",
            "playwright",
            "fetch",
            "memory",
            "git",
            "sentry",
            "linear",
            "jira",
            "confluence",
            "figma",
            "stripe",
            "discord",
            "telegram",
            "whatsapp",
            "outlook",
            "teams",
            "dropbox",
            "kubernetes",
            "docker",
            "openai",
            "anthropic",
            "everything",
            "sequential-thinking",
            "google-maps",
            "youtube",
            "twitter",
            "reddit",
            "spotify",
            "shopify",
            "salesforce",
            "hubspot",
            "zapier",
            "airtable",
            "mongodb",
            "mysql",
            "redis",
            "supabase",
            "firebase",
            "vercel",
            "cloudflare",
        }
    )

    @staticmethod
    def borrowed_server_name(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """An MCP server published under a well-known service's name that its code never names.

        A chess server whose `pyproject.toml` says `name = "github"`, a Messages bridge called
        `slack`: an agent host offering "github" installs whatever answers to the name, and the
        requests meant for GitHub -- with the tokens they carry -- arrive here (review 98:
        mcp-variants' Tool Squatting servers; none of its 786 reference servers). A real GitHub
        server mentions GitHub in its code.
        """
        sources = ServerSources.of(units)
        if not sources:
            return []
        code = [
            u.content.text
            for u in units
            if u.path.endswith((".py", ".ts", ".js", ".mjs", ".cjs"))
            and "/node_modules/" not in u.path
        ]
        out: list[Finding] = []
        for unit in units:
            name_of = unit.path.rpartition("!")[2].rpartition("/")[2]
            if name_of not in ("pyproject.toml", "package.json") or "/node_modules/" in unit.path:
                continue
            found = re.search(
                r'(?m)^name\s*=\s*["\']([^"\']+)|"name"\s*:\s*"([^"]+)"', unit.content.text
            )
            if found is None:
                continue
            bare = (found.group(1) or found.group(2)).lower().rpartition("/")[2]
            for prefix in ("mcp-server-", "server-", "mcp-"):
                bare = bare.removeprefix(prefix)
            for suffix in ("-mcp-server", "-mcp", "-server"):
                bare = bare.removesuffix(suffix)
            if bare not in ReleaseChecks.EXPECTED_SERVER_NAMES:
                continue
            brand = re.compile("(?i)" + re.escape(bare).replace("\\-", "[-_ ]?"))
            if any(brand.search(text) for text in code):
                continue
            out.append(
                replace(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="SUSPECT.MCP.BORROWED_NAME.001",
                        message=(
                            f"This MCP server is published as {bare!r}, the name of a service its "
                            "code never mentions. An agent host offering that service installs "
                            "whatever answers to the name, and the requests meant for it -- with "
                            "the credentials they carry -- arrive here."
                        ),
                        remediation=(
                            "Install the service's own server. Check what this one does with "
                            "requests meant for the service it is named after."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.MEDIUM,
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.MEDIUM),
                    detector="manifest",
                    always_report=False,
                )
            )
        return out

    @staticmethod
    def release_identities(
        units: Sequence[FileUnit],
    ) -> tuple[list[tuple[str, str, str, str]], set[str]]:
        """(ecosystem, name, version, manifest path) for each release manifest the archive holds,
        recognised only where its format puts it (see `_known_malicious_release`); and the npm
        security-holding placeholders among them."""
        identities: list[tuple[str, str, str, str]] = []
        placeholders: set[str] = set()
        for unit in units:
            member = unit.path.rpartition("!")[2]
            parts = member.split("/")
            own = ReleaseChecks.archive_release_identity(unit)
            if own is not None:
                identities.append((*own, unit.path))
                continue
            # A root-level `.nuspec` is the one release manifest kept at the package's top; it
            # counts only inside an archive (a repository's own .nuspec is not a release).
            if len(parts) < 2 and not ("!" in unit.path and member.endswith(".nuspec")):
                continue
            parent, name = (parts[-2] if len(parts) >= 2 else ""), parts[-1]
            try:
                if name == "package.json" and parent == "package":
                    document = ScannedJson.loads(unit.content.text)
                    if (
                        isinstance(document, dict)
                        and document.get("name")
                        and document.get("version")
                    ):
                        identities.append(
                            ("npm", str(document["name"]), str(document["version"]), unit.path)
                        )
                        if NPM_PLACEHOLDER_VERSION.fullmatch(str(document["version"])) and (
                            str(document.get("description", "")).strip().lower()
                            == "security holding package"
                        ):
                            placeholders.add(unit.path)
                elif name == "package.json" and parent == "extension":
                    # A VS Code / Open VSX extension package (.vsix): the Marketplace names it
                    # `publisher.name`, and that is the key OSV's VSCode records use.
                    document = ScannedJson.loads(unit.content.text)
                    if (
                        isinstance(document, dict)
                        and document.get("publisher")
                        and document.get("name")
                        and document.get("version")
                    ):
                        identities.append(
                            (
                                "vscode",
                                f"{document['publisher']}.{document['name']}",
                                str(document["version"]),
                                unit.path,
                            )
                        )
                elif name == "Cargo.toml" and re.search(r"-\d", parent):
                    # A published crate (.crate): `<name>-<version>/Cargo.toml`, normalised by
                    # cargo at publish time, so `[package]` holds the release's own name.
                    text = unit.content.text[:20000]
                    package = re.search(r"(?ms)^\[package\](.*?)(?:^\[|\Z)", text)
                    if package:
                        found_name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', package.group(1))
                        found_version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', package.group(1))
                        if found_name and found_version:
                            identities.append(
                                ("cargo", found_name.group(1), found_version.group(1), unit.path)
                            )
                elif name.endswith(".nuspec") and len(parts) == 1:
                    # A NuGet package (.nupkg): its `<id>.nuspec` sits at the package root.
                    text = unit.content.text[:20000]
                    found_name = re.search(r"<id>\s*([^<\s]+)\s*</id>", text)
                    found_version = re.search(r"<version>\s*([^<\s]+)\s*</version>", text)
                    if found_name and found_version:
                        identities.append(
                            ("nuget", found_name.group(1), found_version.group(1), unit.path)
                        )
                elif (name == "PKG-INFO" and re.search(r"-\d", parent)) or (
                    name == "METADATA" and parent.endswith(".dist-info")
                ):
                    text = unit.content.text[:20000]
                    found_name = re.search(r"(?m)^Name:\s*(\S+)", text)
                    found_version = re.search(r"(?m)^Version:\s*(\S+)", text)
                    if found_name and found_version:
                        identities.append(
                            ("pypi", found_name.group(1), found_version.group(1), unit.path)
                        )
            except (ValueError, TypeError, RecursionError):
                continue
        return identities, placeholders

    _CRATE_MANIFEST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|!)(?P<name>[A-Za-z0-9_-]{1,64})-(?P<version>\d[\w.+-]{0,40})/Cargo\.toml$"
    )

    _GO_MODULE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|!)(?P<module>[^!@]{1,300})@(?P<version>v[^/!]{1,80})/go\.mod$"
    )

    @staticmethod
    def archive_release_identity(unit: FileUnit) -> tuple[str, str, str] | None:
        """(ecosystem, name, version) when the unit is the release manifest of a published gem,
        crate or Go module zip -- recognised only where each format puts it inside its archive.

        npm, PyPI, NuGet and VS Code releases were matched against the malicious-package records
        by their own manifests; these three were not, so a `.gem` OSV records as malicious was
        judged by its code alone (review 98: 485 of 587 recovered malicious gems carry no code).
        """
        archive, bang, member = unit.path.rpartition("!")
        if not bang:
            return None
        if member == "metadata.gz" and archive.lower().endswith(".gem"):
            import gzip
            import zlib

            try:
                with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                    text = stream.read(50_000).decode("utf-8", "replace")
            except (OSError, EOFError, zlib.error):
                return None
            name = re.search(r"(?m)^name:[ \t]{0,8}(\S{1,120})", text)
            version = re.search(r"(?m)^[ \t]{1,8}version:[ \t]{0,8}['\"]?([\w.+-]{1,60})", text)
            if name and version:
                return "rubygems", name.group(1), version.group(1)
            return None
        crate = ReleaseChecks._CRATE_MANIFEST.search(unit.path)
        if crate is not None and archive.lower().endswith(".crate"):
            return "cargo", crate.group("name"), crate.group("version")
        module = ReleaseChecks._GO_MODULE.search(unit.path)
        if module is not None and archive.lower().endswith(".zip"):
            return "gomod", module.group("module").rpartition("!")[2], module.group("version")
        return None

    _THROWAWAY_SUMMARY: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\S{1,3}|test|tmp|temp|foo|bar|x gem|a gem|gem"
    )

    _GEM_CODE: ClassVar[tuple[str, ...]] = (".rb", ".sh", ".py", ".js", ".c", ".so", ".bundle")

    @staticmethod
    def placeholder_release(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """A published gem with no code whose summary is a throwaway word.

        RubyGems' malicious records are mostly releases that ship nothing -- an empty `lib/a.rb`,
        a file `x` -- under the summary `x`, `a` or `x gem`: 478 of 485 code-free malicious gems
        recovered from a mirror, and none of 6,999 benign gems (194 of which are also code-free,
        as shims and renamed packages are, but say what they are). Measured, review 98.
        """
        import gzip
        import zlib

        out: list[Finding] = []
        for unit in units:
            gem, _, member = unit.path.rpartition("!")
            if member != "metadata.gz" or not gem.lower().endswith(".gem"):
                continue
            code = sum(
                u.content.size
                for u in units
                if u.path.startswith(f"{gem}!data.tar.gz!")
                and u.path.lower().endswith(ReleaseChecks._GEM_CODE)
            )
            if code >= 40:
                continue
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                    text = stream.read(50_000).decode("utf-8", "replace")
            except (OSError, EOFError, zlib.error):
                continue
            summary = re.search(r"(?m)^summary:[ \t]{0,8}(.{0,120})$", text)
            said = summary.group(1).strip().strip("'\"") if summary else ""
            if not said or not ReleaseChecks._THROWAWAY_SUMMARY.fullmatch(said):
                continue
            out.append(
                replace(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001",
                        message=(
                            f"This gem carries no code and its summary is `{said}`: a name taken "
                            "to be used, not a library. Most releases RubyGems records as "
                            "malicious have exactly this shape."
                        ),
                        remediation=(
                            "Do not depend on it; find out who published it and what depends on "
                            "the name."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.HIGH,
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                    detector="advisory",
                )
            )
        return out

    @staticmethod
    def known_malicious_release(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """The scanned package is itself a recorded malicious release.

        Dependencies have always been checked against the malicious-package records; the
        package being vetted was not. A tarball whose own `package.json` names a release OSV
        records as malicious is answered by that record, whatever its code does or no longer
        contains -- the commonest shape in the public datasets is a dependency-confusion
        placeholder whose payload was pulled, which no reading of the code can convict.

        Only a package's own manifest counts, recognised by where its format puts it: an npm
        tarball's `package/package.json`, an sdist's `<name>-<version>/PKG-INFO`, a wheel's
        `*.dist-info/METADATA`. A repository's root `package.json` is not a release, so a project
        that shares a name with a malicious package is never matched by name alone.
        """
        from cordon_scanner.intel.registry import AdvisoryDatabase

        identities, placeholders = ReleaseChecks.release_identities(units)
        if not identities:
            return []
        database = AdvisoryDatabase.bundled()
        out: list[Finding] = []
        for ecosystem, name, version, path in identities[:20]:
            records = [a for a in database.matching(ecosystem, name, version) if a.malicious]
            if not records:
                continue
            record = records[0]
            if path in placeholders:
                # npm's own stand-in for a release it removed: `0.0.1-security`, "security holding
                # package", nothing that runs. The name is the finding, not the tarball: 16 of
                # 300 random npm packages in the corpus were these, blocked as malware.
                out.append(
                    replace(
                        OperationalFinding.build(
                            path=path,
                            rule_id=KNOWN_MALICIOUS_RELEASE_RULE,
                            message=(
                                f"{name} {version} is npm's security placeholder for a package "
                                f"removed as malicious ({record.identifier}). It contains no code; "
                                "what it says is that something depended on a name that carried "
                                "malware."
                            ),
                            remediation=(
                                "Remove the dependency, and find out where it came from: a "
                                "lockfile or manifest that names it once resolved the malicious "
                                "release."
                            ),
                            category=Category.SUSPICIOUS,
                            severity=Severity.MEDIUM,
                        ),
                        confidence=Confidence.CONFIRMED,
                        risk=ctx.scorer.score(Severity.MEDIUM, Confidence.CONFIRMED),
                        detector="advisory",
                        references=(record.reference,) if record.reference else (),
                    )
                )
                continue
            out.append(
                replace(
                    OperationalFinding.build(
                        path=path,
                        rule_id=KNOWN_MALICIOUS_RELEASE_RULE,
                        message=(
                            f"{name} {version} is itself a recorded malicious release "
                            f"({record.identifier}). {record.summary} This is an exact match "
                            "against a published incident, not a judgement of the code."
                        ),
                        remediation=(
                            "Do not install it. If it was installed anywhere, treat that machine "
                            "as compromised and rotate the credentials reachable from it."
                        ),
                        category=Category.MALICIOUS,
                        severity=Severity.CRITICAL,
                    ),
                    confidence=Confidence.CONFIRMED,
                    risk=ctx.scorer.score(Severity.CRITICAL, Confidence.CONFIRMED),
                    detector="advisory",
                    references=(record.reference,) if record.reference else (),
                )
            )
        return out

    @staticmethod
    def native_code_in_a_pure_wheel(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """A pure-Python wheel that loads a native library it carries into the interpreter.

        A wheel tagged `py3-none-any` declares that it holds no compiled code; that is what lets
        one file serve every platform. colorinal, a colorama clone, shipped as one with
        `terminate.so` beside its modules and `ctypes.CDLL(os.path.dirname(__file__) +
        "/terminate.so")` at module level: importing the colour library ran a native payload.
        A package with real native code ships platform wheels. Running a bundled binary as a
        program (selenium's driver manager) is not this; loading it into the process is.
        """
        wheel = next(
            (u for u in units if u.path.rsplit("/", 1)[-1] == "WHEEL" and ".dist-info/" in u.path),
            None,
        )
        if wheel is None or not PURE_WHEEL.search(wheel.content.text):
            return []
        natives = {
            u.path.rsplit("/", 1)[-1]
            for u in units
            if u.content.raw[:4] in NATIVE_MAGIC or u.content.raw[:4] in MACHO_MAGIC
        }
        if not natives:
            return []
        out: list[Finding] = []
        for unit in units:
            if not unit.path.endswith(".py"):
                continue
            for number, line in enumerate(unit.content.text.splitlines(), 1):
                if NATIVE_LOAD.search(line) and any(name in line for name in natives):
                    out.append(
                        replace(
                            OperationalFinding.build(
                                path=unit.path,
                                rule_id=NATIVE_IN_PURE_WHEEL_RULE,
                                message=(
                                    "This wheel declares itself pure Python (`none-any`), yet "
                                    "this line loads a native library shipped inside it into the "
                                    "interpreter. Compiled code no reviewer can read runs in-process "
                                    "on import, in a package that said it had none."
                                ),
                                remediation=(
                                    "Do not install it. A package with genuine native code ships "
                                    "platform wheels built from published source."
                                ),
                                category=Category.SUSPICIOUS,
                                severity=Severity.HIGH,
                            ),
                            location=replace(
                                OperationalFinding.build(
                                    path=unit.path,
                                    rule_id=NATIVE_IN_PURE_WHEEL_RULE,
                                    message="",
                                    remediation="",
                                    category=Category.SUSPICIOUS,
                                    severity=Severity.HIGH,
                                ).location,
                                line=number,
                            ),
                            confidence=Confidence.HIGH,
                            risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                            detector="binary",
                        )
                    )
                    break
        return out


__all__ = ["ReleaseChecks"]
