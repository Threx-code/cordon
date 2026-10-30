"""Editor extensions a repository recommends or ships, judged as the editor would install them.

`.vscode/extensions.json` recommendations, a Gitpod config's `vscode.extensions`, and a packaged
extension's own manifest: each extension id (and version, when known) is looked up in OSV's
malicious-extension records, and one that presents itself as a popular extension under another
publisher is reported as an impersonation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.agents.extensions import ExtensionNames, ExtensionVerdicts
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.mcp_servers.declarations import McpConfigs
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.models import (
    Finding,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import ScanContext

_EXTENSION_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$")

_MALWARE_REASONS: Final = ("malware", "potentially malicious")

_SUSPECT_REASONS: Final = ("impersonation", "untrustworthy", "typosquat")


class ExtensionFileFindings:
    """The agent-chain findings in the files that name editor extensions."""

    @classmethod
    def extension_recommendations(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        document = McpConfigs._json(unit.content)
        if not isinstance(document, dict):
            return
        named: list[str] = []
        named += [x for x in document.get("recommendations") or () if isinstance(x, str)]
        raw_customizations = document.get("customizations")
        customizations: dict[str, Any] = (
            raw_customizations if isinstance(raw_customizations, dict) else {}
        )
        raw_vscode = customizations.get("vscode")
        vscode: dict[str, Any] = raw_vscode if isinstance(raw_vscode, dict) else {}
        named += [x for x in vscode.get("extensions") or () if isinstance(x, str)]
        legacy = document.get("extensions")
        if isinstance(legacy, dict):  # a *.code-workspace file
            named += [x for x in legacy.get("recommendations") or () if isinstance(x, str)]
        elif isinstance(legacy, list):  # a legacy devcontainer
            named += [x for x in legacy if isinstance(x, str)]
        for entry in dict.fromkeys(named):
            identifier, _, version = entry.partition("@")
            yield from cls.judge_extension(
                identifier, unit, ctx, recommended=True, version=version or None
            )

    @classmethod
    def gitpod_extensions(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """`vscode.extensions` in a Gitpod config: Open VSX ids, `id@version`, or .vsix URLs."""
        text = unit.content.text
        block = re.search(r"(?ms)^vscode:\s*\n((?:[ \t]+.*\n?)*)", text)
        if not block:
            return
        listing = re.search(r"(?ms)^[ \t]+extensions:\s*\n((?:[ \t]+-.*\n?)*)", block.group(1))
        if not listing:
            return
        for line in listing.group(1).splitlines():
            entry = line.strip().lstrip("-").strip().strip("'\"")
            if not entry or "://" in entry:
                continue
            identifier, _, version = entry.partition("@")
            yield from cls.judge_extension(
                identifier, unit, ctx, recommended=True, version=version or None
            )

    @classmethod
    def vsix_manifest(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        manifest = McpConfigs._json(unit.content)
        if isinstance(manifest, dict) and manifest.get("publisher") and manifest.get("name"):
            version = manifest.get("version")
            yield from cls.judge_extension(
                f"{manifest['publisher']}.{manifest['name']}",
                unit,
                ctx,
                recommended=False,
                version=str(version) if version else None,
                # The release's own identity is the engine's MALWARE.PACKAGE.KNOWN.001, as for an
                # npm or PyPI release; judging it here too would report one package twice.
                osv=False,
            )
            yield from cls._impersonation(manifest, unit, ctx)

    @classmethod
    def _impersonation(
        cls, manifest: dict[str, Any], unit: FileUnit, ctx: ScanContext
    ) -> Iterator[Finding]:
        """An extension presenting itself as a popular one under another identity (review 98: the
        misses an id comparison cannot see, because the impersonator changed its id as well).

        A publisher spelled with look-alike characters (`juanbIanco` for `juanblanco`); a display
        name that, invisible characters removed, is a popular extension's name under another
        publisher; an entry bundle named after a popular extension. And separately: a display
        name carrying invisible characters, which makes two names that read the same differ.
        """
        from cordon_scanner.intel.registry import IntelDataFile

        identifier = f"{manifest['publisher']}.{manifest['name']}".lower()
        display = str(manifest.get("displayName") or "")
        visible = ExtensionNames.INVISIBLE.sub("", display)
        if visible != display and visible.strip():
            yield AgentFinding.at_text(
                "SUSPECT.EXTENSION.HIDDEN_NAME.001",
                unit,
                ctx,
                unit.content.text,
                "displayName",
                message=f"This extension's display name, read as {visible.strip()!r}, carries "
                f"{len(display) - len(visible)} invisible character(s): it reads the same as a "
                "name it is not.",
            )
        intel = IntelDataFile.newest("vscode-extensions.json")
        popular = set(intel.get("popular") or ())
        if not popular or identifier in popular:
            return
        imitated = ExtensionNames.imitated(
            identifier,
            visible,
            [str(manifest.get(k) or "") for k in ("main", "browser")],
            popular,
        )
        if imitated:
            other, how = imitated
            yield AgentFinding.at_text(
                "SUSPECT.EXTENSION.LOOKALIKE.001",
                unit,
                ctx,
                unit.content.text,
                str(manifest["publisher"]),
                message=f"This extension, {identifier}, presents itself as the widely installed "
                f"{other}: {how}. An impersonating extension is installed by people who meant to "
                "install the one it imitates.",
            )

    @classmethod
    def judge_extension(
        cls,
        identifier: str,
        unit: FileUnit,
        ctx: ScanContext,
        *,
        recommended: bool,
        version: str | None = None,
        osv: bool = True,
    ) -> Iterator[Finding]:
        from cordon_scanner.intel.registry import IntelDataFile

        lowered = identifier.strip().lower()
        if not _EXTENSION_ID.match(lowered):
            return
        intel = IntelDataFile.newest("vscode-extensions.json")
        how = "recommends" if recommended else "vendors the package of"
        verdict = ExtensionVerdicts.osv(lowered, version) if osv else None
        if verdict is not None:
            rule_id, detail = verdict
            yield AgentFinding.at_text(
                rule_id,
                unit,
                ctx,
                unit.content.text,
                identifier,
                message=f"This file {how} the editor extension {identifier}"
                f"{'@' + version if version else ''}: {detail}",
            )
            return
        removal = (intel.get("removed") or {}).get(lowered)
        if isinstance(removal, dict):
            reason = str(removal.get("reason", "")).lower()
            when = removal.get("removed", "")
            if any(r in reason for r in _MALWARE_REASONS):
                rule_id = "MALWARE.EXTENSION.REMOVED.001"
            elif any(r in reason for r in _SUSPECT_REASONS):
                rule_id = "SUSPECT.EXTENSION.REMOVED.001"
            else:
                rule_id = ""
            if rule_id:
                yield AgentFinding.at_text(
                    rule_id,
                    unit,
                    ctx,
                    unit.content.text,
                    identifier,
                    message=f"This file {how} the editor extension {identifier}, which Microsoft removed from the "
                    f"Visual Studio Marketplace on {when} for: {removal.get('reason')}.",
                )
                return
        popular = set(intel.get("popular") or ())
        if not popular or lowered in popular:
            return
        lookalike = ExtensionNames._extension_lookalike(lowered, popular)
        if lookalike:
            yield AgentFinding.at_text(
                "SUSPECT.EXTENSION.LOOKALIKE.001",
                unit,
                ctx,
                unit.content.text,
                identifier,
                message=f"This file {how} the editor extension {identifier}, which differs from the widely installed "
                f"{lookalike} by one character or by publisher alone -- the shape an impersonating extension takes.",
            )


__all__ = ["ExtensionFileFindings"]
