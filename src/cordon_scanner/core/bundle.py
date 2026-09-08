"""Moving a release across an air gap.

An air-gapped site cannot `pip install`, and the usual answer -- somebody
downloads a wheel onto a laptop and carries it in -- is exactly the shape of the
attack this tool detects in other people's pipelines. The carried artefact is
unverified, the person carrying it cannot check it, and the failure is silent.

A bundle is that transfer made checkable. It is an ordinary tar.gz holding the
wheel, the rule packs, the advisory database and both SBOMs, plus a
`MANIFEST.sha256` covering every one of them. Verification is a refusal, never
a warning: a bundle with a missing file, an extra file, or a file whose digest
does not match is not installed. A warning here would mean the operator
installed it anyway and now has a note about it.

**What the manifest does and does not prove.** It proves internal consistency:
that the bundle you have is the bundle whose manifest you are reading. It does
not prove who made it, because an attacker who rewrites a file can rewrite the
manifest in the same pass. Authenticity comes from the detached Sigstore
signature produced at release, verified with the `sigstore` command before the
bundle is trusted -- and `verify` says so plainly when no signature is present
rather than reporting success and letting the distinction go unnoticed.

Verifying that signature needs the `sigstore` client, which is a third-party
package, and this tool has no third-party runtime dependencies. Rather than
acquire one, `verify` reports honestly what it did and did not check. A tool
that overstates what it verified is worse than one that verifies less.
"""

from __future__ import annotations

import hashlib
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.archive.safe import ArchiveReader
from cordon_scanner.core.errors import ArchiveError, ConfigError
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

MANIFEST_NAME = "MANIFEST.sha256"
SIGNATURE_DIR = "SIGNATURES"
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class BundleReport:
    """What verification found. Every field is reported, none is inferred."""

    ok: bool
    checked: int = 0
    mismatched: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    unlisted: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()
    problems: list[str] = field(default_factory=list)

    @property
    def signed(self) -> bool:
        return bool(self.signatures)

    def summary(self) -> str:
        if self.ok and self.signed:
            return f"{self.checked} file(s) verified; {len(self.signatures)} signature(s) present"
        if self.ok:
            return (
                f"{self.checked} file(s) match the manifest. No signature is present, so this "
                f"proves the bundle is internally consistent, not who produced it."
            )
        return "; ".join(self.problems) or "bundle failed verification"


class Bundle:
    """Create, verify and install an offline bundle."""

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def create(cls, output: Path, *, files: Sequence[tuple[str, Path]]) -> Path:
        """Write a bundle containing `files`, given as (name in bundle, path).

        The manifest is generated from what is actually written rather than from
        a list of what was meant to be written, so a file that failed to be
        included is absent from both and shows up as a smaller bundle rather
        than as a verification failure at the far end of the air gap.
        """
        if not files:
            raise ConfigError("a bundle with no files would verify successfully and be useless")

        entries: list[tuple[str, str]] = []
        output.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(output, "w:gz") as archive:
            for name, path in files:
                safe = ArchiveReader.safe_member_name(name)
                if safe is None:
                    raise ConfigError(f"unsafe name for a bundle member: {name!r}")
                if not path.is_file():
                    raise ConfigError(f"cannot bundle {path}: not a file")
                data = path.read_bytes()
                entries.append((cls.digest(data), safe))
                archive.add(path, arcname=safe)

            manifest = cls.render_manifest(entries)
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size = len(manifest)
            info.mode = 0o644
            archive.addfile(info, _BytesIO(manifest))

        return output

    @staticmethod
    def render_manifest(entries: Iterable[tuple[str, str]]) -> bytes:
        """`sha256sum` format, so it can be checked without this tool.

        Deliberate: an operator who distrusts the bundle should not have to run
        the program inside it to find out whether to trust it.
        """
        header = (
            f"# Cordon offline bundle, produced by cordon-scanner {__version__}.\n"
            f"# Check with: sha256sum -c {MANIFEST_NAME}\n"
            f"# This proves the bundle is internally consistent. It does not prove\n"
            f"# who produced it -- for that, verify the detached signature.\n"
        )
        body = "".join(
            f"{digest}  {name}\n" for digest, name in sorted(entries, key=lambda e: e[1])
        )
        return (header + body).encode("utf-8")

    @staticmethod
    def parse_manifest(text: str) -> dict[str, str]:
        listed: dict[str, str] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            digest, _, name = stripped.partition("  ")
            if len(digest) != 64 or not name:
                raise ArchiveError(f"malformed manifest line: {line!r}")
            listed[name] = digest
        return listed

    @classmethod
    def verify(cls, path: Path) -> BundleReport:
        """Check every member against the manifest. Fails closed."""
        problems: list[str] = []
        if not path.is_file():
            return BundleReport(ok=False, problems=[f"{path} is not a file"])
        if path.stat().st_size > MAX_BUNDLE_BYTES:
            return BundleReport(ok=False, problems=[f"{path} exceeds {MAX_BUNDLE_BYTES} bytes"])

        contents: dict[str, bytes] = {}
        try:
            with tarfile.open(path, "r:gz") as archive:
                for member in archive:
                    if not member.isfile():
                        # Directories, links and devices are not part of the
                        # format. A symlink in a bundle is a way to write
                        # outside the install directory at extraction time.
                        if member.islnk() or member.issym():
                            problems.append(f"bundle contains a link: {member.name}")
                        continue
                    safe = ArchiveReader.safe_member_name(member.name)
                    if safe is None:
                        problems.append(f"unsafe member name: {member.name!r}")
                        continue
                    if member.size > MAX_MEMBER_BYTES:
                        problems.append(f"member too large: {safe}")
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        problems.append(f"member could not be read: {safe}")
                        continue
                    contents[safe] = handle.read(MAX_MEMBER_BYTES + 1)
        except (tarfile.TarError, OSError) as exc:
            return BundleReport(ok=False, problems=[f"{path} is not a readable bundle: {exc}"])

        if MANIFEST_NAME not in contents:
            problems.append(f"no {MANIFEST_NAME}; nothing in this bundle can be checked")
            return BundleReport(ok=False, problems=problems)

        try:
            listed = cls.parse_manifest(contents[MANIFEST_NAME].decode("utf-8", "replace"))
        except ArchiveError as exc:
            return BundleReport(ok=False, problems=[str(exc)])

        signatures = tuple(sorted(n for n in contents if n.startswith(f"{SIGNATURE_DIR}/")))
        present = {n for n in contents if n != MANIFEST_NAME and n not in signatures}

        mismatched = tuple(
            sorted(n for n in present & set(listed) if cls.digest(contents[n]) != listed[n])
        )
        missing = tuple(sorted(set(listed) - present))
        # Reported, and fatal. An unlisted file is one nobody checked, and
        # `bundle install` would write it to disk alongside the checked ones.
        unlisted = tuple(sorted(present - set(listed)))

        problems.extend(f"digest mismatch: {name}" for name in mismatched)
        problems.extend(f"listed but absent: {name}" for name in missing)
        problems.extend(f"present but unlisted: {name}" for name in unlisted)

        return BundleReport(
            ok=not problems,
            checked=len(present & set(listed)),
            mismatched=mismatched,
            missing=missing,
            unlisted=unlisted,
            signatures=signatures,
            problems=problems,
        )

    @classmethod
    def install(cls, path: Path, into: Path) -> BundleReport:
        """Verify, then extract. Never the other way round.

        Extracting first and checking afterwards would put an unverified file on
        disk, which is the whole thing the bundle exists to avoid -- and on a
        machine where somebody is about to run what was extracted.
        """
        report = cls.verify(path)
        if not report.ok:
            return report

        into.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                safe = ArchiveReader.safe_member_name(member.name)
                if safe is None:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                target = into / safe
                # Re-checked here rather than trusted from `safe_member_name`,
                # because this is the step that writes to disk and it is worth
                # two lines to make the guarantee local to it.
                resolved = target.resolve()
                if not resolved.is_relative_to(into.resolve()):
                    raise ArchiveError(f"member would extract outside the target: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(handle.read(MAX_MEMBER_BYTES + 1))

        return report


class _BytesIO:
    """Minimal file object for `tarfile.addfile`."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._data[self._at :] if size < 0 else self._data[self._at : self._at + size]
        self._at += len(chunk)
        return chunk


__all__ = ["MANIFEST_NAME", "Bundle", "BundleReport"]
