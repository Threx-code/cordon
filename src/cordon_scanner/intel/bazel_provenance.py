"""Bazel Central Registry modules' build attestations, verified the way BCR's presubmit does.

A module version published through `bazel-contrib/publish-to-bcr` carries an
`attestations.json` beside its `source.json` and `MODULE.bazel` in the registry, naming a sigstore
bundle (an in-toto SLSA provenance statement, released as a `.intoto.jsonl` asset) for each:

    GET https://bcr.bazel.build/modules/<name>/<version>/attestations.json
    GET https://bcr.bazel.build/modules/<name>/<version>/source.json     the archive and its hash
    GET https://bcr.bazel.build/modules/<name>/metadata.json             the module's repository
    GET <the bundle's URL, a release asset of that repository>

What the lockfile pinned decides what is verified. MODULE.bazel.lock (Bazel 7.2+) pins the
SHA-256 of the registry's `source.json`; its attestation must name exactly that file, and the
archive's attestation must name the archive digest that file records -- so the archive Bazel
downloads is tied, through a pinned file, to a build of the declared repository. An earlier lock,
or an archive integrity recorded anywhere else, pins the archive itself, and the archive's
attestation must name it.

Each bundle is checked against the hash `attestations.json` records for it (the bundle BCR's
presubmit verified, not one swapped into the release afterwards), must be a release asset of a
repository the module's `metadata.json` names, and is verified by `attest.SigstoreVerification`:
signed through GitHub Actions' OIDC issuer by a workflow of that repository, over a statement whose
subject is the pinned digest.

Bounded and honest about what it cannot answer: a module with no `attestations.json` has nothing
to verify (most of BCR, today); a registry other than BCR is not asked; a lock whose pinned
`source.json` is no longer the one the registry serves cannot be tied to anything. Network use is
the scan's `--online` only, over HTTPS, to bcr.bazel.build and GitHub's release hosts.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Final

from cordon_scanner.intel import attest

REGISTRY: Final = "https://bcr.bazel.build"
MEDIA_TYPE: Final = "application/vnd.build.bazel.registry.attestation+json"
TIMEOUT: Final = 15.0
MAX_BYTES: Final = 4 << 20
#: Where a release asset is served from once github.com redirects its download.
ASSET_HOSTS: Final = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)


class _GitHubRedirects(urllib.request.HTTPRedirectHandler):
    """A release download redirects to GitHub's asset storage: followed there, and only there."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or (target.hostname or "") not in ASSET_HOSTS:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class ModuleCheck:
    outcome: str
    """`verified`, `invalid`, `unverifiable`, `unpinned` or `absent`."""
    detail: str


class BazelProvenance:
    @staticmethod
    def _get(url: str) -> bytes:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("not https")
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - https only, hosts checked
        opener = urllib.request.build_opener(_GitHubRedirects)
        with opener.open(request, timeout=TIMEOUT) as response:
            body: bytes = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("response too large")
        return body

    @staticmethod
    def _module_file(*parts: str) -> bytes | None:
        """`modules/<parts...>` from the registry, or None where it serves no such file."""
        quoted = "/".join(urllib.parse.quote(part, safe="+-._") for part in parts)
        try:
            return BazelProvenance._get(f"{REGISTRY}/modules/{quoted}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    @staticmethod
    def repositories(metadata: bytes | None) -> dict[str, tuple[str, str]]:
        """The GitHub repositories `metadata.json` names, `owner/name` lowercased to the pair."""
        try:
            document = json.loads(metadata or b"{}")
        except ValueError:
            return {}
        found: dict[str, tuple[str, str]] = {}
        for entry in document.get("repository") or () if isinstance(document, dict) else ():
            if isinstance(entry, str) and entry.startswith("github:"):
                owner, _, repo = entry[len("github:") :].partition("/")
                if owner and repo:
                    found[f"{owner}/{repo}".lower()] = (owner, repo)
        return found

    @staticmethod
    def _bundle(
        entry: Any, repositories: dict[str, tuple[str, str]], file: str
    ) -> tuple[list[str], tuple[str, str, str]] | ModuleCheck:
        """The bundle lines of one attested file and the repository they must be signed by."""
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            return ModuleCheck("unverifiable", f"attestations.json names no bundle for {file}")
        url = entry["url"]
        parts = urllib.parse.urlsplit(url)
        segments = parts.path.strip("/").split("/")
        if parts.scheme != "https" or parts.hostname != "github.com" or len(segments) < 2:
            return ModuleCheck(
                "invalid", f"the bundle for {file} is not a GitHub release asset: {url}"
            )
        owner, repo = segments[0], segments[1]
        if f"{owner}/{repo}".lower() not in repositories:
            return ModuleCheck(
                "invalid",
                f"the bundle for {file} is served by {owner}/{repo}, a repository the module's "
                "metadata.json does not name",
            )
        pinned = attest.AttestationDocuments.parse_integrity(entry.get("integrity"))
        if pinned is None or pinned[0] != "sha256":
            return ModuleCheck(
                "unverifiable", f"attestations.json records no sha256 for the bundle of {file}"
            )
        try:
            body = BazelProvenance._get(url)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable", f"the bundle for {file} could not be read ({type(exc).__name__})"
            )
        if hashlib.sha256(body).hexdigest() != pinned[1]:
            return ModuleCheck(
                "invalid",
                f"the bundle released for {file} is not the one BCR recorded: its hash differs",
            )
        lines = [line for line in body.decode("utf-8", "replace").splitlines() if line.strip()]
        return lines, ("github.com", owner, repo)

    @staticmethod
    def _verify(
        entry: Any, repositories: dict[str, tuple[str, str]], file: str, digest: str
    ) -> ModuleCheck:
        bundle = BazelProvenance._bundle(entry, repositories, file)
        if isinstance(bundle, ModuleCheck):
            return bundle
        lines, source = bundle
        if not lines:
            return ModuleCheck("unverifiable", f"the bundle for {file} is empty")
        verdicts = [
            attest.SigstoreVerification.verify(
                line, digest_hex=digest, algorithm="sha256", source_repo=source
            )
            for line in lines
        ]
        if any(v.outcome is attest.Outcome.VERIFIED for v in verdicts):
            return ModuleCheck("verified", f"{file}: built by github.com/{source[1]}/{source[2]}")
        invalid = next((v for v in verdicts if v.outcome is attest.Outcome.INVALID), None)
        if invalid is not None:
            return ModuleCheck("invalid", f"{file}'s attestation: {invalid.detail}")
        return ModuleCheck("unverifiable", f"{file}'s attestation: {verdicts[0].detail}")

    @staticmethod
    def check(name: str, version: str, integrity: str | None) -> ModuleCheck:
        """The module's attestations, against the digest the project pinned for it."""
        label = f"{name}@{version}"
        try:
            listed = BazelProvenance._module_file(name, version, "attestations.json")
            if listed is None:
                return ModuleCheck("absent", f"BCR publishes no attestation for {label}")
            source = BazelProvenance._module_file(name, version, "source.json")
            metadata = BazelProvenance._module_file(name, "metadata.json")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable", f"the registry could not be read ({type(exc).__name__})"
            )
        try:
            document = json.loads(listed)
            record = json.loads(source or b"{}")
        except ValueError:
            return ModuleCheck("unverifiable", f"the registry's files for {label} did not parse")
        if (
            not isinstance(document, dict)
            or not str(document.get("mediaType", "")).startswith(MEDIA_TYPE)
            or not isinstance(document.get("attestations"), dict)
            or not isinstance(record, dict)
        ):
            return ModuleCheck(
                "unverifiable", f"attestations.json for {label} is not a format this reads"
            )
        attestations: dict[str, Any] = document["attestations"]
        repositories = BazelProvenance.repositories(metadata)
        if not repositories:
            return ModuleCheck(
                "unverifiable",
                f"{name}'s metadata.json names no GitHub repository to verify against",
            )
        archive = attest.AttestationDocuments.parse_integrity(record.get("integrity"))
        archive_url: str = record["url"] if isinstance(record.get("url"), str) else ""
        archive_name = urllib.parse.urlsplit(archive_url).path.rsplit("/", 1)[-1]
        if archive is None or archive[0] != "sha256" or not archive_name:
            return ModuleCheck(
                "unverifiable", f"source.json for {label} records no sha256 archive to verify"
            )
        pinned = attest.AttestationDocuments.parse_integrity(integrity)
        if pinned is None or pinned[0] != "sha256":
            return ModuleCheck("unpinned", f"no sha256 is pinned for {label}")
        steps: list[tuple[str, str]]
        if pinned[1] == hashlib.sha256(source or b"").hexdigest():
            # The lock pinned source.json: that file's attestation, then the archive it names.
            steps = [("source.json", pinned[1]), (archive_name, archive[1])]
        elif pinned[1] == archive[1]:
            steps = [(archive_name, archive[1])]
        else:
            return ModuleCheck(
                "unverifiable",
                f"the source.json BCR serves for {label} is not the one pinned here, so its "
                "attestations are not about what this project builds",
            )
        done: list[str] = []
        for file, digest in steps:
            result = BazelProvenance._verify(attestations.get(file), repositories, file, digest)
            if result.outcome != "verified":
                return result
            done.append(result.detail)
        return ModuleCheck("verified", "; ".join(done))


__all__ = ["BazelProvenance", "ModuleCheck"]
