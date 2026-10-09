"""Homebrew bottles' build attestations, verified the way `brew` verifies them.

Homebrew/homebrew-core builds every bottle in GitHub Actions and publishes a sigstore build
attestation for it (`publish-commit-bottles.yml`), which GitHub serves by the bottle's digest. A
Brewfile or an install receipt names a formula, not a bottle, so the digests come from the
formula's own record in Homebrew's API, which lists one bottle per platform:

    GET https://formulae.brew.sh/api/formula/<name>.json         the bottles and their sha256
    GET https://api.github.com/repos/Homebrew/homebrew-core/
          attestations/sha256:<digest>                            the bundle for one bottle

Each bundle is verified by `attest.SigstoreVerification` with the same policy as an npm or PyPI
attestation: signed through GitHub Actions' OIDC issuer, by a workflow in
`Homebrew/homebrew-core`, over an in-toto statement whose subject is that bottle's digest. A
genuine attestation for some other bottle does not pass.

Bounded and honest about what it cannot answer: the API serves only a formula's current version,
so a receipt pinning an older one is reported unverifiable rather than checked against the wrong
bottles; a cask has no bottle; a formula from a third-party tap is not in the API. Network use is
the scan's `--online` only, to these two hosts, over HTTPS, following no redirect.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Final

from cordon_scanner.intel import attest

FORMULA_API: Final = "https://formulae.brew.sh/api/formula/{name}.json"
ATTESTATIONS_API: Final = (
    "https://api.github.com/repos/Homebrew/homebrew-core/attestations/sha256:{digest}"
)
SOURCE_REPO: Final = ("github.com", "Homebrew", "homebrew-core")
TIMEOUT: Final = 15.0
MAX_BYTES: Final = 8 << 20
MAX_BOTTLES: Final = 8
"""Platforms checked per formula: each bottle is its own artefact and its own attestation."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


@dataclass(frozen=True)
class BottleCheck:
    outcome: str
    """`verified`, `invalid`, `unverifiable` or `absent`."""
    detail: str
    version: str = ""


class HomebrewProvenance:
    @staticmethod
    def _get(url: str) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "cordon-scanner"}
        token = os.environ.get("GITHUB_TOKEN", "")
        if token and url.startswith("https://api.github.com/"):
            # GitHub's own token, to GitHub's own API: the unauthenticated limit is 60 an hour.
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url, headers=headers)  # noqa: S310 - fixed https hosts
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=TIMEOUT) as response:
            return json.loads(response.read(MAX_BYTES))

    @staticmethod
    def bottles(name: str) -> tuple[str, dict[str, str]] | None:
        """`(current version, {platform: sha256})` from the formula's record, or None."""
        quoted = urllib.parse.quote(name, safe="@+-._")
        try:
            record = HomebrewProvenance._get(FORMULA_API.format(name=quoted))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        stable = ((record.get("bottle") or {}).get("stable") or {}).get("files") or {}
        version = str((record.get("versions") or {}).get("stable") or "")
        return version, {
            platform: str(info["sha256"])
            for platform, info in sorted(stable.items())
            if isinstance(info, dict) and isinstance(info.get("sha256"), str)
        }

    @staticmethod
    def bundles(digest: str) -> list[str]:
        try:
            body = HomebrewProvenance._get(ATTESTATIONS_API.format(digest=digest))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            raise
        return [
            json.dumps(item["bundle"])
            for item in body.get("attestations") or ()
            if isinstance(item, dict) and isinstance(item.get("bundle"), dict)
        ]

    @staticmethod
    def check(name: str, version: str | None) -> BottleCheck:
        """Every bottle of the formula's current version, each against its own attestation."""
        if "/" in name:
            return BottleCheck("absent", f"{name} is from a third-party tap, not homebrew-core")
        try:
            found = HomebrewProvenance.bottles(name)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return BottleCheck(
                "unverifiable", f"Homebrew's API could not be read ({type(exc).__name__})"
            )
        if found is None:
            return BottleCheck(
                "absent", f"{name} is not a homebrew-core formula (a cask has no bottle)"
            )
        current, bottles = found
        if version and current and version.split("_")[0] != current.split("_")[0]:
            return BottleCheck(
                "unverifiable",
                f"Homebrew's API serves {current}'s bottles, not {version}'s",
                current,
            )
        if not bottles:
            return BottleCheck(
                "absent", f"{name} {current} is built from source: no bottle", current
            )
        results: list[tuple[str, attest.Result]] = []
        for platform, digest in list(bottles.items())[:MAX_BOTTLES]:
            try:
                bundles = HomebrewProvenance.bundles(digest)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                return BottleCheck(
                    "unverifiable",
                    f"GitHub's attestation API could not be read ({type(exc).__name__})",
                    current,
                )
            if not bundles:
                return BottleCheck(
                    "unverifiable",
                    f"no build attestation is published for the {platform} bottle",
                    current,
                )
            verdicts = [
                attest.SigstoreVerification.verify(
                    bundle, digest_hex=digest, algorithm="sha256", source_repo=SOURCE_REPO
                )
                for bundle in bundles
            ]
            best = next(
                (v for v in verdicts if v.outcome is attest.Outcome.VERIFIED),
                next((v for v in verdicts if v.outcome is attest.Outcome.INVALID), verdicts[0]),
            )
            results.append((platform, best))
        invalid = [(p, r) for p, r in results if r.outcome is attest.Outcome.INVALID]
        if invalid:
            platform, result = invalid[0]
            return BottleCheck(
                "invalid", f"the {platform} bottle's attestation: {result.detail}", current
            )
        unverified = [(p, r) for p, r in results if r.outcome is not attest.Outcome.VERIFIED]
        if unverified:
            platform, result = unverified[0]
            return BottleCheck("unverifiable", f"the {platform} bottle: {result.detail}", current)
        return BottleCheck(
            "verified",
            f"{len(results)} bottle(s) of {name} {current}, each attested by Homebrew/homebrew-core",
            current,
        )


__all__ = ["BottleCheck", "HomebrewProvenance"]
