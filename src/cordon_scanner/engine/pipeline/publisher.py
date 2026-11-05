"""What a package's publisher left in it by mistake or by design: signing material and certificates,
the test identities that ship with a package, and secrets that came from the publisher's machine
rather than the project.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.engine.pipeline.constants import (
    CERTIFICATE_BLOCK,
    DER_STRING,
    DROP_POINT_SECRETS,
    TEST_IDENTITY,
)
from cordon_scanner.foundation.models import (
    Category,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class Publisher:
    """Checks on what a package's publisher left in it."""

    @staticmethod
    def publisher_hygiene(findings: list[Finding], advisory: frozenset[Any]) -> list[Finding]:
        """How a published package's own repository was kept, as against what it installs.

        A `.github/workflows/*.yml`, a `Dockerfile` or a release setting that ended up inside a
        tarball describes its publisher's repository and runs for nobody who installs it. These
        domains never fail a build (`Policy.advisory_domains`), and in a package scan they were
        most of what a clean package still warned about: unpinned actions, lockfile integrity,
        an unpinned base image (review 98, FP-8). Reported at INFO -- in JSON and SARIF for anyone
        auditing the publisher, out of the default report. A MALICIOUS finding is untouched.
        """
        from cordon_scanner.foundation.taxonomy import Taxonomy

        out: list[Finding] = []
        for finding in findings:
            if (
                finding.category is not Category.MALICIOUS
                and finding.severity > Severity.INFO
                and (
                    Taxonomy.domain_of(finding.rule_id) in advisory
                    or finding.rule_id.startswith(("POLICY.RELEASE.", "POLICY.LOCKFILE."))
                )
            ):
                finding = replace(finding, severity=Severity.INFO)
            out.append(finding)
        return out

    @staticmethod
    def _certificate_names(raw: bytes) -> bytes:
        """The printable names in the certificates a file holds: subject and issuer fields."""
        names: list[bytes] = []
        for block in CERTIFICATE_BLOCK.findall(raw[:200_000])[:8]:
            try:
                der = base64.b64decode(b"".join(block.split()), validate=False)
            except (ValueError, binascii.Error):
                continue
            names.extend(m.group(2)[: m.group(1)[0]] for m in DER_STRING.finditer(der))
        return b" ".join(names)

    @staticmethod
    def test_identity_keys(findings: list[Finding], units: Sequence[FileUnit]) -> list[Finding]:
        """A private key whose certificate says it is for testing is a test key (review 98, FP-6).

        OpenSSL's `apps/` ships `client.pem` and `server2.pem` issued by "OpenSSL Test
        Intermediate CA ... FOR TESTING PURPOSES ONLY", and `ca-key.pem` beside "Server test
        cert"; every Bazel module that vendors OpenSSL carried 6 such blocks. Judged from the
        certificate in the key's own file or its directory, never from a path: a real key in
        `certs/` beside a real certificate keeps its grade. Reported at LOW, not withdrawn."""
        keys = [
            f
            for f in findings
            if f.rule_id == "SECRET.PRIVATE_KEY.001" and f.severity >= Severity.HIGH
        ]
        if not keys:
            return findings
        directories = {f.location.path.rpartition("/")[0] for f in keys}
        testing: dict[str, bool] = {}
        for unit in units:
            directory = unit.path.rpartition("/")[0]
            if directory not in directories or testing.get(directory):
                continue
            raw = unit.content.raw
            if b"BEGIN CERTIFICATE" in raw[:200_000]:
                names = Publisher._certificate_names(raw)
                testing[directory] = bool(names and TEST_IDENTITY.search(names))
        out: list[Finding] = []
        for finding in findings:
            if finding in keys and testing.get(finding.location.path.rpartition("/")[0]):
                finding = replace(
                    finding,
                    severity=Severity.LOW,
                    message=finding.message
                    + " The certificate beside it names a test identity, so this is read as a "
                    "test key: confirm it is not used anywhere real.",
                )
            out.append(finding)
        return out

    @staticmethod
    def publisher_secrets(findings: list[Finding]) -> list[Finding]:
        """A credential committed inside a published package, graded for whoever installs it.

        The key is its publisher's: they leaked it and they are the ones who can rotate it.
        Nothing about it acts on the machine that installs the package, so for that consumer it
        is reported, in full, at MEDIUM, and does not stop the build. In 40 such blocks read
        from 441 real npm and PyPI packages (review 98) every one was the publisher's own token
        -- a `.coveralls.yml` repo token, a `.env`, a demo's API key. A repository's own
        secrets are untouched: this runs only for a recognised published package. Code that
        USES a credential (harvesting, exfiltration) is a different rule and keeps its grade, and
        so does a token that is a place to post to (`DROP_POINT_SECRETS`).
        """
        out: list[Finding] = []
        for finding in findings:
            if (
                finding.rule_id.startswith("SECRET.")
                and finding.rule_id not in DROP_POINT_SECRETS
                and finding.category is not Category.MALICIOUS
                and finding.severity > Severity.MEDIUM
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " It ships inside a published package, so the exposure is its publisher's"
                    " to rotate; it does not act on whoever installs the package, and is reported"
                    " below the gate.",
                )
            out.append(finding)
        return out


__all__ = ["Publisher"]
