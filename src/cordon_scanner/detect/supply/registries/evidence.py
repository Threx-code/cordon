"""What a registry's answers are evidence of: the repository a package names, and the digests it records.

A repository URL reduced to its forge, owner and name however it is spelled, and a hash string read
as an algorithm and lowercase hex whichever encoding the registry used -- so that two answers about
the same thing compare equal.
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse

FORGE_SHORTHANDS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
    "gist": "gist.github.com",
}
"""npm accepts `github:owner/repo` and friends in the `repository` field, and
plenty of packages use them. Expanded here so a shorthand and the HTTPS URL it
abbreviates compare as the same repository, which is what they are."""


class RegistryEvidence:
    """Repository identities and digests as registries report them."""

    @staticmethod
    def repository_identity(url: str | None) -> tuple[str, str, str] | None:
        """A repository URL reduced to the forge, owner and name it points at.

        The same repository is written half a dozen ways: `git@github.com:o/r.git`,
        `git+https://github.com/o/r.git`, `github:o/r`, a bare `o/r`, and a link
        into a subdirectory of a monorepo. All of those are one repository, and a
        comparison that treated them as different would report a mismatch on
        essentially every package that uses anything but the plain HTTPS form.

        So: the transport prefix goes, credentials go, the query and fragment go,
        the `.git` suffix goes, and only the first two path segments are kept --
        everything after `owner/repo` is a path *inside* the repository, not part of
        its identity.

        Returns `None` when the string does not resolve to all three parts.
        Comparing an unresolvable claim against anything would be guessing, and the
        caller is expected to stay quiet rather than guess.
        """
        if not url:
            return None

        text = url.strip()
        if not text:
            return None

        # `git+https://...`, `git+ssh://...`: the transport is a packaging detail.
        if text.startswith("git+"):
            text = text[4:]

        # An npm shorthand, or a bare `owner/repo` which npm reads as GitHub.
        scheme, separator, remainder = text.partition(":")
        if separator and scheme.lower() in FORGE_SHORTHANDS and not remainder.startswith("//"):
            text = f"https://{FORGE_SHORTHANDS[scheme.lower()]}/{remainder.lstrip('/')}"
        elif "://" not in text and "@" not in text:
            segments = [part for part in text.split("/") if part]
            if len(segments) == 2 and "." not in segments[0]:
                text = f"https://github.com/{segments[0]}/{segments[1]}"

        # `git@host:owner/repo`, the SCP-style form URL parsers do not accept.
        if "://" not in text and "@" in text:
            _, _, tail = text.partition("@")
            host, separator, path = tail.partition(":")
            if separator:
                text = f"https://{host}/{path.lstrip('/')}"

        parsed = urllib.parse.urlsplit(text if "://" in text else f"https://{text}")
        host = parsed.hostname or ""
        if not host:
            return None
        if host.startswith("www."):
            host = host[4:]

        segments = [part for part in parsed.path.split("/") if part]
        if len(segments) < 2:
            return None

        owner, name = segments[0], segments[1]
        if name.endswith(".git"):
            name = name[:-4]
        if not owner or not name:
            return None

        return (host.lower(), owner.lower(), name.lower())

    @staticmethod
    def _canonical_digest(value: str | None) -> tuple[str, str] | None:
        """A hash string as `(algorithm, lowercase hex)`, or `None` if it is not one.

        Registries and lockfiles write the same digest three ways: Subresource
        Integrity (`sha512-<base64>`, npm), a prefixed hex (`sha256:<hex>`, pip),
        and a bare hex whose length names the algorithm (PyPI\'s `digests.sha256`,
        npm\'s `dist.shasum`).

        Everything else returns `None`, and that is the point of the function.
        Yarn Berry\'s `checksum:` (`10c0/<hex>`) and Go\'s `h1:<base64>` occupy the
        same field as a registry digest and are not one, so a caller that compared
        them against what a registry publishes would find a contradiction in every
        correct lockfile.
        """
        if not value:
            return None
        text = value.strip()
        if not text:
            return None
        if text.startswith("h1:"):
            # Go's module hash, which sum.golang.org publishes and go.sum records: comparable
            # with itself and with nothing else, so it is its own algorithm here.
            return RegistryEvidence._h1(text[3:])
        if text.lower().startswith("zh:"):
            # Terraform's: the SHA-256 of a provider's zip for one platform, as the registry's
            # SHA256SUMS lists it.
            return RegistryEvidence._as_hex(text[3:].strip(), 64, "sha256")
        if text.lower().startswith("git-tree-sha1:"):
            # Julia's: the SHA-1 of a git tree, which the General registry lists per version and a
            # manifest records. Not the SHA-1 of any file, so its own algorithm too.
            return RegistryEvidence._as_hex(
                text[len("git-tree-sha1:") :].strip(), 40, "git-tree-sha1"
            )

        prefix, separator, rest = text.partition("-")
        if not separator:
            prefix, separator, rest = text.partition(":")
        if separator:
            algorithm = prefix.strip().lower()
            expected = _DIGEST_HEX_LENGTHS.get(algorithm)
            if expected is None:
                return None
            return RegistryEvidence._as_hex(rest.strip(), expected, algorithm)

        for algorithm, expected in _DIGEST_HEX_LENGTHS.items():
            if len(text) == expected:
                return RegistryEvidence._as_hex(text, expected, algorithm)
        # A bare base64 digest, as NuGet's packages.lock.json writes `contentHash`: its decoded
        # length names the algorithm, and only a sha256 or sha512 length is accepted.
        for algorithm in ("sha512", "sha256"):
            parsed = RegistryEvidence._as_hex(text, _DIGEST_HEX_LENGTHS[algorithm], algorithm)
            if parsed is not None and len(text) in (44, 88):
                return parsed
        return None

    @staticmethod
    def _h1(body: str) -> tuple[str, str] | None:
        try:
            raw = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            return None
        return ("h1", raw.hex()) if len(raw) == 32 else None

    @staticmethod
    def _as_hex(body: str, expected_hex_length: int, algorithm: str) -> tuple[str, str] | None:
        """`body` as `(algorithm, hex)` when it decodes to a digest of that length."""
        lowered = body.lower()
        if len(lowered) == expected_hex_length:
            try:
                bytes.fromhex(lowered)
            except ValueError:
                return None
            return (algorithm, lowered)

        try:
            raw = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(raw) * 2 != expected_hex_length:
            return None
        return (algorithm, raw.hex())


#: Digest length in hex characters, by algorithm name. A value is a digest of
#: one of these only when its length says so, which is what separates a hash
#: from a string that merely sits in a hash-shaped field.
_DIGEST_HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}


__all__ = ["FORGE_SHORTHANDS", "RegistryEvidence"]
