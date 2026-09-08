"""Fetching an organisation policy that lives somewhere else.

An organisation with more than a handful of repositories cannot copy its policy
file into each of them: the copies drift, and a drifted ceiling is worse than no
ceiling because everyone believes it is in force. So the policy has to be
distributable, and `--policy` accepts a URL.

That is a security decision, not a convenience, because of what an organisation
policy *is*. It is the ceiling: the thing that says a repository may not disable
a detector, may not suppress a category, may not raise a limit. Anything able to
change it can switch the control off everywhere at once. Fetching it over a
network without further thought would mean whoever controls the network, the
host, the CDN or a stale DNS entry controls every scan in the organisation.

Two rules follow, and both are refusals rather than warnings.

**A URL must carry its own digest.** `--policy https://acme.example/p.yaml#sha256=<hex>`
is accepted; the same URL without the fragment is refused. With the digest, a
compromised host serves something that does not verify and the scan stops; the
network stops being trusted and becomes merely a transport.

**Fetching requires network access to have been asked for.** Offline is the
default (C2). A tool that quietly reaches out because a path happened to start
with `https://` is a tool whose network behaviour depends on the shape of an
argument, which is not a property anybody can audit.

Verified policies are cached by digest, so the second scan on a machine needs no
network at all, and an air-gapped site can populate the cache by hand.
"""

from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import ClassVar

from cordon_scanner.core.errors import ConfigError

FETCH_TIMEOUT = 30
MAX_POLICY_BYTES = 1024 * 1024
"""A policy is a small YAML document. The cap is what stops a compromised or
merely misconfigured host from turning a fetch into a memory exhaustion."""

_DIGEST = re.compile(r"^sha256=([0-9a-f]{64})$")


class PolicyDistribution:
    """Resolves a `--policy` value that is a URL into a local file."""

    ALLOWED_SCHEMES: ClassVar[tuple[str, ...]] = ("https://",)
    """HTTPS only.

    The digest is what actually protects the content, so this is not the
    control -- but plain HTTP would additionally disclose which policy an
    organisation uses to anyone on the path, and there is no reason to allow
    that. A class attribute so a test can point the fetcher at a loopback
    server without weakening the rule in the shipped code.
    """

    @staticmethod
    def is_remote(source: str) -> bool:
        return source.startswith(("http://", "https://"))

    @staticmethod
    def split(source: str) -> tuple[str, str | None]:
        """Separate the URL from its `#sha256=` fragment."""
        url, _, fragment = source.partition("#")
        if not fragment:
            return (url, None)
        match = _DIGEST.match(fragment)
        return (url, match.group(1) if match else None)

    @classmethod
    def resolve(cls, source: str, *, allow_network: bool, cache_dir: Path) -> Path:
        """Return a local path for a remote policy, fetching it if needed."""
        url, digest = cls.split(source)

        if not url.startswith(cls.ALLOWED_SCHEMES):
            raise ConfigError(
                f"policy URL must use https: {url}",
                hint="Plain HTTP discloses which policy an organisation uses.",
            )
        if digest is None:
            raise ConfigError(
                f"policy URL has no integrity digest: {url}",
                hint=(
                    "Append the expected digest, for example "
                    "https://host/policy.yaml#sha256=<64 hex characters>. Without it, "
                    "whoever controls the network controls the ceiling this policy sets."
                ),
            )

        cached = cache_dir / "policies" / f"{digest}.yaml"
        if cached.is_file():
            # Re-verified on every use rather than trusted because it is in the
            # cache. The cache is an ordinary directory that other processes on
            # the machine can write.
            if hashlib.sha256(cached.read_bytes()).hexdigest() == digest:
                return cached
            cached.unlink(missing_ok=True)

        if not allow_network:
            raise ConfigError(
                f"policy {url} is not cached and network access is not allowed",
                hint=(
                    "Pass --allow-network to fetch it once, or place the file at "
                    f"{cached} on an air-gapped machine."
                ),
            )

        body = cls._fetch(url)
        actual = hashlib.sha256(body).hexdigest()
        if actual != digest:
            raise ConfigError(
                f"policy {url} does not match its digest",
                hint=(
                    f"Expected {digest}, got {actual}. Either the policy changed and the "
                    "URL needs updating, or what was served is not what was published."
                ),
            )

        cached.parent.mkdir(parents=True, exist_ok=True)
        # Written only after verification, so a failed fetch cannot leave
        # something behind that a later run would find and trust.
        cached.write_bytes(body)
        return cached

    @staticmethod
    def _fetch(url: str) -> bytes:
        request = urllib.request.Request(  # noqa: S310 - scheme checked by the caller
            url,
            headers={"User-Agent": "cordon-scanner"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:  # noqa: S310
                # Read one byte past the cap so the difference between "exactly
                # at the limit" and "over it" is visible.
                body: bytes = response.read(MAX_POLICY_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ConfigError(f"could not fetch policy {url}: {exc}") from exc
        if len(body) > MAX_POLICY_BYTES:
            raise ConfigError(
                f"policy {url} is larger than {MAX_POLICY_BYTES} bytes",
                hint="An organisation policy is a small document; this is not one.",
            )
        return body


__all__ = ["PolicyDistribution"]
