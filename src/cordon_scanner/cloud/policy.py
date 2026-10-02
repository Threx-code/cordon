"""K3: the organisation's policy bundle, fetched, verified and cached.

A bundle carries the organisation policy (the same YAML `--policy` reads: the ceiling a repository
cannot relax) and the suppressions the organisation approved centrally. It is signed with the
organisation's Ed25519 policy key and verified against the key pinned at sign-in, with the
verify-only implementation the intel feed already vendors -- so a compromised network path, a
compromised CDN, or a cloud API serving another tenant's bundle cannot change what a scan enforces.

Rules the client applies before a bundle takes effect:

* the signature verifies under a pinned key, and the bundle names this organisation;
* it has not expired, and it is not older than the cached one (no rollback to a weaker policy);
* offline, or when the cloud is unreachable, the cached bundle is used until it expires, and past
  that the scan is told the policy could not be applied rather than silently running without it.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.cloud import CloudError
from cordon_scanner.cloud.transport import Transport, error_text, request
from cordon_scanner.core.models import Suppression
from cordon_scanner.intel import _ed25519

if TYPE_CHECKING:
    from cordon_scanner.cloud.auth import Credentials

BUNDLE_TYPE: Final = "cordon.policy-bundle/v1"
#: The modes a repository's gate can be in. Anything else in a bundle is ignored, which leaves
#: that repository at `block`: an unknown mode never weakens the gate.
GATE_MODES: Final = frozenset({"observe", "warn", "block"})


class PolicyRejected(CloudError):
    """The cloud served a bundle that must not be applied: unsigned by a pinned key, for another
    organisation, or older than the one already held. Never falls back to the cache silently --
    something between this machine and the organisation's policy is wrong."""


@dataclass(frozen=True)
class PolicyBundle:
    org: str
    version: int
    issued_at: float
    expires_at: float
    policy_yaml: str
    suppressions: tuple[Suppression, ...]
    key_id: str
    source: str
    """`fetched` or `cached`."""
    gates: tuple[tuple[str, str], ...] = ()
    """Each repository's gate mode, `(key, mode)`: `observe` or `warn` record a failing verdict
    without failing the build; `block`, or a repository not listed, fails it as the policy says."""

    def gate_mode(self, key: str) -> str:
        """The gate mode for a repository key (`github.com/owner/repo`); `block` when not listed."""
        wanted = key.lower()
        return next((mode for name, mode in self.gates if name.lower() == wanted), "block")


def cache_dir() -> Path:
    explicit = os.environ.get("CORDON_CACHE_DIR")
    root = (
        Path(explicit)
        if explicit
        else Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "cordon"
    )
    return root / "policy"


def _verify(document: dict[str, Any], credentials: Credentials) -> dict[str, Any]:
    payload_b64 = document.get("payload")
    signatures = document.get("signatures")
    if not isinstance(payload_b64, str) or not isinstance(signatures, list):
        raise CloudError("the policy bundle is malformed")
    payload = base64.b64decode(payload_b64, validate=True)
    verified_by = ""
    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        key_id, signature = str(entry.get("keyid", "")), str(entry.get("sig", ""))
        key_hex = credentials.policy_keys.get(key_id)
        if not key_hex:
            continue
        with contextlib.suppress(ValueError):
            if _ed25519.verify(bytes.fromhex(key_hex), payload, bytes.fromhex(signature)):
                verified_by = key_id
                break
    if not verified_by:
        raise PolicyRejected(
            "the policy bundle is not signed by a key pinned for this organisation; it was not applied"
        )
    body = json.loads(payload)
    if not isinstance(body, dict) or body.get("type") != BUNDLE_TYPE:
        raise CloudError("the policy bundle is not a cordon.policy-bundle/v1 document")
    if str(body.get("org", "")) != credentials.org:
        raise PolicyRejected("the policy bundle names a different organisation; it was not applied")
    body["_key_id"] = verified_by
    return body


def _parse(body: dict[str, Any], source: str) -> PolicyBundle:
    suppressions: list[Suppression] = []
    for raw in body.get("suppressions") or ():
        if not isinstance(raw, dict):
            continue
        try:
            suppressions.append(
                Suppression(
                    rule=str(raw["rule"]),
                    path=str(raw["path"]),
                    justification=str(raw["justification"]),
                    expires=str(raw["expires"]),
                    approved_by=str(raw["approved_by"]),
                )
            )
        except KeyError as exc:
            raise CloudError(f"a suppression in the policy bundle is missing {exc}") from exc
    return PolicyBundle(
        org=str(body["org"]),
        version=int(body["version"]),
        issued_at=float(body["issued_at"]),
        expires_at=float(body["expires_at"]),
        policy_yaml=str(body.get("policy", "")),
        suppressions=tuple(suppressions),
        key_id=str(body.get("_key_id", "")),
        source=source,
        gates=tuple(
            (str(name), str(mode))
            for name, mode in sorted((body.get("gates") or {}).items())
            if str(mode) in GATE_MODES
        ),
    )


def _cached(credentials: Credentials) -> tuple[dict[str, Any], PolicyBundle] | None:
    path = cache_dir() / f"{credentials.org}.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        return document, _parse(_verify(document, credentials), "cached")
    except (OSError, ValueError, CloudError, KeyError, TypeError):
        return None


def _store(credentials: Credentials, document: dict[str, Any]) -> None:
    directory = cache_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{credentials.org}.json"
    staging = target.with_suffix(".tmp")
    staging.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    staging.replace(target)


def fetch(
    credentials: Credentials,
    *,
    offline: bool = False,
    transport: Transport | None = None,
    clock: Callable[[], float] = time.time,
) -> PolicyBundle:
    """The organisation's current policy bundle, verified. Raises when none can be applied."""
    now = clock()
    cached = _cached(credentials)
    fetched: PolicyBundle | None = None
    problem = ""
    if not offline:
        try:
            response = request(
                "GET",
                f"{credentials.url}/v1/policy/bundle",
                token=credentials.access_token,
                transport=transport,
            )
            if response.status == 200:
                fetched = _parse(_verify(response.body, credentials), "fetched")
                if cached is not None and fetched.version < cached[1].version:
                    raise PolicyRejected(
                        f"the cloud served policy version {fetched.version}, older than the cached "
                        f"{cached[1].version}; the older bundle was refused"
                    )
                if fetched.expires_at > now:
                    _store(credentials, response.body)
                    return fetched
                problem = "the cloud served an expired policy bundle"
            else:
                problem = f"the cloud did not serve a policy bundle ({error_text(response)})"
        except PolicyRejected:
            raise
        except CloudError as exc:
            problem = str(exc)
    if cached is not None and cached[1].expires_at > now:
        return cached[1]
    raise CloudError(problem or "no current policy bundle is cached; connect once to fetch it")


def materialise(bundle: PolicyBundle) -> Path | None:
    """Write the bundle's policy YAML where `--policy` can read it; None when it carries none."""
    if not bundle.policy_yaml.strip():
        return None
    directory = cache_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{bundle.org}.policy.yaml"
    target.write_text(bundle.policy_yaml, encoding="utf-8")
    return target


__all__ = ["BUNDLE_TYPE", "PolicyBundle", "PolicyRejected", "cache_dir", "fetch", "materialise"]
