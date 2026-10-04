"""K7: signing in. Device flow for people, token exchange for CI, a stored credential for both.

A person runs `cordon login` and approves the request in a browser, through the organisation's
SSO (OAuth 2.0 Device Authorization Grant, RFC 8628). CI never holds a long-lived Cordon token:
the job's own OIDC identity token -- GitHub Actions, GitLab, Buildkite, CircleCI and others issue
one -- is exchanged for a fifteen-minute Cordon token (OAuth 2.0 Token Exchange, RFC 8693), and
the cloud maps it to an organisation through a trust rule on the issuer and claims.

The stored credential lives in the user's config directory with mode 0600 and holds the tokens,
the organisation, and the organisation's policy signing keys -- pinned at sign-in, which is what
the policy bundle is later verified against.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final

from cordon_scanner.cloud import CloudEndpoint, CloudError
from cordon_scanner.cloud.transport import CloudTransport, Transport

CLIENT_ID: Final = "cordon-cli"
DEVICE_GRANT: Final = "urn:ietf:params:oauth:grant-type:device_code"
EXCHANGE_GRANT: Final = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TYPE: Final = "urn:ietf:params:oauth:token-type:jwt"
AUDIENCE: Final = "cordon"
SCOPES: Final = "scans:write policy:read"
CREDENTIALS_NAME: Final = "credentials.json"
REFRESH_MARGIN_SECONDS: Final = 60


@dataclass
class Credentials:
    url: str
    org: str
    access_token: str
    expires_at: float
    refresh_token: str = ""
    subject: str = ""
    """Who signed in, as the cloud named them: an email for a person, a repository for CI."""
    policy_keys: dict[str, str] = field(default_factory=dict)
    """Key id to hex Ed25519 public key, pinned at sign-in."""
    keys_from_customer: bool = True
    """Whether the keys came from somewhere the cloud cannot change: pinned at a first sign-in on this
    machine, or set by the customer in `CORDON_POLICY_KEYS`. False only for a CI exchange with no
    such variable, where the keys arrived with the very token they would be checking."""

    def expired(self, now: float) -> bool:
        return now >= self.expires_at - REFRESH_MARGIN_SECONDS


ORG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
"""An organisation name this client will use in a cache path."""


class CloudAuth:
    """Signing in to the cloud: stored credentials, the device flow, and CI's own identity."""

    @staticmethod
    def config_dir() -> Path:
        explicit = os.environ.get("CORDON_CONFIG_DIR")
        if explicit:
            return Path(explicit)
        root = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        return Path(root) / "cordon"

    @staticmethod
    def load() -> Credentials | None:
        path = CloudAuth.config_dir() / CREDENTIALS_NAME
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Credentials(
                **{k: data[k] for k in Credentials.__dataclass_fields__ if k in data}
            )
        except (OSError, ValueError, TypeError, KeyError):
            return None

    @staticmethod
    def save(credentials: Credentials) -> Path:
        directory = CloudAuth.config_dir()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = directory / CREDENTIALS_NAME
        staging = target.with_suffix(".tmp")
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(asdict(credentials), handle, indent=2, sort_keys=True)
        staging.replace(target)
        return target

    @staticmethod
    def forget() -> bool:
        try:
            (CloudAuth.config_dir() / CREDENTIALS_NAME).unlink()
        except FileNotFoundError:
            return False
        return True

    @staticmethod
    def _credentials_from(
        url: str, body: dict[str, Any], now: float, previous: Credentials | None = None
    ) -> Credentials:
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise CloudError("the cloud issued no access token")
        # Pinned means pinned. A renewal used to replace the keys with whatever the token
        # endpoint returned, so a compromised endpoint could hand over its own key with a bundle
        # it had signed. Once this machine holds keys, a token response cannot change them;
        # rotating them is a fresh `cordon login`, made by the person at the keyboard.
        keys = body.get("policy_keys")
        offered = {str(k): str(v) for k, v in keys.items()} if isinstance(keys, dict) else {}
        pinned = previous.policy_keys if previous and previous.policy_keys else offered
        org = str(body.get("org", previous.org if previous else ""))
        if org and not ORG_NAME.fullmatch(org):
            # It becomes a file name in the policy cache; a name the cloud chose must not climb out.
            raise CloudError("the cloud named an organisation this client will not use as a path")
        return Credentials(
            url=url,
            org=org,
            access_token=token,
            expires_at=now + float(body.get("expires_in", 900)),
            refresh_token=str(
                body.get("refresh_token", previous.refresh_token if previous else "")
            ),
            subject=str(body.get("subject", previous.subject if previous else "")),
            policy_keys=pinned,
            keys_from_customer=True,
        )

    @staticmethod
    def start_device_flow(
        url: str | None = None, *, transport: Transport | None = None
    ) -> DeviceCode:
        api = CloudEndpoint.base_url(url)
        response = CloudTransport.request(
            "POST",
            f"{api}/v1/auth/device/code",
            form={"client_id": CLIENT_ID, "scope": SCOPES},
            transport=transport,
        )
        if response.status != 200:
            raise CloudError(
                f"the cloud refused to start sign-in: {CloudTransport.error_text(response)}"
            )
        body = response.body
        try:
            return DeviceCode(
                device_code=str(body["device_code"]),
                user_code=str(body["user_code"]),
                verification_uri=str(body["verification_uri"]),
                verification_uri_complete=str(
                    body.get("verification_uri_complete", body["verification_uri"])
                ),
                expires_in=int(body.get("expires_in", 900)),
                interval=max(int(body.get("interval", 5)), 1),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CloudError("the cloud's sign-in response was incomplete") from exc

    @staticmethod
    def finish_device_flow(
        code: DeviceCode,
        url: str | None = None,
        *,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> Credentials:
        """Poll until the person approves, declines, or the code expires (RFC 8628 section 3.5)."""
        api = CloudEndpoint.base_url(url)
        interval = code.interval
        deadline = clock() + code.expires_in
        while clock() < deadline:
            sleep(interval)
            response = CloudTransport.request(
                "POST",
                f"{api}/v1/auth/token",
                form={
                    "grant_type": DEVICE_GRANT,
                    "device_code": code.device_code,
                    "client_id": CLIENT_ID,
                },
                transport=transport,
            )
            if response.status == 200:
                return CloudAuth._credentials_from(api, response.body, clock())
            error = str(response.body.get("error", ""))
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            if error == "access_denied":
                raise CloudError("sign-in was declined")
            if error == "expired_token":
                break
            raise CloudError(f"sign-in failed: {CloudTransport.error_text(response)}")
        raise CloudError(
            "the sign-in code expired before it was approved; run `cordon login` again"
        )

    # -- token exchange (CI) -------------------------------------------------------------------------

    @staticmethod
    def ambient_identity_token(
        environ: dict[str, str] | None = None, *, transport: Transport | None = None
    ) -> tuple[str, str] | None:
        """(token, provider) from the CI job's own OIDC identity, or None outside CI.

        GitHub Actions hands out a token on request when the job has `id-token: write`; GitLab and
        others place one in an environment variable the pipeline names (`CORDON_ID_TOKEN` here, set
        through GitLab's `id_tokens:` with audience `cordon`, CircleCI's `circleci run oidc get`,
        Buildkite's `buildkite-agent oidc request-token`, Azure's service-connection token or
        Jenkins' OIDC credential). Bitbucket Pipelines' own token is read as it is: it cannot carry
        another audience. CircleCI's default token is deliberately NOT read - its audience is the
        organisation id that cloud roles trust, and it must not leave the job.
        """
        env = dict(os.environ) if environ is None else environ
        for variable, provider in (
            ("CORDON_ID_TOKEN", "environment"),
            ("BITBUCKET_STEP_OIDC_TOKEN", "bitbucket-pipelines"),
        ):
            if env.get(variable):
                return env[variable], provider
        request_url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        request_token = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if request_url and request_token:
            separator = "&" if "?" in request_url else "?"
            url = f"{request_url}{separator}audience={urllib.parse.quote(AUDIENCE)}"
            if not url.startswith("https://"):
                return None
            with contextlib.suppress(CloudError):
                response = CloudTransport.request(
                    "GET", url, token=request_token, transport=transport
                )
                value = response.body.get("value")
                if response.status == 200 and isinstance(value, str) and value:
                    return value, "github-actions"
        return None

    @staticmethod
    def exchange(
        identity_token: str,
        url: str | None = None,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> Credentials:
        api = CloudEndpoint.base_url(url)
        response = CloudTransport.request(
            "POST",
            f"{api}/v1/auth/token",
            form={
                "grant_type": EXCHANGE_GRANT,
                "subject_token": identity_token,
                "subject_token_type": JWT_TYPE,
                "audience": AUDIENCE,
                "scope": SCOPES,
                "client_id": CLIENT_ID,
            },
            transport=transport,
        )
        if response.status != 200:
            raise CloudError(
                f"the cloud refused this CI identity: {CloudTransport.error_text(response)}. An organisation admin adds a "
                f"trust rule for the repository before its jobs can upload."
            )
        credentials = CloudAuth._credentials_from(api, response.body, clock())
        # In CI nothing is stored between jobs, so trust-on-first-use pins nothing. The keys a
        # policy bundle is checked against come from the customer's CI configuration instead.
        configured = CloudAuth.configured_policy_keys()
        if configured:
            return dataclasses.replace(credentials, policy_keys=configured, keys_from_customer=True)
        return dataclasses.replace(credentials, keys_from_customer=False)

    @staticmethod
    def configured_policy_keys(environ: dict[str, str] | None = None) -> dict[str, str]:
        """`CORDON_POLICY_KEYS`: `keyid:hex,keyid:hex`, set by the customer in CI."""
        raw = (os.environ if environ is None else environ).get("CORDON_POLICY_KEYS", "")
        keys: dict[str, str] = {}
        for part in raw.split(","):
            key_id, _, key_hex = part.strip().partition(":")
            if (
                key_id
                and len(key_hex) == 64
                and all(c in "0123456789abcdefABCDEF" for c in key_hex)
            ):
                keys[key_id] = key_hex.lower()
        return keys

    @staticmethod
    def refresh(
        credentials: Credentials,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> Credentials:
        if not credentials.refresh_token:
            raise CloudError("the sign-in has expired; run `cordon login` again")
        response = CloudTransport.request(
            "POST",
            f"{credentials.url}/v1/auth/token",
            form={
                "grant_type": "refresh_token",
                "refresh_token": credentials.refresh_token,
                "client_id": CLIENT_ID,
            },
            transport=transport,
        )
        if response.status != 200:
            raise CloudError(
                f"the sign-in could not be renewed ({CloudTransport.error_text(response)}); run `cordon login` again"
            )
        return CloudAuth._credentials_from(
            credentials.url, response.body, clock(), previous=credentials
        )

    @staticmethod
    def current(
        url: str | None = None,
        *,
        environ: dict[str, str] | None = None,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> Credentials:
        """A usable credential: CI's own identity when present, otherwise the stored sign-in,
        renewed when it is about to expire."""
        ambient = CloudAuth.ambient_identity_token(environ, transport=transport)
        if ambient is not None:
            return CloudAuth.exchange(ambient[0], url, transport=transport, clock=clock)
        stored = CloudAuth.load()
        if stored is None:
            raise CloudError(
                "not signed in; run `cordon login`, or run in CI with an OIDC identity token"
            )
        if url is not None and CloudEndpoint.base_url(url) != stored.url:
            raise CloudError(
                f"signed in to {stored.url}, not {CloudEndpoint.base_url(url)}; run `cordon login --url`"
            )
        if stored.expired(clock()):
            stored = CloudAuth.refresh(stored, transport=transport, clock=clock)
            CloudAuth.save(stored)
        return stored


# -- device flow (people) ------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


__all__ = ["CloudAuth", "Credentials", "DeviceCode"]
