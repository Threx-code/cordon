"""Registries an organisation runs, asked with the credential its operator supplies.

`--registry-token https://npm.acme.example=ACME_NPM_TOKEN` (or `CORDON_REGISTRY_TOKENS`, comma
separated) names a registry and the environment variable that holds its token. Under `--online`,
a dependency the project resolved from that registry is asked about there -- its versions, the
digests it publishes, withdrawals -- as a public one is about the public registry: npm-compatible
registries by their packument, Python indexes by their PEP 691 JSON, container registries through
the OCI distribution API.

What keeps the credential where it belongs:

* only the operator supplies it, by naming a variable: never a repository's configuration, which
  would let a scanned project send a credential to a host it chose, and never the token itself on
  a command line, where process listings and shell history keep it;
* it goes to the URL it was named for and nowhere else: HTTPS only, no redirect followed, the host
  compared exactly;
* no message, finding or report repeats it -- a failure says which registry and which variable,
  never the value.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any, Final, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.intel.registry_client import PackageFacts

MAX_BYTES: Final = 32 << 20


class PrivateRegistry(NamedTuple):
    base: str
    """`https://host[:port]/path`, without a trailing slash."""
    variable: str
    """The environment variable holding the token: `token` (bearer) or `user:token` (basic)."""

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.base).netloc.lower()


class PrivateRegistries:
    """The configured registries, and the questions put to them."""

    @staticmethod
    def parse(values: Iterable[str]) -> tuple[PrivateRegistry, ...]:
        """`URL=VARIABLE` pairs; anything else is refused with the reason (never the value)."""
        out: list[PrivateRegistry] = []
        for value in values:
            for item in (part.strip() for part in value.split(",")):
                if not item:
                    continue
                url, equals, variable = item.rpartition("=")
                if not equals or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", variable):
                    # Not repeated: the commonest mistake is the token itself where its variable's
                    # name belongs, and an error message is the last place it should appear.
                    raise ValueError(
                        "--registry-token takes URL=ENVIRONMENT_VARIABLE: the name of a variable holding the token, never the token"
                    )
                parsed = urllib.parse.urlsplit(url.strip())
                if (
                    parsed.scheme != "https"
                    or not parsed.netloc
                    or parsed.username
                    or parsed.password
                    or parsed.query
                ):
                    raise ValueError(
                        "--registry-token takes an https:// registry URL with no credentials or query in it"
                    )
                out.append(
                    PrivateRegistry(
                        f"https://{parsed.netloc.lower()}{parsed.path.rstrip('/')}", variable
                    )
                )
        return tuple(out)

    @staticmethod
    def matching(
        configured: tuple[PrivateRegistry, ...],
        ecosystem: str,
        name: str,
        resolved_from: str | None,
    ) -> PrivateRegistry | None:
        """The registry a dependency came from, when it is one of these: by the resolved URL's
        host and path prefix, or (an image) by the registry host in its name."""
        if not configured:
            return None
        if ecosystem == "image":
            host = name.split("/", 1)[0].lower() if "/" in name else ""
            return next((r for r in configured if r.host == host), None)
        reference = (resolved_from or "").removeprefix("registry:")
        if not reference.startswith("https://"):
            return None
        parsed = urllib.parse.urlsplit(reference)
        target = f"https://{parsed.netloc.lower()}{parsed.path}"
        return next(
            (r for r in configured if target == r.base or target.startswith(r.base + "/")), None
        )

    @staticmethod
    def credential(registry: PrivateRegistry) -> str | None:
        value = os.environ.get(registry.variable, "").strip()
        return value or None

    @staticmethod
    def _authorization(credential: str) -> str:
        if ":" in credential:
            import base64

            return "Basic " + base64.b64encode(credential.encode()).decode()
        return f"Bearer {credential}"

    @staticmethod
    def get(
        registry: PrivateRegistry,
        url: str,
        credential: str,
        *,
        accept: str = "application/json",
        authorization: str | None = None,
    ) -> bytes:
        """One request to the registry the credential was named for, never anywhere else."""
        from cordon_scanner.intel import registry_client as base
        from cordon_scanner.intel.registry_client import PackageNotFound, RegistryError

        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc.lower() != registry.host:
            raise RegistryError(
                f"refusing to send {registry.variable} anywhere but {registry.host}"
            )
        request = urllib.request.Request(  # noqa: S310 (https and the host checked above)
            url,
            headers={
                "User-Agent": base.USER_AGENT,
                "Accept": accept,
                "Authorization": authorization or PrivateRegistries._authorization(credential),
            },
        )
        opener = urllib.request.build_opener(base._NoRedirect)
        try:
            with opener.open(request, timeout=base.TIMEOUT_SECONDS) as response:
                body = bytes(response.read(MAX_BYTES + 1))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PackageNotFound(f"{registry.host} has no such package") from exc
            if exc.code in (401, 403):
                raise RegistryError(
                    f"{registry.host} refused the credential in {registry.variable} (HTTP {exc.code})"
                ) from exc
            raise RegistryError(f"HTTP {exc.code} from {registry.host}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} asking {registry.host}") from exc
        if len(body) > MAX_BYTES:
            raise RegistryError(f"a response from {registry.host} exceeded {MAX_BYTES} bytes")
        return body

    @staticmethod
    def facts(
        registry: PrivateRegistry, ecosystem: str, name: str, version: str | None
    ) -> PackageFacts:
        from cordon_scanner.intel.registry_client import RegistryError

        credential = PrivateRegistries.credential(registry)
        if credential is None:
            raise RegistryError(f"{registry.variable} is not set, so {registry.host} was not asked")
        if ecosystem == "npm":
            return PrivateRegistries._npm(registry, credential, name, version)
        if ecosystem == "pypi":
            return PrivateRegistries._pypi(registry, credential, name, version)
        if ecosystem == "image":
            return PrivateRegistries._image(registry, credential, name, version)
        raise RegistryError(f"no private-registry protocol for {ecosystem} is spoken here")

    @staticmethod
    def _npm(
        registry: PrivateRegistry, credential: str, name: str, version: str | None
    ) -> PackageFacts:
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError

        if not re.fullmatch(r"(?:@[a-z0-9][\w.\-]*/)?[a-z0-9][\w.\-]*", name, re.IGNORECASE):
            raise RegistryError(f"{name} is not an npm package name")
        quoted = urllib.parse.quote(name, safe="@/")
        try:
            document = json.loads(
                PrivateRegistries.get(registry, f"{registry.base}/{quoted}", credential)
            )
        except ValueError as exc:
            raise RegistryError(f"{registry.host} answered with something other than JSON") from exc
        return RegistryClient._npm_document(
            RegistryClient._mapping(document), name, version, downloads=False
        )

    @staticmethod
    def _pypi(
        registry: PrivateRegistry, credential: str, name: str, version: str | None
    ) -> PackageFacts:
        from cordon_scanner.intel.registry_client import PackageFacts, RegistryClient, RegistryError

        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,199}", normalized):
            raise RegistryError(f"{name} is not a Python project name")
        index = registry.base if registry.base.endswith("/simple") else f"{registry.base}/simple"
        try:
            document = RegistryClient._mapping(
                json.loads(
                    PrivateRegistries.get(
                        registry,
                        f"{index}/{normalized}/",
                        credential,
                        accept="application/vnd.pypi.simple.v1+json",
                    )
                )
            )
        except ValueError as exc:
            raise RegistryError(
                f"{registry.host} does not serve the JSON simple API (PEP 691)"
            ) from exc
        files = [
            f
            for f in document.get("files") or []
            if isinstance(f, dict) and isinstance(f.get("filename"), str)
        ]
        versions = [str(v) for v in document.get("versions") or [] if isinstance(v, str)]
        mine = [
            f
            for f in files
            if version and RegistryClient._is_file_for_version(f["filename"], version)
        ]
        digests = tuple(
            f"sha256:{RegistryClient._mapping(f.get('hashes')).get('sha256')}"
            for f in mine
            if isinstance(RegistryClient._mapping(f.get("hashes")).get("sha256"), str)
        )
        yanked = bool(mine) and all(f.get("yanked") not in (None, False) for f in mine)
        missing = bool(version) and not mine
        return PackageFacts(
            name=name,
            version=version,
            yanked=yanked or missing,
            yanked_reason=("yanked" if yanked else "not a version the registry holds")
            if (yanked or missing)
            else None,
            latest=None,
            digests=digests,
            releases=len(versions) or len({f["filename"] for f in files}),
        )

    @staticmethod
    def _image(
        registry: PrivateRegistry, credential: str, name: str, version: str | None
    ) -> PackageFacts:
        """The OCI distribution API with the registry's credential: tried directly, and through
        the token service a registry names in its challenge when it wants one."""
        import hashlib

        from cordon_scanner.intel.more_registries import MoreRegistries
        from cordon_scanner.intel.registry_client import (
            PackageFacts,
            PackageNotFound,
            RegistryError,
        )

        repository = name.split("/", 1)[1] if "/" in name else ""
        if not re.fullmatch(
            r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*",
            repository,
        ):
            raise RegistryError(f"{name} is not an image on {registry.host}")
        if version is not None and not re.fullmatch(
            r"[\w][\w.-]{0,127}|sha256:[0-9a-f]{64}", version
        ):
            raise RegistryError(f"{version} is not a tag or a digest")
        base_url = f"https://{registry.host}/v2/{repository}"
        authorization = PrivateRegistries._oci_authorization(registry, credential, base_url)
        listed = [
            str(t)
            for t in RegistryClientHelpers.tags(
                PrivateRegistries.get(
                    registry, f"{base_url}/tags/list", credential, authorization=authorization
                )
            )
        ]
        digests: tuple[str, ...] = ()
        found = True
        if version is not None:
            try:
                raw = PrivateRegistries.get(
                    registry,
                    f"{base_url}/manifests/{version}",
                    credential,
                    accept=MoreRegistries.MANIFEST_TYPES,
                    authorization=authorization,
                )
            except PackageNotFound:
                found = False
            else:
                document = RegistryClientHelpers.mapping(json.loads(raw))
                platforms = [
                    str(m["digest"]).lower()
                    for m in document.get("manifests") or []
                    if isinstance(m, dict)
                    and isinstance(m.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", m["digest"])
                ]
                digests = (f"sha256:{hashlib.sha256(raw).hexdigest()}", *platforms)
        return PackageFacts(
            name=name,
            version=version,
            yanked=not found,
            yanked_reason=None if found else "not a tag or digest the registry holds",
            latest=None,
            digests=digests,
            releases=len(listed),
        )

    @staticmethod
    def _oci_authorization(registry: PrivateRegistry, credential: str, base_url: str) -> str:
        """The header the registry accepts: the credential itself, or the bearer token its token
        service issues for it -- asked of that service only when it is on the same host."""
        from cordon_scanner.intel import registry_client as base
        from cordon_scanner.intel.registry_client import RegistryError

        direct = PrivateRegistries._authorization(credential)
        request = urllib.request.Request(
            f"https://{registry.host}/v2/",
            headers={"User-Agent": base.USER_AGENT, "Authorization": direct},
        )
        try:
            with urllib.request.build_opener(base._NoRedirect).open(
                request, timeout=base.TIMEOUT_SECONDS
            ):
                return direct
        except urllib.error.HTTPError as exc:
            challenge = str(exc.headers.get("WWW-Authenticate", "")) if exc.code == 401 else ""
            if not challenge.startswith("Bearer "):
                if exc.code in (401, 403):
                    raise RegistryError(
                        f"{registry.host} refused the credential in {registry.variable} (HTTP {exc.code})"
                    ) from exc
                return direct
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} asking {registry.host}") from exc
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = urllib.parse.urlsplit(fields.get("realm", ""))
        if realm.scheme != "https" or realm.netloc.lower() != registry.host:
            raise RegistryError(
                f"{registry.host} asked for {registry.variable} to be sent to another host; it was not"
            )
        scope = f"repository:{base_url.split('/v2/', 1)[1]}:pull"
        query = urllib.parse.urlencode({"service": fields.get("service", ""), "scope": scope})
        token = RegistryClientHelpers.mapping(
            json.loads(PrivateRegistries.get(registry, f"{fields['realm']}?{query}", credential))
        ).get("token")
        if not isinstance(token, str):
            raise RegistryError(f"{registry.host}'s token service gave no token")
        return f"Bearer {token}"


class RegistryClientHelpers:
    @staticmethod
    def mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def tags(raw: bytes) -> list[str]:
        try:
            document = json.loads(raw)
        except ValueError:
            return []
        tags = RegistryClientHelpers.mapping(document).get("tags")
        return [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []


__all__ = ["PrivateRegistries", "PrivateRegistry", "RegistryClientHelpers"]
