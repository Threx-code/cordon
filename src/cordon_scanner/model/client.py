"""`scan --model`: the packages a scan holds, scored by a Cordon model server.

    --model cordon-cloud      Cordon Cloud, with the `cordon-scanner login` sign-in
    --model https://HOST      a model server inside the organisation (cordon-model-server), with the
                              token in CORDON_MODEL_TOKEN -- never from a repository's configuration

What is sent per package is what `features` computes: structure and capability counts, hashed
identifiers and per-file rows. No file, path, name or line of source leaves the machine. The
request goes over HTTPS (plain HTTP only to this machine's own loopback), follows no redirect,
and the reply is size-capped and checked before any of it becomes a finding.

Which packages: a package archive scanned on its own (`scan pkg.tgz`, `scan pkg:npm/x@1`), the
package archives a directory holds, and the installed packages under `node_modules/` and Python's
`site-packages/` -- the code a project runs but did not write. A project's own source is not sent:
the model was trained on published packages, and is not asked about anything else.
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.model.features import FileFeatures, PackageArchive, PackageFeatures

TOKEN_ENV: Final = "CORDON_MODEL_TOKEN"  # noqa: S105 - the variable's name, never a value
BATCH: Final = 100
#: About this many bytes per request: under the 16 MB a model server (and Cordon Cloud) accepts.
MAX_REQUEST: Final = 12 << 20
MAX_PACKAGES: Final = 2000
MAX_REPLY: Final = 8 << 20
TIMEOUT: Final = 60
_ARCHIVES: Final = (".tgz", ".tar.gz", ".whl", ".zip", ".gem", ".crate", ".nupkg")
#: What makes a directory one package: npm's manifest, or a Python distribution's.
_PACKAGE_MANIFESTS: Final = ("package.json", "PKG-INFO", "setup.py", "pyproject.toml", "setup.cfg")


class ModelError(Exception):
    """The model could not be asked; the scan says so and is incomplete."""


@dataclass(frozen=True, slots=True)
class PackageUnit:
    """One package to score: where it is (reported in findings, never sent) and its files."""

    location: str
    files: list[tuple[str, bytes]]


@dataclass(frozen=True, slots=True)
class Verdict:
    location: str
    malicious: bool
    package_score: float
    file_score: float | None
    reasons: tuple[str, ...]


class ModelTargets:
    """The packages in a scan target."""

    @staticmethod
    def collect(target: Path) -> tuple[list[PackageUnit], bool]:
        """(packages, whether more were found than are scored)."""
        if target.is_file():
            return [PackageUnit(target.name, PackageArchive.members(target.read_bytes()))], False
        units: list[PackageUnit] = []
        unpacked = ModelTargets.unpacked_root(target)
        if unpacked is not None:
            units.append(
                PackageUnit(
                    unpacked.relative_to(target).as_posix() or ".",
                    PackageArchive.directory(unpacked),
                )
            )
        for path in sorted(target.rglob("*")):
            if len(units) >= MAX_PACKAGES:
                return units, True
            if path.is_symlink():
                continue
            relative = path.relative_to(target).as_posix()
            if path.is_file() and path.name.lower().endswith(_ARCHIVES):
                try:
                    data = path.read_bytes() if path.stat().st_size <= (64 << 20) else b""
                except OSError:
                    continue
                files = PackageArchive.members(data) if data else []
                if files:
                    units.append(PackageUnit(relative, files))
            elif path.is_dir() and ModelTargets.installed_package(path):
                units.append(PackageUnit(relative, PackageArchive.directory(path)))
        return units, False

    @staticmethod
    def unpacked_root(target: Path) -> Path | None:
        """The scan target itself, when it is one unpacked package: a manifest at its top, or down
        a chain of at most four lone subdirectories (an npm tarball unpacks to `package/`, an sdist
        to `name-version/`, and an archive of either may wrap them further). Not a git checkout: that is a repository, and the model was trained
        and measured on published packages."""
        if (target / ".git").exists():
            return None
        candidate = target
        for _ in range(5):
            if any((candidate / name).is_file() for name in _PACKAGE_MANIFESTS):
                return candidate
            try:
                children = [p for p in candidate.iterdir() if not p.name.startswith(".")]
            except OSError:
                return None
            dirs = [p for p in children if p.is_dir() and not p.is_symlink()]
            if len(dirs) != 1 or len(children) - len(dirs) > 1:
                return None
            candidate = dirs[0]
        return None

    @staticmethod
    def installed_package(path: Path) -> bool:
        """An installed npm package (node_modules/[@scope/]name with a package.json) or a Python
        distribution's top-level package in site-packages."""
        parent = path.parent
        if parent.name == "node_modules" or (
            parent.name.startswith("@") and parent.parent.name == "node_modules"
        ):
            return (path / "package.json").is_file()
        if parent.name in ("site-packages", "dist-packages"):
            return (path / "__init__.py").is_file()
        return False


class ModelClient:
    def __init__(self, endpoint: str, token: str) -> None:
        self.endpoint = endpoint
        self.token = token

    @staticmethod
    def for_target(spec: str, cloud_url: str | None = None) -> ModelClient:
        if spec == "cordon-cloud":
            from cordon_scanner.cloud import CloudError, auth

            base = (
                cloud_url or os.environ.get("CORDON_CLOUD_URL") or "https://api.cordon.dev"
            ).rstrip("/")
            try:
                credentials = auth.CloudAuth.current(base)
            except CloudError as exc:
                raise ModelError(f"Cordon Cloud is not signed in: {exc}") from exc
            return ModelClient(f"{base}/v1/model/score", credentials.access_token)
        parsed = urllib.parse.urlsplit(spec)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ModelError(
                "--model takes cordon-cloud or the https:// address of a Cordon model server"
            )
        if parsed.scheme == "http" and not ModelClient.loopback(parsed.hostname):
            raise ModelError(
                "a model server is reached over HTTPS; plain HTTP is only for this machine's loopback"
            )
        token = os.environ.get(TOKEN_ENV, "").strip()
        if not token:
            raise ModelError(f"a model server needs its token in {TOKEN_ENV}")
        return ModelClient(spec.rstrip("/") + "/v1/model/score", token)

    @staticmethod
    def loopback(host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @staticmethod
    def batches(units: list[PackageUnit]) -> list[list[tuple[int, dict[str, Any]]]]:
        """Packages grouped into requests of at most `BATCH` and about `MAX_REQUEST` bytes: a
        package heavy with identifiers must not push a request past what the server accepts."""
        out: list[list[tuple[int, dict[str, Any]]]] = []
        current: list[tuple[int, dict[str, Any]]] = []
        size = 0
        for index, unit in enumerate(units):
            dense, tokens = PackageFeatures.extract(unit.files)
            entry = {
                "ref": str(index),
                "dense": dense,
                "tokens": tokens,
                "files": FileFeatures.rows(unit.files),
            }
            weight = len(json.dumps(entry))
            if current and (len(current) >= BATCH or size + weight > MAX_REQUEST):
                out.append(current)
                current, size = [], 0
            current.append((index, entry))
            size += weight
        if current:
            out.append(current)
        return out

    def score(self, units: list[PackageUnit]) -> list[Verdict]:
        verdicts: list[Verdict] = []
        for group in ModelClient.batches(units):
            reply = self._post(
                {"schema": "cordon.model/v1", "packages": [entry for _, entry in group]}
            )
            by_ref = {r.get("ref"): r for r in reply.get("results") or [] if isinstance(r, dict)}
            for index, _ in group:
                unit = units[index]
                result = by_ref.get(str(index))
                if not isinstance(result, dict) or result.get("verdict") not in (
                    "malicious",
                    "benign",
                ):
                    raise ModelError("the model server's reply did not cover every package")
                verdicts.append(
                    Verdict(
                        location=unit.location,
                        malicious=result["verdict"] == "malicious",
                        package_score=float(result.get("package_score") or 0.0),
                        file_score=None
                        if result.get("file_score") is None
                        else float(result["file_score"]),
                        reasons=tuple(
                            str(r) for r in result.get("reasons") or () if r in ("package", "file")
                        ),
                    )
                )
        return verdicts

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - https, or http to loopback, checked above
            self.endpoint,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "cordon-scanner (model client)",
            },
            method="POST",
        )
        opener = urllib.request.build_opener(NoRedirects)
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                raw = Download.read(response, MAX_REPLY + 1)
        except urllib.error.HTTPError as exc:
            hint = " (check the token)" if exc.code in (401, 403) else ""
            raise ModelError(f"the model server answered HTTP {exc.code}{hint}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ModelError(f"could not reach the model server: {type(exc).__name__}") from exc
        if len(raw) > MAX_REPLY:
            raise ModelError("the model server's reply was larger than 8 MB")
        try:
            reply = json.loads(raw)
        except ValueError as exc:
            raise ModelError("the model server's reply is not JSON") from exc
        if not isinstance(reply, dict) or reply.get("schema") != "cordon.model/v1":
            raise ModelError("the model server's reply is not cordon.model/v1")
        return reply
