"""K6: `cordon runner`, the customer-run worker. Outbound only: it asks for work, never listens.

Mode C deployment: code never leaves the customer's network. The runner leases a scan job from the
cloud, fetches the target itself (a git clone or an artefact download), scans it with the same
engine as `cordon scan`, uploads the signed results (K2) and reports the job's outcome. It holds
one lease at a time per worker and heartbeats while it scans, so a crashed runner's job is leased
again elsewhere once its lease lapses.

The cloud is not trusted to point the runner anywhere: the operator lists the hosts the runner may
clone or download from, and a job naming any other host is refused, so a compromised control plane
cannot turn the runner into a probe of the internal network. Clones run with hooks disabled, the
file protocol refused, no credential prompts and a depth of one. Nothing from the target is
executed -- that is the engine's rule everywhere.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cordon_scanner.cloud import CloudError
from cordon_scanner.cloud.transport import Response, Transport, error_text, request

MAX_ARTIFACT_BYTES: Final = 2 << 30
CLONE_TIMEOUT_SECONDS: Final = 600
#: A full or abbreviated commit, or a pull or merge request's ref: fetched exactly, not cloned
#: by branch name.
EXACT_REVISION: Final = re.compile(
    r"^(?:[0-9a-f]{7,40}|refs/pull/\d+/(?:head|merge)|refs/merge-requests/\d+/head)$"
)
DEFAULT_POLL_SECONDS: Final = 15.0
MAX_POLL_SECONDS: Final = 300.0
#: Idle polling stops backing off here, so a scan someone just asked for starts within half a
#: minute; failures still back off to MAX_POLL_SECONDS so a down control plane is not hammered.
MAX_IDLE_POLL_SECONDS: Final = 30.0


@dataclass(frozen=True)
class Job:
    id: str
    lease_id: str
    lease_seconds: float
    target: dict[str, Any]
    options: dict[str, Any]


@dataclass
class RunnerConfig:
    url: str
    token: str
    runner_id: str
    allowed_hosts: frozenset[str]
    labels: tuple[str, ...] = ()
    work_dir: Path = field(default_factory=lambda: Path(tempfile.gettempdir()))
    poll_seconds: float = DEFAULT_POLL_SECONDS


class JobRefused(CloudError):
    """The job asked for something this runner will not do. Reported to the cloud as failed."""


def _post(
    config: RunnerConfig, path: str, body: dict[str, Any], transport: Transport | None
) -> Response:
    return request(
        "POST",
        f"{config.url}{path}",
        json_body=body,
        token=config.token,
        transport=transport,
    )


def lease(config: RunnerConfig, *, transport: Transport | None = None) -> Job | None:
    response = _post(
        config,
        "/v1/runner/jobs/lease",
        {
            "runner_id": config.runner_id,
            "labels": list(config.labels),
            "capabilities": ["scan:git", "scan:artifact"],
        },
        transport,
    )
    if response.status == 204:
        return None
    if response.status != 200:
        raise CloudError(f"the lease request was refused ({error_text(response)})")
    body = response.body
    try:
        return Job(
            id=str(body["job_id"]),
            lease_id=str(body["lease_id"]),
            lease_seconds=float(body.get("lease_expires_in", 300)),
            target=dict(body["target"]),
            options=dict(body.get("options") or {}),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CloudError("the leased job was malformed") from exc


def heartbeat(
    config: RunnerConfig,
    job: Job,
    *,
    transport: Transport | None = None,
    stage: str = "",
) -> bool:
    """Extend the lease, and say what the job is doing (`fetching`, `scanning`, `uploading`) so
    the console can show it. False means the cloud has taken the job back: stop working on it."""
    body: dict[str, Any] = {"lease_id": job.lease_id}
    if stage:
        body["stage"] = stage
    try:
        return (
            _post(
                config,
                f"/v1/runner/jobs/{job.id}/heartbeat",
                body,
                transport,
            ).status
            == 200
        )
    except CloudError:
        return False


def report(
    config: RunnerConfig,
    job: Job,
    outcome: dict[str, Any],
    *,
    transport: Transport | None = None,
) -> None:
    response = _post(
        config,
        f"/v1/runner/jobs/{job.id}/result",
        {"lease_id": job.lease_id, **outcome},
        transport,
    )
    if response.status not in (200, 202, 204):
        raise CloudError(f"the job result was refused ({error_text(response)})")


class _Heartbeat:
    """Keeps the lease alive from a background thread while a scan runs."""

    def __init__(
        self, config: RunnerConfig, job: Job, transport: Transport | None
    ) -> None:
        self.lost = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._beat, args=(config, job, transport), daemon=True
        )

    def _beat(
        self, config: RunnerConfig, job: Job, transport: Transport | None
    ) -> None:
        interval = max(job.lease_seconds / 3, 1.0)
        while not self._stop.wait(interval):
            if not heartbeat(config, job, transport=transport, stage="scanning"):
                self.lost.set()
                return

    def __enter__(self) -> _Heartbeat:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


def _check_host(url: str, config: RunnerConfig) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise JobRefused(f"only https targets are fetched, not {parsed.scheme}")
    if (parsed.hostname or "") not in config.allowed_hosts:
        raise JobRefused(f"{parsed.hostname} is not on this runner's allowed hosts")
    if parsed.username or parsed.password:
        raise JobRefused(
            "a target URL must not carry credentials; the job supplies a token separately"
        )
    return parsed


def fetch_git(
    target: dict[str, Any],
    config: RunnerConfig,
    into: Path,
    *,
    run: Callable[..., Any] | None = None,
) -> Path:
    parsed = _check_host(str(target.get("url", "")), config)
    ref = str(target.get("ref", "") or "")
    if ref.startswith("-") or any(c in ref for c in " \t\n\\"):
        raise JobRefused("the job's ref is not a branch, tag or commit name")
    destination = into / "repo"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(into),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": "https",
    }
    command = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never",
        "-c", "core.symlinks=false",
        "-c", "submodule.recurse=false",
    ]  # fmt: skip
    token = target.get("token")
    if isinstance(token, str) and token:
        # A short-lived clone token from the SCM app installation, sent as a header for this one
        # host and never written into the URL, the config or the process's argument list.
        environment["GIT_CONFIG_COUNT"] = "1"
        environment["GIT_CONFIG_KEY_0"] = f"http.https://{parsed.hostname}/.extraheader"
        import base64

        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        environment["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {basic}"
    url = urllib.parse.urlunsplit(parsed)
    if EXACT_REVISION.match(ref):
        # A commit or a pull request's ref is not something `clone --branch` can name: fetch
        # exactly that revision, one commit deep, into an empty repository and check it out.
        # The origin remote is recorded as a clone records it, so the scan names the repository
        # by its URL and not by the workspace directory.
        in_repo = [*command, "-C", str(destination)]
        steps = [
            [*command, "init", "-q", "--", str(destination)],
            [*in_repo, "remote", "add", "origin", url],
            [*in_repo, "fetch", "--depth", "1", "--no-tags", "origin", ref],
            [*in_repo, "checkout", "-q", "--detach", "FETCH_HEAD"],
        ]
    else:
        clone = [*command, "clone", "--depth", "1", "--no-tags", "--single-branch"]
        if ref:
            clone += ["--branch", ref]
        steps = [[*clone, "--", url, str(destination)]]
    for step in steps:
        completed = (run or subprocess.run)(
            step,
            env=environment,
            capture_output=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
        )
        if completed.returncode != 0:
            raise JobRefused(f"the clone failed (git exited {completed.returncode})")
    return destination


def fetch_artifact(
    target: dict[str, Any],
    config: RunnerConfig,
    into: Path,
    *,
    opener: Callable[..., Any] | None = None,
) -> Path:
    parsed = _check_host(str(target.get("url", "")), config)
    expected = str(target.get("sha256", "")).lower()
    if len(expected) != 64:
        raise JobRefused("an artefact job must name the artefact's sha256")
    name = Path(parsed.path).name or "artifact"
    destination = into / name
    digest = hashlib.sha256()
    total = 0
    url = urllib.parse.urlunsplit(parsed)
    request_object = urllib.request.Request(
        url, headers={"User-Agent": "cordon-runner"}
    )  # noqa: S310
    with (
        (opener or urllib.request.urlopen)(request_object, timeout=60) as response,
        destination.open("wb") as handle,
    ):
        for chunk in iter(lambda: response.read(1 << 20), b""):
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise JobRefused("the artefact is larger than the runner accepts")
            digest.update(chunk)
            handle.write(chunk)
    if digest.hexdigest() != expected:
        raise JobRefused("the artefact does not match the sha256 the job named")
    return destination


def execute(
    job: Job,
    config: RunnerConfig,
    *,
    transport: Transport | None = None,
    fetchers: dict[str, Callable[..., Path]] | None = None,
    alive: Callable[[], bool] = lambda: True,
) -> dict[str, Any]:
    """Run one job to an outcome. Never raises: every failure becomes a reported outcome."""
    from cordon_scanner import Scanner
    from cordon_scanner.cloud import auth, results
    from cordon_scanner.core.config import Config
    from cordon_scanner.core.policy import PolicyGate

    fetch: dict[str, Callable[..., Path]] = {
        "git": fetch_git,
        "artifact": fetch_artifact,
        **(fetchers or {}),
    }
    workspace = Path(tempfile.mkdtemp(prefix="cordon-job-", dir=config.work_dir))
    try:
        kind = str(job.target.get("type", ""))
        if kind not in fetch:
            raise JobRefused(f"this runner does not handle {kind!r} targets")
        if not heartbeat(config, job, transport=transport, stage="fetching"):
            return {
                "status": "abandoned",
                "error": "the lease was lost before the fetch",
            }
        target = fetch[kind](job.target, config, workspace)
        if not alive() or not heartbeat(
            config, job, transport=transport, stage="scanning"
        ):
            return {
                "status": "abandoned",
                "error": "the lease was lost before the scan",
            }
        overrides: dict[str, Any] = {"use_cache": False}
        if job.options.get("online"):
            overrides["offline"] = False
        with _Heartbeat(config, job, transport) as beating:
            result = Scanner(Config.default().with_overrides(**overrides)).scan(target)
        if beating.lost.is_set():
            return {
                "status": "abandoned",
                "error": "the lease was lost during the scan",
            }
        verdict = PolicyGate.evaluate(result, Config.default().policy)
        heartbeat(config, job, transport=transport, stage="uploading")
        credentials = auth.Credentials(
            url=config.url,
            org=str(job.options.get("org", "")),
            access_token=config.token,
            expires_at=time.time() + 600,
        )
        receipt = results.upload(
            result,
            credentials,
            exit_code=int(verdict.exit_code),
            reason=str(verdict.reason),
            transport=transport,
        )
        return {
            "status": "succeeded",
            "exit_code": int(verdict.exit_code),
            "scan_id": receipt.scan_id,
        }
    except JobRefused as exc:
        return {"status": "refused", "error": str(exc)}
    except CloudError as exc:
        return {"status": "failed", "error": str(exc)}
    except Exception as exc:
        return {
            "status": "failed",
            "error": f"{type(exc).__name__} while running the job",
        }
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def serve(
    config: RunnerConfig,
    *,
    once: bool = False,
    transport: Transport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = print,
) -> int:
    """Lease, run and report until stopped. SIGTERM finishes the current job, then exits."""
    stopping = {"now": False}

    def stop(*_: Any) -> None:
        stopping["now"] = True
        log("stopping after the current job")

    previous = signal.signal(signal.SIGTERM, stop) if not once else None
    idle = config.poll_seconds
    handled = 0
    try:
        while not stopping["now"]:
            ceiling = MAX_IDLE_POLL_SECONDS
            try:
                job = lease(config, transport=transport)
            except CloudError as exc:
                log(f"lease failed: {exc}; retrying in {idle:.0f}s")
                job = None
                ceiling = MAX_POLL_SECONDS
            if job is None:
                if once:
                    return handled
                sleep(idle)
                idle = min(idle * 2, max(ceiling, config.poll_seconds))
                continue
            idle = config.poll_seconds
            log(f"job {job.id}: {job.target.get('type')} target")
            outcome = execute(
                job, config, transport=transport, alive=lambda: not stopping["now"]
            )
            try:
                report(config, job, outcome, transport=transport)
            except CloudError as exc:
                log(f"job {job.id}: the result could not be reported ({exc})")
            log(f"job {job.id}: {outcome['status']}")
            handled += 1
            if once:
                return handled
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
    return handled


__all__ = [
    "Job",
    "JobRefused",
    "RunnerConfig",
    "execute",
    "fetch_artifact",
    "fetch_git",
    "heartbeat",
    "lease",
    "report",
    "serve",
]
