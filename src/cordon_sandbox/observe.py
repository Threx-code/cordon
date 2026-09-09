"""Running a package under isolation and recording what it did.

The unit of work is an install, because that is where the attack is: a
lifecycle script runs as the developer, with their environment, between typing
a command and getting a prompt back. So the package is installed inside the
container with lifecycle scripts *enabled* -- disabling them would remove the
only thing worth watching.

**What is observed, and what is not.** This records the container's filesystem
changes, its exit status and its output. It does not trace syscalls. That is a
real limitation and is stated in the result rather than left for the reader to
discover: `execve` and `connect` are what map cleanly onto the capability
model, and reading them portably needs either a tracing runtime or a
kernel-level probe, neither of which is present on an ordinary machine.

What filesystem effects and a network-free run *do* establish is worth having.
A package that writes outside its own install tree has done something an install
should not. A package that fails only when the network is removed needed the
network at install time, which is the dropper precondition. And a package that
writes to a persistence location has said what it is for.

**Every observation is what happened, not what might.** Findings from here carry
confirmed confidence, because the thing was run and the effect was recorded --
which is exactly the property the static tiers cannot have.
"""

from __future__ import annotations

import shlex
import subprocess
import uuid
from dataclasses import dataclass, field

from cordon_sandbox.fetch import Artefact
from cordon_sandbox.isolation import Backend, IsolationError

BASE_IMAGES = {"pypi": "python:3.12-slim", "npm": "node:20-slim"}

PREPARED_IMAGE = "cordon-sandbox-base"
"""Tag for the image the analysis runs in.

Built once, with network, from a base image plus the build tooling an offline
install needs. Preparing it is not a compromise of the isolation: the build runs
*our* Dockerfile and installs setuptools from PyPI, and the package being
analysed is not present at any point. The container that runs the package has no
network at all.

Without this the analysis fails on every source distribution. `python:3.12-slim`
no longer ships setuptools, pip's build isolation would fetch it, and there is
no network to fetch it over -- so `six` reported "install failed" for the same
reason `curl`-based malware would, which is a signal that cannot distinguish
anything."""

PREPARE_TIMEOUT = 600.0

WALL_CLOCK_SECONDS = 120
"""How long the install may take before it is killed.

A payload that sleeps past this defeats the observation, which is the arms race
the static anti-analysis rules exist to cover: a package that waits out an
analysis window lights those up instead. The two tiers cover each other, and
neither is asked to be complete."""

MEMORY = "512m"
PIDS = "128"

PERSISTENCE_PREFIXES = (
    "/etc/cron",
    "/etc/systemd",
    "/etc/rc",
    "/root/.bashrc",
    "/root/.profile",
    "/usr/local/bin",
    "/etc/ld.so",
)
"""Paths whose modification outlives the install.

An install writes into its own package tree. Writing here is arranging to run
again, or to be run by something else, which is a different intent."""


@dataclass(frozen=True, slots=True)
class Observation:
    """One thing the package was seen to do."""

    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class Run:
    """The record of one isolated execution."""

    backend: Backend
    image: str
    command: str
    exit_status: int
    timed_out: bool
    observations: tuple[Observation, ...] = ()
    output_tail: str = ""
    guarantees: tuple[str, ...] = field(default_factory=tuple)


def _run(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  (fixed argv built here, never a shell)
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def prepare_image(backend: Backend, ecosystem: str) -> str:
    """Build (or reuse) the image the analysis runs in.

    Deliberately a separate phase, and deliberately the only one with network
    access. It installs build tooling from the ecosystem's own registry; the
    package under analysis is not involved, and the container that later runs
    that package has `--network none`.
    """
    base = BASE_IMAGES.get(ecosystem)
    if base is None:
        raise IsolationError(f"no base image is defined for {ecosystem!r}")

    tag = f"{PREPARED_IMAGE}:{ecosystem}"
    if _run([backend.command, "image", "inspect", tag], timeout=60).returncode == 0:
        return tag

    dockerfile = f"FROM {base}\n"
    if ecosystem == "pypi":
        # Everything an offline `pip install` of a source distribution needs.
        # Fetching these at analysis time is impossible by design, so they are
        # baked in while the network is still allowed.
        dockerfile += "RUN pip install --no-cache-dir setuptools wheel\n"

    built = subprocess.run(  # noqa: S603  (fixed argv)
        [backend.command, "build", "-t", tag, "-"],
        input=dockerfile.encode("utf-8"),
        capture_output=True,
        timeout=PREPARE_TIMEOUT,
        check=False,
    )
    if built.returncode != 0:
        raise IsolationError(
            "the analysis image could not be built, so nothing was run: "
            + built.stderr.decode("utf-8", "replace").strip()[-400:]
        )
    return tag


def install_command(ecosystem: str, filename: str) -> tuple[str, str]:
    """The image and command that installs an artefact already inside the container.

    Installed from the local file with the index disabled, because the container
    has no network. Fetching happens before isolation is established -- see
    `fetch.py` for why the two are separate.

    Lifecycle scripts are deliberately left enabled. They are the reason to run
    anything at all: `--ignore-scripts` would produce a clean observation of a
    package whose whole payload is a postinstall hook.
    """
    quoted = shlex.quote(f"/work/{filename}")
    if ecosystem == "npm":
        return (
            BASE_IMAGES["npm"],
            f"HOME=/work npm install --offline --no-audit --no-fund --no-save --cache /work/npm {quoted}",
        )
    if ecosystem == "pypi":
        return (
            BASE_IMAGES["pypi"],
            # `--no-cache-dir` and a writable HOME because the root filesystem
            # is read-only: pip writes its cache under $HOME and fails there,
            # which looked like the package's install code failing.
            f"HOME=/work pip install --no-input --disable-pip-version-check "
            f"--no-cache-dir --no-index --no-deps --no-build-isolation "
            f"--target /work/site {quoted}",
        )
    raise IsolationError(f"no install command is defined for {ecosystem!r}")


def observe(backend: Backend, ecosystem: str, artefact: Artefact) -> Run:
    """Install an already-downloaded package under isolation and record what changed.

    The container is created, the artefact is copied into it, and it is started
    separately from the inspection so the filesystem can be diffed after it
    exits. It is removed either way -- a container left behind holding a
    payload's output is a mess the caller did not ask for.

    The artefact is copied rather than mounted. A bind mount would make a host
    path reachable from inside, which is the one thing the isolation is for.
    """
    image = prepare_image(backend, ecosystem)
    _, command = install_command(ecosystem, artefact.filename)
    name = f"cordon-sandbox-{uuid.uuid4().hex[:12]}"

    create = _run(
        [
            backend.command,
            "create",
            "--name",
            name,
            # The isolation, stated as flags. Each one is a claim the report
            # repeats, so they are here rather than spread across the file.
            "--network",
            "none",
            # The filesystem is writable on purpose. See `isolation.py`: a
            # read-only root stops a payload writing to /etc/cron.d, which
            # turns the observation this component exists for into an
            # indistinguishable "the install failed". The container is
            # destroyed at the end of the run, and no host path is mounted at
            # any point, which is where the actual protection comes from.
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            MEMORY,
            "--pids-limit",
            PIDS,
            # A writable layer is needed for the install itself; it is a tmpfs
            # so nothing survives the container, and no host path is mounted at
            # any point.
            "--tmpfs",
            # A path inside the container, not on this machine. The rule that
            # fires here is about host temporary files; nothing on the host is
            # touched, which is the property being configured.
            "/tmp:rw,noexec,nosuid,size=256m",  # noqa: S108
            "--workdir",
            "/work",
            "--tmpfs",
            "/work:rw,exec,nosuid,size=256m",
            # Stdin is how the artefact gets in, rather than a bind mount. A
            # mount would make a host path reachable from inside, which is the
            # one thing this isolation is for.
            "--interactive",
            image,
            "sh",
            "-c",
            f"cat > {shlex.quote(f'/work/{artefact.filename}')} && {command}",
        ],
        timeout=60,
    )
    if create.returncode != 0:
        raise IsolationError(
            f"the container could not be created, so nothing was run: "
            f"{(create.stderr or create.stdout).strip()[:400]}"
        )

    timed_out = False
    try:
        started = subprocess.run(  # noqa: S603  (fixed argv)
            [backend.command, "start", "--attach", "--interactive", name],
            input=artefact.data,
            capture_output=True,
            timeout=WALL_CLOCK_SECONDS,
            check=False,
        )
        status = started.returncode
        output = started.stdout.decode("utf-8", "replace") + started.stderr.decode(
            "utf-8", "replace"
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        status, output = -1, ""
        _run([backend.command, "kill", name], timeout=30)

    changes = _run([backend.command, "diff", name], timeout=60)
    _run([backend.command, "rm", "-f", name], timeout=60)

    return Run(
        backend=backend,
        image=image,
        command=command,
        exit_status=status,
        timed_out=timed_out,
        observations=tuple(_interpret(changes.stdout or "", status, timed_out)),
        output_tail=output[-2000:],
        guarantees=backend.guarantees,
    )


def _interpret(diff: str, status: int, timed_out: bool) -> list[Observation]:
    """Turn a container filesystem diff into things worth saying.

    `docker diff` prints one path per line prefixed by A, C or D. An install
    changes a great many paths inside its own package tree, and none of that is
    interesting -- what is interesting is anything outside it.
    """
    observations: list[Observation] = []

    if timed_out:
        observations.append(
            Observation(
                kind="timeout",
                detail=(
                    f"the install did not finish within {WALL_CLOCK_SECONDS}s and was killed, "
                    f"so what it did after that point was not observed"
                ),
            )
        )

    persistence: list[str] = []
    for line in diff.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        _, path = parts
        if path.startswith(PERSISTENCE_PREFIXES):
            persistence.append(path)

    if persistence:
        shown = ", ".join(sorted(set(persistence))[:8])
        observations.append(
            Observation(
                kind="persistence",
                detail=(
                    f"the install wrote to {len(set(persistence))} path(s) that outlive it: {shown}"
                ),
            )
        )

    if status != 0 and not timed_out:
        # The artefact is already present and the index is disabled, so this is
        # not the installer failing to reach a registry -- that was the first
        # version of this component, where every package failed at the fetch
        # step and this observation fired on all of them. What is left is the
        # package's own install code failing, which for a package that needs
        # the network at install time is the dropper precondition. An ordinary
        # build failure looks the same from here, so this reports what happened
        # rather than what it means.
        observations.append(
            Observation(
                kind="install_failed",
                detail=(
                    f"the install exited {status} with the artefact already present and "
                    f"no network interface. Its own install code failed; a package that "
                    f"needs the network at install time fails exactly this way, and so "
                    f"does one with an ordinary build error"
                ),
            )
        )

    return observations


__all__ = [
    "MEMORY",
    "PERSISTENCE_PREFIXES",
    "PIDS",
    "WALL_CLOCK_SECONDS",
    "Observation",
    "Run",
    "install_command",
    "observe",
]
