"""Running a package under isolation and recording what it did.

The unit of work is an install, because that is where the attack is: a
lifecycle script runs as the developer, with their environment, between typing
a command and getting a prompt back. So the package is installed inside the
container with lifecycle scripts *enabled* -- disabling them would remove the
only thing worth watching.

**What is observed.** The container's filesystem changes, its exit status, its
output, and -- where the host permits it -- the syscalls the install made.

Tracing is `strace -f` on `execve` and `connect`, baked into the prepared image
and attached to the install command. Those two are the ones that map onto the
capability model: `execve` is what the package *ran*, which is the difference
between an install that compiled an extension and one that shelled out to
`curl`; `connect` is what it *tried to reach*, and it is more informative here
than it would be on a normal machine, because the container has no network at
all. A connect to an address that could never succeed is intent recorded
without the payload ever arriving.

**And what is not.** Tracing needs `CAP_SYS_PTRACE` and a seccomp policy that
permits `ptrace`, and a host that refuses either produces a run with no trace.
That case is reported as "not traced" rather than as "nothing was executed" --
which is the same invariant the static side is built on, that a check which did
not run must never look like a check that found nothing.

What filesystem effects and a network-free run establish on their own is still
worth having, and still holds where tracing is unavailable. A package that
writes outside its own install tree has done something an install should not. A
package that fails only when the network is removed needed the network at
install time, which is the dropper precondition. And a package that writes to a
persistence location has said what it is for.

**Every observation is what happened, not what might.** Findings from here carry
confirmed confidence, because the thing was run and the effect was recorded --
which is exactly the property the static tiers cannot have.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass, field

from cordon_sandbox.fetch import Artefact
from cordon_sandbox.isolation import Backend, IsolationError

BASE_IMAGES = {"pypi": "python:3.12-slim", "npm": "node:20-slim"}

PREPARED_IMAGE = "cordon-sandbox-base"
IMAGE_GENERATION = "2"
"""Bumped whenever the prepared image's contents change.

The image is cached by tag and reused across runs, so adding `strace` to it
without changing the tag would mean every machine that had already built the
image kept running untraced -- and reporting, in its guarantees, that it was
tracing."""
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

TRACE_SENTINEL = "---cordon-syscall-trace---"
"""Marks where the install's own output ends and the trace begins.

The trace is written to a file inside the container and printed after the
install finishes, rather than copied out afterwards: `/work` is a tmpfs, and a
tmpfs is gone the moment the container stops, so there is nothing left to copy
by the time the run is over."""

TRACED_CALLS = "execve,connect"
"""The two syscalls that map onto the capability model.

`execve` is what the package ran. `connect` is what it tried to reach, which is
more informative here than on a normal machine because there is no network to
reach it over: the call is recorded and the payload never arrives. Tracing
`openat` as well was tried and produces tens of thousands of lines per install,
none of which say anything a filesystem diff does not."""

MAX_TRACE_BYTES = 512 << 10
"""How much of the trace to read back. A build that execs ten thousand
compilers is a build, not a finding, and the first half-megabyte says so."""

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

    traced: bool = False
    """Whether a syscall trace was actually produced.

    Distinct from the backend asking for one. A host that refuses `ptrace`
    yields an empty trace, and reporting that as "nothing was executed" would
    be the one mistake this project is organised against."""


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

    tag = f"{PREPARED_IMAGE}:{ecosystem}-{IMAGE_GENERATION}"
    if _run([backend.command, "image", "inspect", tag], timeout=60).returncode == 0:
        return tag

    dockerfile = f"FROM {base}\n"
    # `strace` is the tracer. Installed here, while the network is still
    # allowed, for the same reason the build tooling is: the container that
    # runs the package has none.
    dockerfile += (
        "RUN apt-get update && apt-get install -y --no-install-recommends strace "
        "&& rm -rf /var/lib/apt/lists/*\n"
    )
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


def traced_command(command: str) -> str:
    """The install command with a tracer around it, and the trace printed after.

    Written as one shell line rather than as a wrapper script because the
    container is created with a fixed argv and nothing is mounted into it --
    there is nowhere to put a script. The install's exit status is preserved
    across the trace dump, since a non-zero exit is itself an observation.

    A failure to start the tracer is not a failure of the run. `strace` exits
    non-zero when the host denies `ptrace`, and in that case this falls through
    to running the install untraced: an install that did not happen is worth
    less than an install that happened unobserved, and the empty trace is what
    tells the caller which of the two it got.
    """
    trace_file = "/work/.cordon-trace"
    return (
        f"if strace -f -qq -o {trace_file} -e trace={TRACED_CALLS} "
        f"-s 200 sh -c {shlex.quote(command)}; then rc=0; else rc=$?; fi; "
        f"if [ $rc -ne 0 ] && [ ! -s {trace_file} ]; then "
        f"sh -c {shlex.quote(command)}; rc=$?; fi; "
        f"echo {shlex.quote(TRACE_SENTINEL)}; "
        f"head -c {MAX_TRACE_BYTES} {trace_file} 2>/dev/null; "
        f"exit $rc"
    )


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
            # A stronger OCI runtime where one is configured. See
            # `isolation.py`: this is asked of the runtime rather than of PATH,
            # because naming a runtime the daemon does not know fails the
            # creation, and "a better boundary was available" would become
            # "nothing ran".
            *(("--runtime", backend.runtime) if backend.runtime else ()),
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
            # Everything is dropped and exactly one thing is added back:
            # tracing needs it, and a payload that reaches it is confined to a
            # container that already has no network and no host mounts. The
            # seccomp default profile blocks `ptrace` on older kernels, so this
            # is a request that may not be granted -- which is why whether a
            # trace was produced is recorded rather than assumed.
            "--cap-add",
            "SYS_PTRACE",
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
            (f"cat > {shlex.quote(f'/work/{artefact.filename}')} && {traced_command(command)}"),
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

    installer_output, trace = _split_trace(output)
    traced = bool(trace.strip())
    observed = Backend(
        command=backend.command,
        version=backend.version,
        rootless=backend.rootless,
        runtime=backend.runtime,
        traces_syscalls=traced,
    )

    observations = _interpret(changes.stdout or "", status, timed_out)
    observations.extend(_interpret_trace(trace, traced=traced))

    return Run(
        backend=observed,
        image=image,
        command=command,
        exit_status=status,
        timed_out=timed_out,
        observations=tuple(observations),
        output_tail=installer_output[-2000:],
        guarantees=observed.guarantees,
        traced=traced,
    )


def _split_trace(output: str) -> tuple[str, str]:
    """The installer's own output and the trace, separated at the sentinel.

    The sentinel may not be there at all -- a container killed at the wall
    clock never printed it -- in which case everything is the installer's
    output and the trace is empty, which is exactly what the caller must be
    told."""
    head, found, tail = output.partition(TRACE_SENTINEL)
    return (head, tail) if found else (output, "")


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


# `strace -f` prefixes each line with a pid, then the call. The argv of an
# `execve` is the second argument, a bracketed list; the address of a `connect`
# is inside the sockaddr struct. Both are matched loosely on purpose: strace's
# output format varies between versions, and a parser that demanded one shape
# would silently report "nothing executed" on the versions it did not know.
_EXECVE = re.compile(r'execve\("([^"]{1,400})"')
_CONNECT_INET = re.compile(r'sin_addr=inet_addr\("([0-9.]{7,15})"\)')
_CONNECT_INET6 = re.compile(r'inet_pton\(AF_INET6, "([0-9A-Fa-f:]{2,45})"')
_CONNECT_PORT = re.compile(r"sin6?_port=htons\((\d{1,5})\)")

INSTALL_TOOLING = (
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/usr/bin/env",
    "/usr/bin/python",
    "/usr/local/bin/python",
    "/usr/bin/node",
    "/usr/local/bin/node",
    "/usr/bin/gcc",
    "/usr/bin/cc",
    "/usr/bin/ld",
    "/usr/bin/as",
    "/usr/bin/make",
    "/usr/bin/strace",
)
"""What an ordinary install execs.

An install that compiles an extension runs a compiler, a linker and a shell,
and reporting those would be reporting that a build happened. What is worth
saying is what it ran *besides* these -- `curl`, `wget`, `chmod`, a binary it
unpacked itself."""


def _interpret_trace(trace: str, *, traced: bool) -> list[Observation]:
    """What the syscall trace says the install did.

    The two things asked of it are what ran and what it tried to reach, and
    both are reported as facts about the run rather than as conclusions: an
    `execve` of `curl` during an install is worth a person's attention and is
    not, on its own, proof of anything.
    """
    if not traced:
        return [
            Observation(
                kind="not_traced",
                detail=(
                    "no syscall trace was produced, so what the install executed "
                    "and what it tried to reach were not observed. This is not "
                    "the same as it having done neither: the host refused "
                    "ptrace, or the run ended before the trace was read"
                ),
            )
        ]

    observations: list[Observation] = []

    executed = [
        path
        for path in dict.fromkeys(_EXECVE.findall(trace))
        if not path.startswith(INSTALL_TOOLING)
    ]
    if executed:
        shown = ", ".join(executed[:8])
        observations.append(
            Observation(
                kind="executed",
                detail=(
                    f"the install ran {len(executed)} program(s) that are not "
                    f"the shell, interpreter or toolchain a build uses: {shown}"
                ),
            )
        )

    addresses = dict.fromkeys([*_CONNECT_INET.findall(trace), *_CONNECT_INET6.findall(trace)])
    # Loopback and the unspecified address are how a build talks to itself, not
    # how it talks to anybody. This is reading addresses out of a trace, not
    # binding one.
    local = ("127.", "::1", "0.0.0.0")  # noqa: S104
    remote = [a for a in addresses if not a.startswith(local)]
    if remote:
        ports = ", ".join(dict.fromkeys(_CONNECT_PORT.findall(trace)))
        shown = ", ".join(remote[:8])
        observations.append(
            Observation(
                kind="attempted_egress",
                detail=(
                    f"the install tried to reach {len(remote)} address(es) "
                    f"({shown}) on port(s) {ports or 'unknown'}. There is no "
                    f"network interface in this container, so nothing arrived "
                    f"-- what is recorded is that it tried"
                ),
            )
        )

    return observations


__all__ = [
    "INSTALL_TOOLING",
    "MAX_TRACE_BYTES",
    "MEMORY",
    "PERSISTENCE_PREFIXES",
    "PIDS",
    "TRACED_CALLS",
    "TRACE_SENTINEL",
    "WALL_CLOCK_SECONDS",
    "Observation",
    "Run",
    "install_command",
    "observe",
    "traced_command",
]
