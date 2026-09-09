"""Establishing isolation, or refusing to proceed.

This module answers one question: is there somewhere safe to run this? Every
other part of the component depends on the answer being honest, so the failure
mode is chosen carefully -- it raises rather than returning a degraded option.

**Why refusal is the feature.** The person running this has decided to execute a
package they do not trust. If the isolation they think they have is not there,
running it anyway harms them more than not running it at all, because they will
read the result as "it did nothing" rather than "it ran on my laptop". So a
missing backend is an error, not a warning, and there is no flag to override it.

**What counts as isolation here.** A container runtime with the network removed,
no host filesystem mounted, dropped capabilities, no-new-privileges, a process
ceiling and a memory ceiling. That is weaker than a microVM and it is stated as
such: a container boundary is a kernel boundary, and a kernel exploit crosses
it. It is what is available on an ordinary developer machine and a CI runner
without privileged setup, and the alternative -- offering nothing until a
hypervisor is present -- would mean the residual never gets looked at.

**Except where a stronger boundary is already installed.** gVisor's `runsc`
intercepts the guest's syscalls in userspace and serves them from its own
kernel, so the host kernel sees a small, fixed surface rather than the whole
syscall table. Where it is configured in the runtime this uses it, because the
cost is one flag and the difference is the class of bug that gets you out. It
is not required -- demanding it would put this back to running on nothing --
and which boundary was actually used is recorded with the result, since a
reader deciding what an observation is worth needs to know which one it was.

**The container filesystem is writable, and that is deliberate.** The first
version made the root read-only, which reads as stronger and was in fact
useless: a payload that writes to `/etc/cron.d` simply failed, and the run
reported "the install failed" rather than "it tried to persist". A sandbox that
prevents the behaviour it exists to observe has been configured into
uselessness. Nothing on the host is reachable either way -- that is what the
absent mounts do -- and the container is destroyed when the run ends.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

RUNTIMES = ("podman", "docker")
"""Runtimes tried in order.

Podman first because it runs rootless by default, so a container escape lands as
an unprivileged user rather than as root. Where both are present that is the
better default, and where only Docker is present it is still isolation."""

PROBE_TIMEOUT = 10.0
"""How long to wait for a runtime to say it is working.

A runtime that is installed but whose daemon is not running would otherwise hang
the check, and a hang here is indistinguishable to the user from a sandbox that
is thinking."""


class IsolationError(RuntimeError):
    """Isolation could not be established, so nothing was run.

    Deliberately not recoverable by the caller into "run it anyway". There is no
    degraded mode: the whole value of this component is that the code ran
    somewhere it could not reach anything.
    """


GVISOR_RUNTIME = "runsc"
"""gVisor's OCI runtime, as `--runtime` names it."""


@dataclass(frozen=True, slots=True)
class Backend:
    """A runtime that can host the analysis, and what it guarantees."""

    command: str
    version: str
    rootless: bool

    runtime: str | None = None
    """An OCI runtime to ask for by name, when one stronger than the default is
    configured. `None` means the runtime's own default, which is `runc`."""

    traces_syscalls: bool = False
    """Whether the run can be traced.

    Recorded on the backend rather than assumed, because tracing needs
    `CAP_SYS_PTRACE` and a seccomp profile that permits `ptrace`, and a host
    that refuses either produces a run with no trace. The difference between
    "nothing called execve" and "nothing was watching" is the difference this
    whole project is built around, so it is carried rather than inferred."""

    @property
    def guarantees(self) -> tuple[str, ...]:
        """What this backend does and does not promise, in the report's words.

        Carried with the result rather than described in documentation, because
        a reader deciding what an observation is worth needs to know what the
        boundary was -- and the boundary differs between a rootless and a
        root-owned runtime.
        """
        common: tuple[str, ...] = (
            "no network interface",
            "no host filesystem mounted",
            "container filesystem is writable but discarded afterwards",
            "all Linux capabilities dropped",
            "no new privileges",
            "process and memory ceilings",
        )
        if self.runtime == GVISOR_RUNTIME:
            common = (
                *common,
                "gVisor: the guest's syscalls are served by a userspace kernel, "
                "so the host kernel sees a small fixed surface rather than the "
                "whole syscall table",
            )
        else:
            common = (
                *common,
                "the host kernel is the boundary: a kernel exploit crosses it, "
                "which a virtual machine or gVisor would not allow",
            )

        common = (
            *common,
            "syscalls traced: execve and connect are recorded"
            if self.traces_syscalls
            else "syscalls are NOT traced: what the install executed and what "
            "it tried to reach were not observed",
        )

        if self.rootless:
            return (*common, "runtime is rootless: an escape lands unprivileged")
        return (
            *common,
            "runtime is root-owned: an escape lands as root, which is weaker "
            "than a rootless runtime and much weaker than a virtual machine",
        )


def available_backend() -> Backend:
    """The first working runtime, or `IsolationError` if there is none."""
    tried: list[str] = []

    for runtime in RUNTIMES:
        path = shutil.which(runtime)
        if path is None:
            tried.append(f"{runtime}: not installed")
            continue
        try:
            probe = subprocess.run(  # noqa: S603  (fixed argv, resolved path)
                [path, "version", "--format", "{{.Client.Version}}"],
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            tried.append(f"{runtime}: {type(exc).__name__}")
            continue

        if probe.returncode != 0:
            detail = (probe.stderr or probe.stdout or "").strip().splitlines()
            tried.append(f"{runtime}: not usable ({detail[0] if detail else 'no output'})")
            continue

        return Backend(
            command=path,
            version=(probe.stdout or "").strip() or "unknown",
            rootless=runtime == "podman",
            runtime=GVISOR_RUNTIME if _has_gvisor(path) else None,
        )

    raise IsolationError(
        "no container runtime is available, so the package was not run. "
        "Install podman (preferred, rootless) or docker. This does not fall "
        "back to running the code on this machine: a sandbox that degrades to "
        "no sandbox is worse than none, because you would read the result as "
        "'it did nothing'.\n  " + "\n  ".join(tried)
    )


def _has_gvisor(command: str) -> bool:
    """Whether this runtime has gVisor configured as an OCI runtime.

    Asked of the runtime rather than of `PATH`. `runsc` sitting in a directory
    the daemon does not know about is not a runtime that can be selected, and
    passing `--runtime runsc` on that host fails the container creation --
    which would turn "a stronger boundary is available" into "nothing ran".

    **Every failure is "no".** `docker info` talks to the daemon, so on a
    machine where Docker is installed and not running it hangs until the
    timeout and raises -- and this is called from `available_backend`, whose
    entire job is to answer that situation with a sentence rather than a
    traceback. It went unhandled: a user with Docker installed and stopped got
    `subprocess.TimeoutExpired` out of `cordon-sandbox` instead of the refusal
    that explains what to install. Windows CI, where the daemon is absent, is
    what surfaced it.

    Refusing to answer is also the safe direction. A runtime that cannot say
    whether it has gVisor is used with its default runtime, which is what would
    have happened anyway.
    """
    try:
        probe = subprocess.run(  # noqa: S603  (fixed argv, resolved path)
            [command, "info", "--format", "{{.Runtimes}}"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False

    if probe.returncode != 0:
        return False
    return GVISOR_RUNTIME in (probe.stdout or "")


__all__ = [
    "GVISOR_RUNTIME",
    "PROBE_TIMEOUT",
    "RUNTIMES",
    "Backend",
    "IsolationError",
    "available_backend",
]
