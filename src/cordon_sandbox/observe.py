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

import base64
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass, field

from cordon_sandbox.fetch import Artefact
from cordon_sandbox.isolation import Backend, IsolationError

BASE_IMAGES = {"pypi": "python:3.12-slim", "npm": "node:20-slim"}

PREPARED_IMAGE = "cordon-sandbox-base"
IMAGE_GENERATION = "3"
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
by the time the run is over.

**The package writes to the same output.** A fixed sentinel let any install
print `---cordon-syscall-trace---` itself and hand the observer a forged, empty
trace. So every run appends a random nonce to each sentinel (`Observer.marker`),
and the output is split at the LAST occurrence of each, which is the observer's
own dump at the end. A payload that reads the nonce out of its own process tree
could still forge the channel; that is stated in the run's guarantees, and it
can only hide what the package did - it cannot clear a static finding."""

HOME_SENTINEL = "---cordon-home-listing---"
"""Marks where the trace ends and the listing of the install directory begins.

For the same reason the trace is printed rather than copied: `/work` is a
tmpfs, so it is gone before anything outside the container could look at it."""

LIMITS_SENTINEL = "---cordon-cgroup-limits---"
"""Marks where the listing ends and the run's own cgroup limits begin.

Read back from inside, because asking for a limit is not having one: a rootless
daemon without cgroup delegation accepts `--memory 512m --pids-limit 128` and
discards both, and the guarantee "process and memory ceilings" would then be a
claim about the request rather than the run."""

MEMORY_BYTES = 512 << 20
"""`MEMORY` in bytes, to check the read-back limit against."""

DNS_SENTINEL = "---cordon-dns-queries---"
"""Marks where the limits probe ends and the names the install tried to resolve begin."""

DNS_LOG = "/work/.cordon-dns"
DNS_LOGGER = "/opt/cordon/dnslog"
MAX_DNS_BYTES = 64 << 10

DNS_LOGGERS = {
    # A resolver on 127.0.0.1:53 that records each queried name and answers NXDOMAIN. Nothing is ever
    # forwarded - the container has no network - so the only effect is the record.
    "npm": (
        "const dgram=require('dgram'),fs=require('fs'),out=process.argv[2],s=dgram.createSocket('udp4');\n"
        "s.on('message',(m,r)=>{try{let i=12,l=[];while(i<m.length&&m[i]){const n=m[i];"
        "l.push(m.slice(i+1,i+1+n).toString('latin1'));i+=n+1;}"
        "fs.appendFileSync(out,l.join('.').slice(0,253)+'\\n');"
        "const a=Buffer.from(m.slice(0,512));a[2]=0x81;a[3]=0x83;s.send(a,r.port,r.address);}catch(e){}});\n"
        "s.bind(53,'127.0.0.1');\n"
    ),
    "pypi": (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.bind(('127.0.0.1', 53))\n"
        "while True:\n"
        "    m, a = s.recvfrom(512)\n"
        "    try:\n"
        "        i, labels = 12, []\n"
        "        while i < len(m) and m[i]:\n"
        "            n = m[i]; labels.append(m[i + 1:i + 1 + n].decode('latin1')); i += n + 1\n"
        "        open(sys.argv[1], 'a').write('.'.join(labels)[:253] + '\\n')\n"
        "        r = bytearray(m); r[2], r[3] = 0x81, 0x83; s.sendto(bytes(r), a)\n"
        "    except Exception:\n"
        "        pass\n"
    ),
}
"""What resolves names inside the container, per ecosystem, in the runtime its image already has.

**Why a resolver at all.** The container inherits the daemon's nameserver, and a package manager
resolves names during an install whatever `--offline` says: node's resolver looked up the registry
on every npm install, so a `connect` to the nameserver on port 53 was recorded for every package,
including ones with no install scripts. Reported as egress, that fired on everything - and an
exfiltration finding next to it would have turned the noise into a published false advisory.

Dropping port 53 would have hidden the real thing: a DNS lookup is how many dependency-confusion
payloads call home. So the lookups are captured instead, with the NAME each one asked for, which a
`connect` to a resolver never carried. The package manager's own registry names are attributed to
it (`TOOLCHAIN_DOMAINS`); anything else is what the install tried to reach."""

DNS_LOGGER_COMMAND = {"npm": f"node {DNS_LOGGER}", "pypi": f"python3 {DNS_LOGGER}"}

TOOLCHAIN_DOMAINS = {
    "npm": frozenset({"registry.npmjs.org", "registry.yarnpkg.com"}),
    "pypi": frozenset({"pypi.org", "files.pythonhosted.org", "pypi.python.org"}),
}
"""Names the package manager itself resolves. A lookup of one of these is the toolchain, not the package."""

HOME_DIR = "/work"
"""Where the install runs, and what `$HOME` is set to for both ecosystems.

Both facts matter together, and the combination is why this file grew a second
observation pass. `docker diff` reports the container's writable overlay layer
and a tmpfs is not part of it -- so a package writing `$HOME/.ssh/authorized_keys`
or `$HOME/.bashrc` produced no `persistence` observation at all, while the same
write to `/etc/cron.d` was reported. The diff showed `A /work`, the bare mount
point, and nothing underneath it ever.

That is the failure this component exists to avoid: not a missed rule but a
clean-looking report for a package that was never looked at. Worse in
combination -- on a host that denies `ptrace` the syscall tier is dark too, so
both layers could go quiet on the same install for two unrelated structural
reasons."""

HOME_PERSISTENCE_NAMES = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".cshrc",
        ".kshrc",
        ".ssh",
        ".gnupg",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".curlrc",
        ".wgetrc",
        ".gitconfig",
        ".aws",
    }
)
"""Names under `$HOME` whose creation is arranging for something later.

An install writes its own package tree -- `/work/site` for pip, `/work/npm` for
npm's cache -- and neither is interesting. A shell profile, an authorized key,
a registry credential or a proxy setting in `.npmrc` is a different intent, and
it is the same intent `PERSISTENCE_PREFIXES` names outside `$HOME`.

Deliberately not `.config`, `.local` or `.cache`. pip and npm write those
themselves when `$HOME` points at a directory they own, so a rule naming them
would fire on every ordinary install -- and an observation that fires on
everything is one an analyst learns to scroll past, which is how the real one
gets missed."""

MAX_HOME_LISTING_BYTES = 64 << 10
"""How much of the listing to read back. Bounded like the trace: a package tree
with fifty thousand files is a package tree, and the dotfiles at the top of
`$HOME` are what this pass is for."""

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


#: Severity of each observation kind, on the same scale the static scanner
#: uses, so a CI pipeline can gate a dynamic run with the same threshold it
#: gates a static scan. Persistence and an attempted outbound connection during
#: an install are the shapes a compromised package takes; running a non-toolchain
#: program is suspicious but ordinary in some builds. The two completeness
#: observations -- an untraced run, and an install directory that could not be
#: enumerated -- are medium on purpose: a run that could not be fully watched is
#: not a clean run, and a gate set to fail on medium treats it as the unfinished
#: check it is, which is the same stance the static engine takes toward a scan it
#: could not complete.
OBSERVATION_SEVERITY: dict[str, str] = {
    "persistence": "high",
    "attempted_egress": "high",
    "executed": "medium",
    "timeout": "medium",
    "not_traced": "medium",
    "not_observed": "medium",
    "install_failed": "low",
}

_SEVERITY_ORDER = ("low", "medium", "high", "critical")


class Observer:
    """Installing a package under isolation and reading what it did."""

    @staticmethod
    def observation_severity(kind: str) -> str:
        """The severity of an observation kind, defaulting to low for an unknown one."""
        return OBSERVATION_SEVERITY.get(kind, "low")

    @staticmethod
    def meets_threshold(observations: tuple[Observation, ...], threshold: str) -> bool:
        """Whether any observation is at least as severe as `threshold`."""
        if threshold not in _SEVERITY_ORDER:
            return bool(observations)
        floor = _SEVERITY_ORDER.index(threshold)
        return any(
            _SEVERITY_ORDER.index(Observer.observation_severity(o.kind)) >= floor
            for o in observations
        )

    @staticmethod
    def _run(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603  (fixed argv built here, never a shell)
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    @staticmethod
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
        if Observer._run([backend.command, "image", "inspect", tag], timeout=60).returncode == 0:
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
        # The resolver that records lookups (see DNS_LOGGERS). Base64 so no quoting can break it.
        encoded = base64.b64encode(DNS_LOGGERS[ecosystem].encode("utf-8")).decode("ascii")
        dockerfile += f"RUN mkdir -p /opt/cordon && echo {encoded} | base64 -d > {DNS_LOGGER}\n"

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

    @staticmethod
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

    @staticmethod
    def marker(sentinel: str, nonce: str) -> str:
        """A sentinel for one run. The nonce is random per run, so a package cannot print a marker it
        has not first dug out of its own process tree."""
        return f"{sentinel}{nonce}"

    @staticmethod
    def limits_probe() -> str:
        """Prints the container's own memory and process limits, cgroup v2 first, then v1."""
        return (
            "for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do "
            '[ -r "$f" ] && { printf "memory=%s\\n" "$(cat "$f")"; break; }; done; '
            "for f in /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids/pids.max; do "
            '[ -r "$f" ] && { printf "pids=%s\\n" "$(cat "$f")"; break; }; done'
        )

    @staticmethod
    def limits_enforced(probe: str | None) -> bool | None:
        """Whether the requested ceilings were actually in force: True, False, or None when the probe
        never arrived (a killed container) and nothing can be said."""
        if probe is None:
            return None
        values = dict(
            line.strip().split("=", 1) for line in probe.splitlines() if "=" in line.strip()
        )
        memory, pids = values.get("memory", ""), values.get("pids", "")
        if not memory and not pids:
            return None
        memory_ok = memory.isdigit() and 0 < int(memory) <= MEMORY_BYTES * 2
        pids_ok = pids.isdigit() and 0 < int(pids) <= int(PIDS) * 2
        return memory_ok and pids_ok

    @staticmethod
    def interpret_dns(log: str | None, ecosystem: str) -> list[Observation]:
        """The names the install tried to resolve, less the package manager's own and local lookups."""
        if not log:
            return []
        toolchain = TOOLCHAIN_DOMAINS.get(ecosystem, frozenset())
        names = []
        for raw in log.splitlines():
            name = raw.strip().lower().rstrip(".")
            if not name or "." not in name or name in toolchain:
                continue  # empty, or a single label (the container's own name), or the toolchain
            if name.endswith((".in-addr.arpa", ".ip6.arpa", ".localhost")) or name == "localhost":
                continue
            if not re.fullmatch(r"[a-z0-9_.-]{1,253}", name):
                name = name.encode("unicode_escape").decode("ascii")[:120]
            names.append(name)
        unique = list(dict.fromkeys(names))
        if not unique:
            return []
        shown = ", ".join(unique[:8])
        return [
            Observation(
                kind="attempted_egress",
                detail=(
                    f"the install tried to resolve {len(unique)} name(s): {shown}. Each lookup was "
                    f"answered NXDOMAIN inside the container and none left it - what is recorded is "
                    f"that it asked"
                ),
            )
        ]

    @staticmethod
    def container_command(filename: str, command: str, nonce: str, logger: str) -> str:
        """What the container runs: write the artefact from stdin, then the traced install.

        The traced part is GROUPED. It starts the lookup recorder with a trailing `&`, and in
        `A && B & C` the shell backgrounds `A && B` - so ungrouped, writing the artefact went to the
        background with the recorder and the install began on a half-written file."""
        return (
            f"cat > {shlex.quote(f'/work/{filename}')} && "
            f"{{ {Observer.traced_command(command, nonce, logger)}; }}"
        )

    @staticmethod
    def traced_command(command: str, nonce: str = "", logger: str = "") -> str:
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
        # The lookup recorder starts first, outside the tracer, so its own syscalls are not the
        # install's; a moment lets it bind before anything resolves.
        start_logger = f"{logger} {DNS_LOG} >/dev/null 2>&1 & sleep 0.3; " if logger else ""
        return (
            f"{start_logger}"
            f"if strace -f -qq -o {trace_file} -e trace={TRACED_CALLS} "
            f"-s 200 sh -c {shlex.quote(command)}; then rc=0; else rc=$?; fi; "
            f"if [ $rc -ne 0 ] && [ ! -s {trace_file} ]; then "
            f"sh -c {shlex.quote(command)}; rc=$?; fi; "
            f"echo {shlex.quote(Observer.marker(TRACE_SENTINEL, nonce))}; "
            f"head -c {MAX_TRACE_BYTES} {trace_file} 2>/dev/null; "
            f"echo {shlex.quote(Observer.marker(HOME_SENTINEL, nonce))}; "
            f"{Observer.home_listing()}; "
            f"echo {shlex.quote(Observer.marker(LIMITS_SENTINEL, nonce))}; "
            f"{Observer.limits_probe()}; "
            f"echo {shlex.quote(Observer.marker(DNS_SENTINEL, nonce))}; "
            f"head -c {MAX_DNS_BYTES} {DNS_LOG} 2>/dev/null; "
            f"exit $rc"
        )

    @staticmethod
    def home_listing() -> str:
        """A listing of `$HOME`, produced from inside the container.

        `find` rather than `docker diff`, and run in here rather than out there,
        because `$HOME` is a tmpfs: the overlay diff the caller runs afterwards
        cannot see a single path under it, and the tmpfs itself does not survive
        the container.

        Two levels deep. One is not enough -- `.ssh/authorized_keys` is the write
        worth reporting and `.ssh` alone does not say it was written to -- and the
        bound keeps a package tree of fifty thousand files from being enumerated
        for the sake of a dozen dotfiles. `-xdev` for the same reason: `/tmp` is a
        separate mount and has its own reasons to be busy.
        """
        return (
            f"find {HOME_DIR} -xdev -mindepth 1 -maxdepth 2 -path '{HOME_DIR}/.*' "
            f"2>/dev/null | head -c {MAX_HOME_LISTING_BYTES}"
        )

    @staticmethod
    def observe(backend: Backend, ecosystem: str, artefact: Artefact) -> Run:
        """Install an already-downloaded package under isolation and record what changed.

        The container is created, the artefact is copied into it, and it is started
        separately from the inspection so the filesystem can be diffed after it
        exits. It is removed either way -- a container left behind holding a
        payload's output is a mess the caller did not ask for.

        The artefact is copied rather than mounted. A bind mount would make a host
        path reachable from inside, which is the one thing the isolation is for.
        """
        image = Observer.prepare_image(backend, ecosystem)
        _, command = Observer.install_command(ecosystem, artefact.filename)
        name = f"cordon-sandbox-{uuid.uuid4().hex[:12]}"
        # Per run, so the markers in the output cannot be known in advance (see TRACE_SENTINEL).
        nonce = uuid.uuid4().hex

        create = Observer._run(
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
                # Lookups go to the recorder on loopback (DNS_LOGGERS), never to the daemon's
                # nameserver. Binding port 53 needs no capability once the namespaced sysctl allows
                # it, so every capability stays dropped.
                "--dns",
                "127.0.0.1",
                "--sysctl",
                "net.ipv4.ip_unprivileged_port_start=0",
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
                Observer.container_command(
                    artefact.filename, command, nonce, DNS_LOGGER_COMMAND.get(ecosystem, "")
                ),
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
            # Kept apart. The markers and the dumps after them are written to stdout; the
            # install's stderr arrives separately, and appended after stdout it landed inside the
            # last dumped section, where an npm error message was read as a looked-up name.
            output = started.stdout.decode("utf-8", "replace")
            errors = started.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            timed_out = True
            status, output, errors = -1, "", ""
            Observer._run([backend.command, "kill", name], timeout=30)

        changes = Observer._run([backend.command, "diff", name], timeout=60)
        Observer._run([backend.command, "rm", "-f", name], timeout=60)

        installer_output, trace, home, limits, lookups = Observer._split_trace(output, nonce)
        installer_output = installer_output + errors
        traced = bool(trace.strip())
        observed = Backend(
            command=backend.command,
            version=backend.version,
            rootless=backend.rootless,
            runtime=backend.runtime,
            traces_syscalls=traced,
            limits_enforced=Observer.limits_enforced(limits),
        )

        observations = Observer._interpret(changes.stdout or "", status, timed_out, home)
        observations.extend(Observer._interpret_trace(trace, traced=traced))
        observations.extend(Observer.interpret_dns(lookups, ecosystem))

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

    @staticmethod
    def _split_trace(
        output: str, nonce: str = ""
    ) -> tuple[str, str, str | None, str | None, str | None]:
        """The installer's output, the trace, the listing of `$HOME`, the limits probe, and the
        names the install tried to resolve.

        Each marker may be absent -- a container killed at the wall clock printed
        none -- and the cases are not the same. An empty trace means the tracer
        did not run; a MISSING home listing means the install directory was never
        enumerated, which must not read as an install that wrote nothing there.
        `None` says that, where an empty string says "looked, found nothing".

        Split at the LAST occurrence of each marker: the observer's own dump comes
        after everything the install printed, so a marker the package printed
        earlier (forged, or by accident) lands in the installer's output where it
        belongs instead of being read as the trace."""
        trace_marker = Observer.marker(TRACE_SENTINEL, nonce)
        head, found, tail = output.rpartition(trace_marker)
        if not found:
            return (output, "", None, None, None)
        trace, listed, rest = tail.rpartition(Observer.marker(HOME_SENTINEL, nonce))
        if not listed:
            return (head, tail, None, None, None)
        listing, limited, rest = rest.rpartition(Observer.marker(LIMITS_SENTINEL, nonce))
        if not limited:
            return (head, trace, rest, None, None)
        limits, resolved, lookups = rest.rpartition(Observer.marker(DNS_SENTINEL, nonce))
        if not resolved:
            return (head, trace, listing, rest, None)
        return (head, trace, listing, limits, lookups)

    @staticmethod
    def _interpret_home(listing: str | None) -> list[Observation]:
        """What the install left in `$HOME`, which `docker diff` cannot see.

        The absent case comes first and is an observation of its own. This module's
        stated position is that a check which did not run must never look like a
        check that found nothing, and `$HOME` is the one place the package's own
        install code runs -- so not having enumerated it is a hole in the report,
        not a clean result.
        """
        if listing is None:
            return [
                Observation(
                    kind="not_observed",
                    detail=(
                        f"{HOME_DIR} -- where the install ran, and what $HOME was set to -- "
                        f"was not enumerated, so anything written there is unreported. "
                        f"It is a tmpfs, which the container filesystem diff cannot see "
                        f"into at all"
                    ),
                )
            ]

        found: list[str] = []
        for line in listing.splitlines():
            path = line.strip()
            if not path.startswith(f"{HOME_DIR}/"):
                continue
            relative = path[len(HOME_DIR) + 1 :]
            # The first segment, which is the dotfile or dotdirectory itself. A hit
            # on `.ssh/authorized_keys` and one on `.ssh` are the same finding, and
            # the longer path is the one worth printing.
            if relative.split("/", 1)[0] in HOME_PERSISTENCE_NAMES:
                found.append(path)

        if not found:
            return []

        interesting = sorted(set(found))
        shown = ", ".join(interesting[:8])
        return [
            Observation(
                kind="persistence",
                detail=(
                    f"the install wrote {len(interesting)} path(s) under $HOME that arrange "
                    f"for something later: {shown}"
                ),
            )
        ]

    @staticmethod
    def _interpret(
        diff: str, status: int, timed_out: bool, home_listing_output: str | None
    ) -> list[Observation]:
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

        observations.extend(Observer._interpret_home(home_listing_output))

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

    @staticmethod
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
            if path.rpartition("/")[2] not in INSTALL_TOOLING
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

        # Address and port are read per connect line, so a port belongs to the address it was
        # dialled on: a loopback lookup on 53 is not reported against a remote address on 443.
        # Loopback and the unspecified address are how a build talks to itself, not how it
        # talks to anybody. This is reading addresses out of a trace, not binding one.
        local = ("127.", "::1", "0.0.0.0")  # noqa: S104
        remote: dict[str, None] = {}
        remote_ports: dict[str, None] = {}
        for line in trace.splitlines():
            if "connect(" not in line:
                continue
            found = [*_CONNECT_INET.findall(line), *_CONNECT_INET6.findall(line)]
            if not found or found[0].startswith(local):
                continue
            remote[found[0]] = None
            remote_ports.update(dict.fromkeys(_CONNECT_PORT.findall(line)))
        if remote:
            ports = ", ".join(remote_ports)
            shown = ", ".join(list(remote)[:8])
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


# `strace -f` prefixes each line with a pid, then the call. The argv of an
# `execve` is the second argument, a bracketed list; the address of a `connect`
# is inside the sockaddr struct. Both are matched loosely on purpose: strace's
# output format varies between versions, and a parser that demanded one shape
# would silently report "nothing executed" on the versions it did not know.
# Only the calls that returned 0. An `execve` that failed ran nothing, and a
# PATH search produces one failure per directory before the success: `pip`
# looking for `lsb_release` emitted eight lines, seven of them `-1 ENOENT`, and
# all eight were reported as programs the install had run.
_EXECVE = re.compile(r'execve\("([^"]{1,400})"[^\n]{0,600}?\)\s*=\s*0\s*$', re.MULTILINE)
_CONNECT_INET = re.compile(r'sin_addr=inet_addr\("([0-9.]{7,15})"\)')
_CONNECT_INET6 = re.compile(r'inet_pton\(AF_INET6, "([0-9A-Fa-f:]{2,45})"')
_CONNECT_PORT = re.compile(r"sin6?_port=htons\((\d{1,5})\)")

INSTALL_TOOLING = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "env",
        "python",
        "python3",
        "python3.11",
        "python3.12",
        "python3.13",
        "pip",
        "pip3",
        "node",
        "npm",
        "gcc",
        "cc",
        "c++",
        "g++",
        "cc1",
        "cc1plus",
        "ld",
        "as",
        "ar",
        "ranlib",
        "objdump",
        "strip",
        "install",
        "make",
        "strace",
        "uname",
        "dpkg",
        "dpkg-architecture",
        "lsb_release",
        "gcc-12",
        "x86_64-linux-gnu-gcc",
        "aarch64-linux-gnu-gcc",
    }
)
"""What an ordinary install execs, by program name.

By name and not by path. `/bin/sh` and `/usr/bin/sh` are the same shell on any
merged-`/usr` distribution, and the first run of this against a real package
reported `/usr/bin/sh` and `/usr/local/bin/pip` as programs a build does not
use -- because the list held absolute paths and neither string was in it.

An install that compiles an extension runs a compiler, a linker and a shell,
and reporting those would be reporting that a build happened. What is worth
saying is what it ran *besides* these: `curl`, `wget`, `chmod`, a binary it
unpacked itself."""


__all__ = [
    "DNS_LOGGERS",
    "DNS_LOGGER_COMMAND",
    "DNS_SENTINEL",
    "HOME_SENTINEL",
    "INSTALL_TOOLING",
    "LIMITS_SENTINEL",
    "MAX_TRACE_BYTES",
    "MEMORY",
    "MEMORY_BYTES",
    "PERSISTENCE_PREFIXES",
    "PIDS",
    "TRACED_CALLS",
    "TRACE_SENTINEL",
    "WALL_CLOCK_SECONDS",
    "Observation",
    "Observer",
    "Run",
]
