# The sandbox

`cordon-sandbox` installs a package under isolation and reports what it did. It
is the one part of this project that executes untrusted code, and it is kept
separate from the scanner in every way that matters.

## Why it is separate

Cordon's core promise is that it never executes the code it scans. That is a
security property, not a limitation: running attacker code is the thing the tool
exists to protect people from. So this component has its own entry point, is not
imported by the scanner, and is not reachable from `cordon-scanner scan`. A test
asserts the scanner does not import it, because a promise with an entry point
into execution is not a promise.

## Why it exists

The static tiers resolve constant-derived obfuscation — aliased imports, bound
names, spliced strings, computed dispatch — and turn what they cannot resolve
into a signal of its own. What none of that decides is behaviour that only
exists while the code runs: a target decoded from a network response, logic
gated on a fetched value. That residual is Rice's theorem rather than a missing
feature, and the only tool that observes it is one that runs the code.

## Using it

```bash
cordon-sandbox pypi requests==2.31.0 --sandbox
cordon-sandbox npm left-pad --sandbox --json
```

`--sandbox` is required and carries no information the command does not already
imply. It exists so that running untrusted code is never something you did by
accident, and so a copied command line is obviously the thing it is.

Exit codes match the scanner: `0` nothing observed, `1` something was, `2` the
component could not run, `3` bad invocation.

## What it refuses to do

If isolation cannot be established, it does not run the code. Not with a
warning, not with reduced isolation, not on the host — it exits and says why,
and there is no override flag. A sandbox that degrades to no sandbox is worse
than none, because the person who asked for it believes they are protected.

## The three phases

**Prepare.** An analysis image is built once, with network, from a base image
plus the build tooling an offline install needs. Only this project's own
Dockerfile runs here; the package under analysis is not present.

**Fetch.** The artefact is downloaded over HTTP from the registry. Downloading a
tarball executes nothing. This is deliberately not `pip download`, which runs
`setup.py egg_info` to resolve a source distribution — that would run the
payload on the host, before any sandbox existed.

**Observe.** The artefact is streamed into a container that has no network
interface and no host filesystem mounted, and installed from the local file with
the index disabled. Lifecycle scripts are left enabled: they are the reason to
run anything at all, and `--ignore-scripts` would produce a clean observation of
a package whose whole payload is a postinstall hook.

## What the isolation is, and is not

- No network interface.
- No host filesystem mounted at any point. The artefact arrives on stdin rather
  than through a bind mount.
- All Linux capabilities dropped, no-new-privileges.
- Process and memory ceilings, and a wall-clock budget.
- The container filesystem is writable and destroyed when the run ends.

That last point reads as weaker than a read-only root and is the opposite. The
first version made the root read-only, which meant a payload writing to
`/etc/cron.d` simply failed, and the run reported "the install failed" rather
than "it tried to persist" — a sandbox configured into uselessness. Nothing on
the host is reachable either way; that is what the absent mounts do.

A container boundary is a kernel boundary, and a kernel exploit crosses it. A
rootless runtime (podman, preferred where present) means an escape lands
unprivileged; a root-owned one means it lands as root. The report says which was
used rather than leaving the reader to assume.

Where gVisor is configured in the runtime, it is used. `runsc` serves the
guest's syscalls from a userspace kernel, so the host kernel sees a small fixed
surface instead of the whole syscall table — a materially different class of
bug is needed to get out. It is not required: demanding it would put this back
to running on nothing on an ordinary machine. Whether it was used is one of the
guarantees printed with the result, because a reader deciding what an
observation is worth needs to know which boundary held it.

One capability is added back after everything is dropped: `CAP_SYS_PTRACE`, for
the tracer below. A payload that reaches it is confined to a container that
already has no network and no host mounts.

## What it observes, and what it does not

It records filesystem effects, exit status, output, and — where the host
permits it — the syscalls the install made. Tracing is `strace -f` on `execve`
and `connect`, baked into the prepared image and wrapped around the install.

Those two are the ones that map onto the capability model. `execve` is what the
package *ran*, and the report names only what is not the shell, interpreter or
toolchain a build legitimately uses — an install that compiles an extension
runs a compiler, and saying so would be saying a build happened. `connect` is
what it *tried to reach*, and it is more informative here than on a normal
machine: the container has no network at all, so a connection to an address
that could never have succeeded is intent recorded with the payload never
arriving.

Tracing needs `CAP_SYS_PTRACE` and a seccomp policy that permits `ptrace`. A
host that refuses either produces a run with no trace, and that case is
reported as *not traced* rather than as "nothing was executed" — the same
invariant the static side is built on, that a check which did not run must
never look like a check that found nothing. When the tracer cannot start, the
install is run again without it: an install that did not happen is worth less
than one that happened unobserved.

What filesystem effects and a network-free install establish on their own is
still worth having, and still holds where tracing is unavailable. A package that writes outside its own install tree has done something an
install should not. A package whose own install code fails with the artefact
already present and no network needed the network at install time, which is the
dropper precondition — and an ordinary build error looks the same from here, so
the result says what happened rather than what it means.

## The arms race, stated plainly

A payload that sleeps past the wall-clock budget defeats this. So does one that
fingerprints the container and stays quiet. That is exactly why the static tiers
report anti-analysis behaviour as a finding of its own: code that checks whether
it is being watched, and then decodes, spawns or reaches the network, has
described its own evasion. The two tiers cover each other's blind spot, and
neither is asked to be complete.
