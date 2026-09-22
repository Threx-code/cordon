# 16 · The sandbox -- running what you do not trust

Every other tutorial rests on one promise: **Cordon reads, it never executes.**
This one is about the single component that breaks that promise on purpose, and
about all the ways it is kept away from the rest.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   cordon-scanner                    cordon-sandbox                       │
├──────────────────────────────────────────────────────────────────────────┤
│   reads                             EXECUTES                             │
│   safe on hostile packages          isolation or nothing                 │
│   no flag needed                    --sandbox required, no override      │
│   offline by default                fetches the artefact                 │
│                                                                          │
│   Two entry points, on purpose. The scanner does not import the          │
│   sandbox, and a test asserts it: a promise with a code path into        │
│   execution is not a promise.                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Why it exists at all

```
┌──────────────────────────────────────────────────────────────────────────┐
│   The static tiers resolve what is constant-derivable:                   │
│                                                                          │
│      aliased imports, bound names, spliced strings, base64 in a          │
│      literal, computed dispatch over a known namespace                   │
│                                                                          │
│   What no static tier can decide is behaviour that only exists           │
│   while the code runs:                                                   │
│                                                                          │
│      a target decoded from a network RESPONSE                            │
│      logic gated on a value that is fetched                              │
│      a payload assembled from two files at import time                   │
│                                                                          │
│   That residual is Rice's theorem, not a missing feature. The            │
│   only instrument that observes it is one that runs the code.            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Using it

```bash
cordon-sandbox pypi requests==2.31.0 --sandbox
cordon-sandbox npm  left-pad          --sandbox --json
```

`--sandbox` carries no information the command does not already imply. It is
there so that running untrusted code is never something you did by accident.

## The three phases

```
┌──────────────────────────────────────────────────────────────────────────┐
│   1. PREPARE      an analysis image is built once, with network,         │
│                   from this project's own Dockerfile. The package        │
│                   under analysis is NOT present at this stage.           │
│                                                                          │
│   2. FETCH        the artefact is downloaded over HTTPS from the         │
│                   registry. Downloading a tarball executes nothing.      │
│                                                                          │
│                   deliberately NOT `pip download`: that runs             │
│                   setup.py egg_info to resolve an sdist, which           │
│                   would run the payload on YOUR host, before any         │
│                   sandbox existed.                                       │
│                                                                          │
│   3. OBSERVE      the artefact is streamed into a container with         │
│                   no network interface and no host filesystem,           │
│                   and installed from the local file with the             │
│                   index disabled.                                        │
│                                                                          │
│                   lifecycle scripts stay ENABLED -- they are the         │
│                   whole reason to run anything, and                      │
│                   --ignore-scripts would produce a clean                 │
│                   observation of a package that was never asked          │
│                   to do the thing.                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

## What the container is, and is not

```
┌──────────────────────────────────────────────────────────────────────────┐
│   GUARANTEED, every run                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│     no network interface                                                 │
│     no host filesystem mounted                                           │
│     a writable layer, discarded afterwards                               │
│     all Linux capabilities dropped                                       │
│     no-new-privileges                                                    │
│     process and memory ceilings                                          │
├──────────────────────────────────────────────────────────────────────────┤
│   STATED, because it varies                                              │
├──────────────────────────────────────────────────────────────────────────┤
│     rootless?      asked of the runtime, never inferred from the         │
│                    binary's name. Podman runs rootful, Docker has        │
│                    a rootless mode; an unreadable answer is              │
│                    reported as rootful.                                  │
│                                                                          │
│     gVisor?        if runsc is configured it is used, and the            │
│                    guest's syscalls are served by a userspace            │
│                    kernel. Without it the HOST KERNEL is the             │
│                    boundary -- a kernel exploit crosses it, which        │
│                    a VM would not allow.                                 │
│                                                                          │
│     syscalls traced?  execve and connect, where available.               │
└──────────────────────────────────────────────────────────────────────────┘
```

Every one of those is printed with the result, so the report says what the
isolation actually was rather than what it usually is.

## It refuses rather than degrades

```
┌──────────────────────────────────────────────────────────────────────────┐
│   If isolation cannot be established, it does not run the code.          │
│                                                                          │
│     not with a warning                                                   │
│     not with reduced isolation                                           │
│     not on the host                                                      │
│     and there is no override flag                                        │
│                                                                          │
│   It exits and says why. A sandbox that degrades to no sandbox is        │
│   worse than none, because the person who asked for it believes          │
│   they are protected.                                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Exit codes

```
  0   nothing observed
  1   something was observed
  2   the component could not run (no runtime, image build failed)
  3   bad invocation (e.g. --sandbox missing)
```

They match the scanner's, so one pipeline can gate on either.

## When to reach for it

```
┌──────────────────────────────────────────────────────────────────────────┐
│   scan says CLEAN and you still do not trust it                          │
│      └─▶ a dependency with an install hook you cannot read,              │
│          a minified bundle, a fetched-then-executed target               │
│                                                                          │
│   scan says SUSPECT.OBFUSCATION or DYNAMIC_DISPATCH                      │
│      └─▶ the static tier said 'I cannot resolve this', which is          │
│          a signal, not an answer. The sandbox gives the answer.          │
│                                                                          │
│   you are about to add a dependency to a product                         │
│      └─▶ read it (15), then run it (16). In that order: reading          │
│          is free and cannot hurt you.                                    │
│                                                                          │
│   DO NOT use it as a gate on every build. It is slow, it needs a         │
│   container runtime, and a clean observation only says the               │
│   package did nothing THIS time, on THIS machine.                        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

Next: **[17 · Source, build systems and binaries](17-source-build-binaries.md)**.
