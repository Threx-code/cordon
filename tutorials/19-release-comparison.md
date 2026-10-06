# 19 · What changed since the last release

> **For Cordon 0.5.2.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

An attacker can disguise code. They cannot hide that it changed. Most real
supply-chain compromises -- a maintainer account taken over, a malicious version of a
trusted package -- show first as a difference between two releases.

```
┌──────────────────────────────────────────────────────────────────────────┐
│    pkg-1.4.2.tgz  (the version you trust)                                │
│    pkg-1.4.3.tgz  (the one you are about to install)                     │
│                                                                          │
│    cordon-scanner scan pkg-1.4.3.tgz --compare-with pkg-1.4.2.tgz        │
│                                                                          │
│    or let Cordon fetch the previous release from the registry,           │
│    verified against the registry's own digest:                           │
│                                                                          │
│    cordon-scanner scan pkg-1.4.3.tgz --online                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## What it reports

```
┌──────────────────────────────────────────────────────────────────────────┐
│   NEW_INSTALL_HOOK     this release runs code at install;                │
│                        the last did not                                  │
│   NEW_CAPABILITY       install-time code now reaches the network, starts │
│                        processes or executes a payload                   │
│   NEW_OBFUSCATION      obfuscated code where there was none              │
│   NEW_BINARY           compiled files that were not there before         │
│   NEW_PUBLISHER        (npm) a different account published it            │
└──────────────────────────────────────────────────────────────────────────┘
```

On stderr Cordon says what it compared with -- `compared with pkg 1.4.2: no new
install hooks, capabilities, obfuscation or binaries` -- so a clean result is a
comparison that was made, not one that was skipped.

`--online` names the package to its registry; without it nothing leaves the machine.

Next: **[20 · Findings in the editor](20-in-the-editor.md)**.
