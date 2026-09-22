# 17 · Source, build systems, binaries and licences

The domains that do not fit anywhere else, and the flags that decide *what gets
scanned in the first place*. Thirteen rules plus the licence layer.

## Choosing what to scan

```
┌──────────────────────────────────────────────────────────────────────────┐
│   cordon-scanner scan .              the working tree                    │
│   cordon-scanner scan pkg.tgz        an archive, in memory (15)          │
│                                                                          │
│   --staged                           what `git commit` would commit      │
│   --tracked                          files git knows about               │
│   --git-diff main...HEAD             what this branch changed            │
│                                                                          │
│   --include 'packages/api/**'        a monorepo, one project             │
│   --exclude 'vendor/**'              ...and see the exclusion            │
│                                      reported back to you                │
│                                                                          │
│   An exclusion is never silent. POLICY.COVERAGE.BROAD_EXCLUSION          │
│   fires when configuration removes 80%+ of the tree, and                 │
│   POLICY.EXCLUDE.UNMATCHED fires when a pattern matched nothing --       │
│   because a rule for a path that does not exist silently skips           │
│   whatever is committed there later.                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

A pre-commit hook wants `--staged`; a pull-request gate wants `--git-diff`.
Both scan less, and both say so in the report rather than quietly.

## Domain 1 -- source and VCS identity

```
┌──────────────────────────────────────────────────────────────────────────┐
│   SUSPECT.VCS.HOOK_ADDED.001        a .githooks/ or .git/hooks/          │
│   SUSPECT.VCS.HOOKS_PATH.001        core.hooksPath redirected            │
│                                                                          │
│       A repository that ships its own git hooks runs code on             │
│       `git commit`, on `git checkout`, on clone-and-configure.           │
│       Nobody reviews hooks the way they review source.                   │
│                                                                          │
│   SUSPECT.SUBMODULE.UNTRUSTED.001   a submodule over http://, or         │
│                                     pointing at a host nobody            │
│                                     pinned                               │
│                                                                          │
│   SUSPECT.POLYGLOT.MISMATCH.001     the contents contradict the          │
│                                     name: a .png that is a script,       │
│                                     a .json that is an ELF               │
│                                                                          │
│   POLICY.VCS.BINARY_ADDED.001       a binary appeared in a tree          │
│                                     that is otherwise source             │
└──────────────────────────────────────────────────────────────────────────┘
```

## Domain 4 -- build systems

```
┌──────────────────────────────────────────────────────────────────────────┐
│   A build file is an install hook wearing a different name. It           │
│   runs on every machine that builds, usually before any test.            │
│                                                                          │
│   SUSPECT.BUILD.MAKE_FETCH_EXEC.001       a Makefile recipe that         │
│                                           downloads and runs             │
│   SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001                               │
│                                           FetchContent/                  │
│                                           ExternalProject with no        │
│                                           hash to check                  │
│   SUSPECT.BUILD.MSBUILD_FETCH_EXEC.001    an Exec task doing the         │
│                                           same on .NET                   │
│   POLICY.BUILD.UNPINNED_DEPENDENCY.001    a Gradle/Maven                 │
│                                           coordinate with a              │
│                                           floating version               │
│                                                                          │
│   Cordon separates `build` from `projectbuild`: a Makefile in            │
│   YOUR repository is not an install hook for your users, and is          │
│   scored on what it contains rather than on where it sits.               │
└──────────────────────────────────────────────────────────────────────────┘
```

## Domain 12 -- binaries and artefacts

```
┌──────────────────────────────────────────────────────────────────────────┐
│   POLICY.BINARY.COMMITTED.001       a compiled artefact in source        │
│                                     control. Nobody diffs it, so         │
│                                     nobody reviews it.                   │
│                                                                          │
│   SUSPECT.BINARY.EXECUTABLE_PATH.001                                     │
│                                     an executable where source           │
│                                     belongs -- scripts/, bin/ in         │
│                                     a package that ships no binary       │
│                                                                          │
│   SUSPECT.BINARY.PACKED.001         UPX or a packer signature:           │
│                                     the file is deliberately             │
│                                     unreadable                           │
│                                                                          │
│   SUSPECT.BINARY.STRINGS.001        strings inside a binary that         │
│                                     name a pool, a C2 host or a          │
│                                     credential path                      │
│                                                                          │
│   A binary is classified from its extension and leading bytes,           │
│   never from what it contains -- so a source file cannot dodge           │
│   scanning by looking binary.                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Licences

Not a threat domain -- an obligation one. The lockfile records what the
registry said at lock time, so this is answered offline where the format
carries it.

```bash
cordon-scanner scan . -f json:out.json
jq '.findings[] | select(.rule_id | startswith("POLICY.LICENSE")) |
    {rule_id, package: .location.package}' out.json
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│   POLICY.LICENSE.WEAK_COPYLEFT.001       MPL, LGPL, EPL                  │
│   POLICY.LICENSE.COPYLEFT.001            GPL                             │
│   POLICY.LICENSE.NETWORK_COPYLEFT.001    AGPL -- the network clause      │
│                                          is a different obligation       │
│                                                                          │
│   A dependency whose licence the lockfile did not record produces        │
│   NO finding. `null` means the format did not carry one offline;         │
│   it does not mean the dependency has none, and it is never              │
│   reported as though it did.                                             │
│                                                                          │
│   npm's v2/v3 lockfiles carry it. Most other formats do not, so a        │
│   complete licence inventory needs the registry -- a different           │
│   promise from the one this tool makes by default.                       │
└──────────────────────────────────────────────────────────────────────────┘
```

## Domain 14 -- the scanner itself

```
┌──────────────────────────────────────────────────────────────────────────┐
│   The last domain is Cordon. A scanner that can be silently              │
│   disabled protects nothing.                                             │
│                                                                          │
│     POLICY.PLUGIN.SHADOWED          a package registered a               │
│                                     detector name that is                │
│                                     built-in. It was NOT loaded,         │
│                                     and you are told.                    │
│                                                                          │
│     POLICY.COVERAGE.DETECTOR_DISABLED                                    │
│     POLICY.COVERAGE.RULE_DISABLED   the SCAN TARGET's own config         │
│     POLICY.CONFIG.LIMIT_REDUCED     tried to narrow the scan             │
│     POLICY.CONFIG.GATE_WEAKENED     ...and was refused                   │
│                                                                          │
│   cordon-scanner guard verify       the installed files still            │
│                                     match their manifest                 │
│                                                                          │
│   A repository cannot decide which of its own findings are               │
│   allowed to fail your build.                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

That is the whole rule pack. Back to **[the map](README.md)**, or straight to
**[10 · Config, policy and baselines](10-config-policy-baselines.md)** to decide
which of it gates your builds.
