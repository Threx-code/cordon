# 26 · Every command

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Every command and every option, rendered from the scanner's own argument parser, so nothing
here can name a flag that does not exist. `cordon-scanner help <command>` prints the same for
one command at a terminal.

```
   0  clean            nothing met the failure policy
   1  findings         something did: the build should stop
   2  scanner error    a bug in Cordon; please report it
   3  config error     the invocation or configuration is wrong
   4  incomplete       the scan could not read everything (with --fail-on-incomplete)
```

## Scan and inspect

- `scan`: scan a directory, file or archive
- `clone`: clone, scanned before checkout
- `pull`: pull, scanned before the merge
- `inventory`: what the repository is, and why
- `deps`: dependency graph and findings
- `review`: what a dependency update adds
- `sbom`: CycloneDX or SPDX bill of materials
- `report`: re-render a saved JSON result

## scan

Scan a directory, file or archive.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                    path to scan (default: .), or a package URL such │
│                           as pkg:npm/name@1.0.0 (npm, pypi, cargo, gem,    │
│                           nuget; needs --online)                           │
│ --host                    read TARGET as the root of an installed system   │
│                           (default /): its OS packages and the language    │
│                           packages installed outside any project, matched  │
│                           for known vulnerabilities and malicious releases │
│                           (OS packages with --online). Files are not       │
│                           content-scanned                                  │
│ --home DIR                with --host, also read this user's own installs  │
│                           (pipx, ~/.local, ~/go/bin, cargo install)        │
│ --history                 also read every blob in git history that is no   │
│                           longer in the tree, for secrets                  │
│ --verify-secrets          ask each found credential's own issuer whether   │
│                           it still works (needs --online)                  │
│ --include GLOB            restrict to matching paths (repeatable)          │
│ --exclude GLOB            skip matching paths (repeatable)                 │
│ --staged                  scan the content staged in git, not the working  │
│                           tree (for pre-commit hooks)                      │
│ --tracked                 scan only files git tracks, skipping build       │
│                           output and ignored paths                         │
│ --git-diff REF            scan only files that differ from REF             │
│ --detector ID             run only these detectors (repeatable)            │
│ --no-detector ID          disable a detector (organisation policy may      │
│                           forbid this)                                     │
│ --rules PATH              additional rule pack (repeatable)                │
│ --advisories PATH         advisory database to use instead of the bundled  │
│                           one, as JSON. How an air-gapped site stays       │
│                           current without network access.                  │
│ --severity LEVEL          report at or above:                              │
│                           info|low|medium|high|critical                    │
│ --confidence LEVEL        report at or above: low|medium|high|confirmed    │
│ --fail-on LEVEL           fail the build at or above this severity         │
│ --fail-on-incomplete      treat a degraded scan as a failure               │
│ --baseline PATH           treat findings recorded in this file as already- │
│                           known                                            │
│ --vex PATH                an OpenVEX or CycloneDX VEX document             │
│                           (repeatable): a vulnerability a statement rules  │
│                           out (not_affected, fixed) is marked suppressed   │
│                           with its justification                           │
│ --config PATH             repository configuration file                    │
│ --policy PATH             organisation policy file                         │
│ --format, -f FMT[:PATH]   text|json|sarif|junit|markdown|github.           │
│                           Repeatable. Append :PATH to write that format to │
│                           a file, for example --format sarif:cordon.sarif  │
│ --output, -o PATH         write to a file (only valid with a single        │
│                           --format)                                        │
│ --evidence MODE           none|masked|hash_only (default: masked). The     │
│                           stricter of this and each rule's own policy      │
│                           wins, so `none` only takes effect for rules that │
│                           permit it -- no shipped rule does.               │
│ --timeout SECONDS         total wall-clock budget                          │
│ --no-cache                ignore and do not write the incremental cache    │
│ --cache-dir PATH          where to keep the incremental cache              │
│ --jobs, -j N              worker processes (0 or unset means automatic)    │
│ --offline                 forbid all network access, including the signed  │
│                           intel feed (air-gapped use; CORDON_OFFLINE=1     │
│                           does the same). The intel's age is still         │
│                           reported                                         │
│ --online                  permit the detectors that query a package        │
│                           registry (npm and pypi only; other ecosystems    │
│                           are reported as unasked). Off by default; an     │
│                           organisation policy forbidding network access    │
│                           still wins, and a config found inside the scan   │
│                           target can never set it                          │
│ --compare-with PATH       an earlier release of the same package; report   │
│                           what this one adds -- a new install hook, new    │
│                           network or execution capability, new obfuscation │
│                           or binaries. With --online and a published npm   │
│                           or PyPI artefact, the previous release is        │
│                           fetched from the registry instead                │
│ --allow-network           permit the one network operation there is:       │
│                           fetching a --policy URL, which must carry a      │
│                           #sha256= digest. Never used for scanning         │
│ --reachability            annotate vulnerability findings with import      │
│                           reachability: a vuln in a transitive dependency  │
│                           no first-party code imports is lowered and       │
│                           tagged (never dropped). Reads every source file  │
│                           to collect imports                               │
│ --notify CHANNELS         when the gate fails, post one message to each    │
│                           channel: webhook, slack, teams (comma-           │
│                           separated). URLs come only from                  │
│                           CORDON_NOTIFY_WEBHOOK, CORDON_NOTIFY_SLACK and   │
│                           CORDON_NOTIFY_TEAMS; the webhook is signed with  │
│                           CORDON_NOTIFY_WEBHOOK_SECRET. A failed delivery  │
│                           never changes the exit code                      │
│ --judge MODEL             also have a language model judge agent-facing    │
│                           text (instruction files, skills, MCP tool        │
│                           descriptions, hook commands): cordon-cloud       │
│                           (recommended; `cordon-scanner login`),           │
│                           anthropic[:<model>], openai:<model>, or          │
│                           ollama:<model> to keep everything on this        │
│                           machine. Off by default; only agent-facing text  │
│                           is sent, and the report says whether it ran      │
│                           (env: CORDON_JUDGE)                              │
│ --judge-blocks            report a malicious verdict from --judge at HIGH, │
│                           inside the default gate (default: it warns)      │
│ --judge-max-calls N       the most model calls --judge may make in one     │
│                           scan (default 200)                               │
│ --registry-token URL=VARIABLE                                              │
│                           with --online, ask a private registry about what │
│                           was resolved from it, presenting the token held  │
│                           in the environment variable named (repeatable;   │
│                           never the token itself). Never set from a        │
│                           repository's configuration (env:                 │
│                           CORDON_REGISTRY_TOKENS)                          │
│ --yara RULES              also match every file against a YARA rules file  │
│                           (needs the yara-python module). Off by default;  │
│                           never set from a repository's own configuration  │
│                           (env: CORDON_YARA)                               │
│ --clamav SOCKET           also hand each file to a local ClamAV daemon: a  │
│                           Unix socket path, or tcp://127.0.0.1:3310. Off   │
│                           by default; the report says whether it ran.      │
│                           Never set from a repository's own configuration  │
│                           (env: CORDON_CLAMAV)                             │
│ --upload                  send the results to Cordon Cloud after the scan  │
│                           (K2: an in-toto statement over the JSON results, │
│                           signed keylessly with the CI identity when       │
│                           sigstore is installed). Needs `cordon-scanner    │
│                           login` or a CI OIDC token. A failed upload is    │
│                           reported and never changes the exit code         │
│ --cloud-policy            apply the organisation policy and approved       │
│                           suppressions from Cordon Cloud, verified against │
│                           the policy key pinned at sign-in. Replaces       │
│                           --policy. If no current, verified bundle is      │
│                           available the scan does not run (exit 3)         │
│ --cloud-url URL           Cordon Cloud API base (default:                  │
│                           CORDON_CLOUD_URL, else https://api.cordon.dev)   │
│ --no-expand               do not open archives found inside a directory    │
│                           scan. Faster, and the scan is then marked        │
│                           incomplete if any archive went unopened          │
│ --quiet, -q               findings only                                    │
│ --verbose, -v             more detail                                      │
│ --no-color                disable colour                                   │
│ --audit-log PATH          append one JSON line per scan recording what ran │
│                           and what was suppressed; never file content      │
│ --progress {auto,always,never}                                             │
│                           show a live progress line on stderr; auto means  │
│                           only when stderr is an interactive terminal      │
└────────────────────────────────────────────────────────────────────────────┘
```

## clone

Clone a repository, scanning it before any file is checked out.

Clone without checking out, scan the commit from git's object store, then check it out. A blocked clone is removed, so nothing of it is left on disk.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ url                       the repository to clone                          │
│ directory                 where to clone it (default: its name)            │
│ --branch, -b NAME         check out this branch                            │
│ --fail-on SEVERITY        also block on findings at or above this severity │
│                           (default: critical; anything malicious always    │
│                           blocks)                                          │
│ --config PATH             your own configuration; the repository's is      │
│                           never read                                       │
└────────────────────────────────────────────────────────────────────────────┘
```

## pull

Fetch, scan what would be merged, and merge only if it passes.

Fetch the branch, scan the incoming commit from git's object store, and merge only when it passes. Findings your checkout already had are not counted again. A blocked pull leaves the checkout exactly as it was.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ remote                    the remote (default: the branch's upstream)      │
│ branch                    the branch on that remote                        │
│ --merge                   allow a merge commit; fast-forward only by       │
│                           default                                          │
│ --fail-on SEVERITY        also block on findings at or above this severity │
│                           (default: critical; anything malicious always    │
│                           blocks)                                          │
│ --config PATH             your own configuration; the incoming code's is   │
│                           never read                                       │
│ -C PATH                   the repository (default: .)                      │
└────────────────────────────────────────────────────────────────────────────┘
```

## inventory

Print what the repository is, and the evidence for it.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                                                                     │
│ --format, -f {text,json}                                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

## deps

Dependency graph and per-package findings.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                    path to scan (default: .)                        │
│ --format {text,json}                                                       │
│ --direct-only             list direct dependencies only                    │
│ --exclude GLOB            skip matching paths, as `scan --exclude` does    │
│                           (repeatable)                                     │
│ --online                  also ask registries (withdrawal, hashes,         │
│                           provenance)                                      │
└────────────────────────────────────────────────────────────────────────────┘
```

## review

What a dependency update adds, compared with a git revision.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                    repository directory (default: .)                │
│ --base REF                the revision to compare with, e.g. origin/main   │
│ --format {text,markdown,json}                                              │
│ --online                  fetch each changed package's old and new         │
│                           releases from its registry, verify, scan and     │
│                           compare them                                     │
│ --quiet                   no progress on stderr                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## sbom

Generate or inspect a bill of materials for a scan target.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ sbom generate                 write a CycloneDX or SPDX document from the  │
│                               resolved graph                               │
└────────────────────────────────────────────────────────────────────────────┘
```

### sbom generate

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                                                                     │
│ --format {cyclonedx,spdx}                                                  │
│ --output, -o PATH                                                          │
│ --exclude GLOB            skip matching paths, as `scan --exclude` does    │
│                           (repeatable)                                     │
│ --ai                      write the AI bill of materials instead           │
│                           (CycloneDX 1.6): agent instruction, skill and    │
│                           prompt files, agent settings, MCP servers,       │
│                           models and AI SDKs                               │
│ --vulnerabilities         embed the advisory matches (CycloneDX            │
│                           `vulnerabilities`), marking those on CISA KEV or │
│                           ENISA EUVD as exploited: the per-release record  │
│                           the EU Cyber Resilience Act asks a manufacturer  │
│                           to keep                                          │
│ --name NAME               root component name (default: directory name)    │
│ --component-version VERSION                                                │
│                           root component version (default: whatever the    │
│                           target's own manifest declares, or 0.0.0 when it │
│                           declares none)                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

## report

Re-render a saved JSON result in another format.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ report convert                render a saved result                        │
└────────────────────────────────────────────────────────────────────────────┘
```

### report convert

```
┌────────────────────────────────────────────────────────────────────────────┐
│ path                      a result written with --format json              │
│ --format, -f FORMAT       text|json|sarif|junit|markdown|github            │
│ --output, -o OUTPUT       write to a file                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

## Policy

- `rules`: list, test and show the rules
- `config`: check the repository configuration
- `baseline`: record findings, adopt gradually
- `suppress`: reviewed, expiring exceptions
- `guard`: git hooks and self-integrity

## rules

Inspect and validate rule packs.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ rules list                    list every loaded rule                       │
│ rules test                    run every rule's declared samples            │
│ rules diff                    compare rule packs and report removal or     │
│                               weakening                                    │
│ rules show                    show one rule in full                        │
└────────────────────────────────────────────────────────────────────────────┘
```

### rules diff

```
┌────────────────────────────────────────────────────────────────────────────┐
│ before                    a pack file, or a directory of packs             │
│ after                     the pack to compare; defaults to the packs built │
│                           into this install                                │
└────────────────────────────────────────────────────────────────────────────┘
```

### rules show

```
┌────────────────────────────────────────────────────────────────────────────┐
│ rule_id                                                                    │
└────────────────────────────────────────────────────────────────────────────┘
```

## config

Check configuration.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ config validate               validate a configuration file                │
│ config fetch-policy           fetch a digest-pinned organisation policy    │
│                               once, so scans read it offline               │
│ config policy-drift           check a vendored policy copy against the     │
│                               published one (exit 1 when they differ)      │
│ config explain                show effective settings and their origin     │
└────────────────────────────────────────────────────────────────────────────┘
```

### config validate

```
┌────────────────────────────────────────────────────────────────────────────┐
│ path                                                                       │
│ --policy PATH                                                              │
└────────────────────────────────────────────────────────────────────────────┘
```

### config fetch-policy

```
┌────────────────────────────────────────────────────────────────────────────┐
│ url                       https://host/policy.yaml#sha256=<64 hex>         │
└────────────────────────────────────────────────────────────────────────────┘
```

### config policy-drift

```
┌────────────────────────────────────────────────────────────────────────────┐
│ vendored                  the copy in this repository                      │
│ --published PUBLISHED     the published policy: a path, or its URL with    │
│                           #sha256=<hex> (compared by digest, nothing       │
│                           fetched)                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

### config explain

```
┌────────────────────────────────────────────────────────────────────────────┐
│ path                                                                       │
│ --policy PATH                                                              │
└────────────────────────────────────────────────────────────────────────────┘
```

## baseline

Record known findings so a tool can be adopted incrementally.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ baseline create               record the current findings                  │
│ baseline compare              report findings outside the baseline         │
└────────────────────────────────────────────────────────────────────────────┘
```

### baseline create

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                                                                     │
│ --output, -o OUTPUT       where to write it                                │
│ --policy PATH                                                              │
│ --all-files               include files git ignores; by default a baseline │
│                           inside a repository covers tracked files only    │
└────────────────────────────────────────────────────────────────────────────┘
```

### baseline compare

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                                                                     │
│ BASELINE                                                                   │
│ --policy PATH                                                              │
│ --all-files               include files git ignores; by default a baseline │
│                           inside a repository covers tracked files only    │
└────────────────────────────────────────────────────────────────────────────┘
```

## suppress

List, add and prune suppressions in the repository config.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ suppress list                 show every suppression and whether it is in  │
│                               force                                        │
│ suppress add                  add a suppression, checked as the scanner    │
│                               checks it                                    │
│ suppress prune                remove expired suppressions and report them  │
└────────────────────────────────────────────────────────────────────────────┘
```

### suppress list

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --root ROOT               repository root (default: .)                     │
│ --config CONFIG           config file to edit (default: the repository's   │
│                           cordon.yaml)                                     │
│ --policy POLICY           organisation policy whose ceiling suppressions   │
│                           must respect                                     │
│ --format {text,json}                                                       │
└────────────────────────────────────────────────────────────────────────────┘
```

### suppress add

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --root ROOT               repository root (default: .)                     │
│ --config CONFIG           config file to edit (default: the repository's   │
│                           cordon.yaml)                                     │
│ --policy POLICY           organisation policy whose ceiling suppressions   │
│                           must respect                                     │
│ rule                      the rule id, e.g. SUSPECT.SPAWN.001              │
│ path                      the path it applies to (no `**`)                 │
│ --justification JUSTIFICATION                                              │
│                           why this is safe here (at least 40 characters)   │
│ --expires EXPIRES         expiry date, YYYY-MM-DD                          │
│ --days DAYS               expire this many days from today (default 30)    │
│ --approved-by APPROVED_BY who approved it (required when policy demands an │
│                           approver)                                        │
└────────────────────────────────────────────────────────────────────────────┘
```

### suppress prune

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --root ROOT               repository root (default: .)                     │
│ --config CONFIG           config file to edit (default: the repository's   │
│                           cordon.yaml)                                     │
│ --policy POLICY           organisation policy whose ceiling suppressions   │
│                           must respect                                     │
│ --dry-run                 report what would be removed, change nothing     │
└────────────────────────────────────────────────────────────────────────────┘
```

## guard

Scanner self-integrity and git hook installation.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ guard verify                  check that the guard is intact               │
│ guard install                 install fail-closed git hooks                │
│ guard update                  regenerate the guard hash manifest           │
└────────────────────────────────────────────────────────────────────────────┘
```

### guard verify

```
┌────────────────────────────────────────────────────────────────────────────┐
│ path                                                                       │
│ --manifest-only           check only that every file the guard manifest    │
│                           lists matches it; for CI, which has no hooks to  │
│                           check                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### guard install

```
┌────────────────────────────────────────────────────────────────────────────┐
│ path                                                                       │
│ --global                  install into git's template directory, so every  │
│                           repository cloned or created from now on has the │
│                           hooks                                            │
│ --force                   replace a pre-existing non-cordon hook. Without  │
│                           this such a hook is preserved and a backup is    │
│                           written beside it                                │
└────────────────────────────────────────────────────────────────────────────┘
```

### guard update

```
┌────────────────────────────────────────────────────────────────────────────┐
│ path                                                                       │
└────────────────────────────────────────────────────────────────────────────┘
```

## Threat intel

- `advisories`: the advisory database
- `intel`: the signed threat-intel feed
- `bundle`: offline bundle for air-gapped use

## advisories

Manage the vulnerability/malicious-package advisory database.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ advisories sync               refresh the local advisory data from OSV's   │
│                               bulk export                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

### advisories sync

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --only ECOSYSTEM          sync only these ecosystems (default: all         │
│                           supported)                                       │
│ --os FAMILY               also sync these distributions' advisories        │
│                           (debian, ubuntu, alpine, wolfi, chainguard,      │
│                           rocky, almalinux, redhat, suse, opensuse) so     │
│                           image scans match operating-system packages      │
│                           offline                                          │
│ --bundle URL              install a signed advisory bundle from URL        │
│                           instead of building from OSV; the bundle's       │
│                           Ed25519 signature is verified against the pinned │
│                           release key before anything is unpacked          │
└────────────────────────────────────────────────────────────────────────────┘
```

## intel

The signed threat-intel feed: how current it is, and refreshing it.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ intel status                  show the intel's source, serial and age      │
│                               without fetching anything                    │
│ intel update                  verify and apply the latest signed feed now  │
└────────────────────────────────────────────────────────────────────────────┘
```

### intel status

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --json                    print as JSON                                    │
└────────────────────────────────────────────────────────────────────────────┘
```

### intel update

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --json                    print as JSON                                    │
└────────────────────────────────────────────────────────────────────────────┘
```

## bundle

Build and verify an offline bundle for an air-gapped install.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ bundle create                 build a bundle from a directory              │
│ bundle verify                 check a bundle against its manifest          │
│ bundle install                verify a bundle, then extract it             │
└────────────────────────────────────────────────────────────────────────────┘
```

### bundle create

```
┌────────────────────────────────────────────────────────────────────────────┐
│ source                    directory holding the files to bundle            │
│ --output, -o PATH                                                          │
└────────────────────────────────────────────────────────────────────────────┘
```

### bundle verify

```
┌────────────────────────────────────────────────────────────────────────────┐
│ BUNDLE                                                                     │
└────────────────────────────────────────────────────────────────────────────┘
```

### bundle install

```
┌────────────────────────────────────────────────────────────────────────────┐
│ BUNDLE                                                                     │
│ --into DIR                                                                 │
└────────────────────────────────────────────────────────────────────────────┘
```

## Cordon cloud

- `login`: sign in to Cordon Cloud (SSO)
- `logout`: end the Cordon Cloud sign-in
- `whoami`: the Cordon Cloud sign-in in use
- `runner`: run Cloud jobs in your network
- `agent`: AI agents and MCP servers, for MDM

## login

Sign in to Cordon Cloud through your organisation's SSO (device flow).

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --url URL                 Cordon Cloud API base                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## logout

Forget the stored Cordon Cloud sign-in.

## whoami

Show the Cordon Cloud sign-in in use.

## runner

Run scan jobs from Cordon Cloud inside your own network (outbound only).

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --url URL                 Cordon Cloud API base                            │
│ --allow-host HOST         a host the runner may clone or download from     │
│                           (repeat); jobs naming any other are refused      │
│ --label LABEL             a label jobs can target (repeat)                 │
│ --git-credential HOST=ENV clone private repositories on HOST with the      │
│                           credential in environment variable ENV: a token, │
│                           or user:token (repeat). For GitLab and           │
│                           Bitbucket, which cannot mint a token per clone   │
│ --id ID                   this runner's name (default: the host name)      │
│ --work-dir WORK_DIR       where job workspaces are created and removed     │
│ --once                    take at most one job, then exit                  │
│ --allow-online            let jobs ask for registry lookups (off: the      │
│                           cloud cannot turn on network use here)           │
│ --make-fixes              also take fix jobs: move one npm or PyPI         │
│                           dependency to a safe version in its lockfile and │
│                           push a branch (no package manager or package     │
│                           code is run). Off by default                     │
└────────────────────────────────────────────────────────────────────────────┘
```

## agent

This machine's AI agents and MCP servers, for an organisation's MDM (read-only, disclosed).

```
┌────────────────────────────────────────────────────────────────────────────┐
│ agent inventory               print exactly what `agent report` would      │
│                               send; sends nothing                          │
│ agent report                  send the inventory with the MDM's device     │
│                               token                                        │
│ agent mcp-approve             record the tools each remote MCP server in   │
│                               the repository serves now (.cordon/mcp-      │
│                               tools.json)                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

### agent report

```
┌────────────────────────────────────────────────────────────────────────────┐
│ --url URL                 Cordon Cloud API base                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### agent mcp-approve

```
┌────────────────────────────────────────────────────────────────────────────┐
│ target                    repository directory (default: .)                │
└────────────────────────────────────────────────────────────────────────────┘
```

## General

- `help`: this screen, or one command's help
- `completion`: shell completion script

## help

This screen, or the help for one command.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ COMMAND                   a command, or a command and its action           │
└────────────────────────────────────────────────────────────────────────────┘
```

## completion

Print a shell completion script.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ shell                                                                      │
└────────────────────────────────────────────────────────────────────────────┘
```
Next: **[27 · Every AI agent and MCP location](27-every-agent-location.md)**.
