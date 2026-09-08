# Security and Threat Model

The scanner runs on developer laptops holding SSH keys, cloud credentials and
sometimes crypto wallets, and on CI runners holding deploy credentials and
registry publish tokens. It is pointed, by design, at code that may be actively
malicious. **It is a higher-value target than most of what it scans.**

The governing assumption is stated once and never relaxed:

> **Everything in the scan target is attacker-controlled.** File contents, file
> names, directory structure, symlinks, archive members, manifest fields,
> lockfile entries, git refs, commit messages, and any configuration file found
> inside the target.

---

## 1. Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│ TRUSTED                                                             │
│   Cordon's own code and bundled rule packs (signed, hash-verified)  │
│   Organisation policy supplied via --policy or CORDON_POLICY        │
│   CLI flags typed by the operator                                   │
├─────────────────────────────────────────────────────────────────────┤
│ SEMI-TRUSTED — validated, then clamped by org policy                │
│   Repository cordon.yaml                                            │
│   Third-party rule packs (signature-verified, sandbox-compiled)     │
├─────────────────────────────────────────────────────────────────────┤
│ UNTRUSTED — never executed, never trusted for control decisions     │
│   Every byte of the scan target                                     │
│   Archive members                                                   │
│   Intel feed responses (when --online)                              │
└─────────────────────────────────────────────────────────────────────┘
```

The middle tier is where most scanners get this wrong. A repository's own config
must be able to *describe* the repository — where its vendored code lives, which
paths are generated — without being able to *disable the scan of itself*.

---

## 2. Threats and controls

### T1 — Arbitrary code execution via the scan target

**The primary threat.** Realised by: importing target Python to read
`setup.py`; running `node` to parse `package.json`; invoking `npm ls` or
`pip install` to resolve a graph; loading a plugin found in the target; expanding
a rule pack committed to the target.

**Controls.**
- C4 is absolute: nothing in the target is executed, imported, or evaluated.
- All manifests parsed by Cordon's own parsers. `setup.py` is treated as *source
  code to analyse*, never as a module to import; its metadata is recovered by AST
  inspection of literal assignments only.
- Plugins load **only** from Python entry points in the Cordon environment, never
  from the target, and are disabled unless `--allow-plugins` or an org-policy
  allowlist names them.
- `subprocess` appears in exactly one module (`sources/git.py`), wrapped so that
  every invocation uses a fixed argv list, `--` separators before any
  target-derived value, `-z` output parsing, and a timeout. No shell.
- CI enforcement: a test asserts that no module outside `sources/git.py` imports
  `subprocess`, `os.system`, `os.popen`, `pty`, or `importlib` with a
  target-derived path.

> Reading metadata by invoking the ecosystem's own tooling is the tempting
> shortcut. The parse itself may be safe, but it establishes "run the ecosystem's
> tool" as an acceptable pattern, and the end of that road is a resolver
> executing install hooks inside the scanner.

### T2 — Decompression bombs

**Realised by:** a 42 KB zip expanding to 4.5 PB; a nested archive 20 levels deep;
a tar with a billion 1-byte entries.

**Controls** — all in `archive/safe.py`, the only code allowed to expand anything:
- `max_archive_ratio` (default 200:1) checked **incrementally during the stream**,
  not after extraction. Extraction aborts the moment the running ratio is exceeded.
- `max_archive_entries` (default 50,000).
- `max_archive_depth` (default 3). A nested archive beyond the limit is a finding,
  not a silent skip.
- `max_uncompressed_bytes` per archive and per scan, enforced by a counting
  wrapper around the stream, never by trusting the header's declared size.
- Extraction is streamed to a bounded scratch directory; entries are never read
  fully into memory.

### T3 — Path traversal and link attacks

**Realised by:** archive members named `../../etc/cron.d/x` or `/etc/passwd`; a
symlink in the target pointing at `~/.ssh/id_rsa`, so the scanner reads it and
prints it as evidence; a symlink loop; a hardlink to a file outside the root.

**Controls.**
- Every extracted member path is normalised and must resolve *inside* the
  destination root after `os.path.realpath`. Absolute paths and any `..` segment
  are rejected outright.
- Symlink and hardlink archive members are **never materialised**. Their existence
  is recorded as a finding.
- During directory traversal, symlinks are not followed. A symlink is inventoried
  as a symlink; its target is scanned only if the target is independently inside
  the scan root.
- Device files, FIFOs and sockets are never opened.
- `max_path_depth` and a visited-inode set bound traversal.

> This threat is also why evidence redaction (C7) is defence in depth rather
> than cosmetics. If traversal protection ever fails, masked evidence means the
> scanner still does not print the contents of a private key into a CI log.

### T4 — CPU exhaustion (ReDoS)

**Realised by:** a file crafted to trigger catastrophic backtracking in a rule's
regex. Especially dangerous because organisations write their own rules.

**Controls.**
- Rule patterns are validated at **pack load time**, not match time. Rejected:
  backreferences, lookbehind of unbounded width, and nested unbounded quantifiers
  (`(a+)+`, `(a*)*`, `(a|aa)+`). The validator walks the parsed pattern rather
  than pattern-matching the source string.
- `per_file_timeout` (default 5 s) enforced by the worker; a timeout is an
  `OPERATIONAL` finding naming the file and the rule that was running.
- A worker that exceeds `max_memory` is killed and restarted; its unit is reported
  as unscanned.
- Regex matching runs against **bytes**, with input length capped at
  `max_file_bytes` (default 10 MiB). Larger files get a targeted subset of rules
  (literal and entropy only) plus an `OPERATIONAL` note.

### T5 — Memory exhaustion

**Controls.** Files above a threshold are `mmap`'d rather than read; findings are
streamed to the reporter rather than accumulated when the count exceeds a bound
(with a hard `max_findings` cap that produces an `OPERATIONAL` finding); the
dependency graph is bounded by `max_dependencies`; worker processes carry an
`RLIMIT_AS` where the platform supports it.

### T6 — Scanner blinding via configuration

**Realised by:** committing a `cordon.yaml` that excludes the malicious directory,
disables the `capability` detector, adds a permanent suppression, or lowers
`severity_threshold` to `critical`.

**Controls (C3).**
- Org policy is a **ceiling**. A repo config can only narrow within what the org
  policy permits, never widen.
- A repo config **cannot**: disable a detector the org policy enables; add a
  suppression without an `expires` and a justification; suppress `MALICIOUS`;
  lower a threshold; enable network access; add rule packs; add plugins; raise a
  limit.
- Every effective-config decision is written to the audit log with its origin
  layer, and `cordon config explain` prints where each value came from.
- Exclusions are counted and reported: a scan reports `excluded: 412 files by 6
  patterns`, and an exclusion that matches an unusually large fraction of the tree
  produces a `POLICY` finding.

> The subtle form of this deserves naming: an exclusion entry for a path that
> does not exist is a hole held open for a file nobody would notice appearing.
> Commit a file at that path and it is skipped by the very check that exists to
> examine it. Exclusion lists must therefore be validated against the tree, and
> an exclusion matching nothing is reported rather than ignored.

### T7 — Tampering with the scanner itself

**Realised by:** deleting the hook, editing the rule pack, setting
`core.hooksPath` elsewhere, dropping the executable bit, or replacing the
installed binary.

**Controls.**
- `cordon install-hooks` writes shims into `.git/hooks/` (untracked, so no commit,
  branch switch, merge or `git clean` removes them). Each shim **fails closed** if
  the tracked hook it delegates to is missing or non-executable.
- `cordon guard verify` checks: guard files present, tracked, correct mode, not
  staged for deletion, hashes matching the manifest, `core.hooksPath` unset, and
  `.git/hooks/*` really being the shim.
- Rule packs are content-hashed; the hash is recorded in every scan result and in
  SARIF, so a report states which rules produced it.
- Release artefacts are signed (cosign, keyless where possible) and the CLI can
  verify its own rule-pack signatures offline against a bundled public key.

The limit must be stated honestly: **an attacker who can edit a guard can
regenerate its hash manifest in the same commit, and no self-hosted check can
prevent that.** What the manifest guarantees is that such a change *cannot be
silent*. It must appear as a diff in a file whose only purpose is to be reviewed,
and code-owner rules plus branch protection are what put a human on that diff.
Cordon ships the manifest and the verification; it cannot ship the reviewer.

### T8 — Information disclosure through findings

**Realised by:** a rule matching a line containing a live secret, and the tool
printing that line into a CI log, a PR comment, or a SARIF file uploaded to a
third party.

**Controls (C7).**
- Default `RedactionMode.MASKED`: the snippet retains structure and masks
  high-entropy runs. Secret-category rules are `HASH_ONLY` and cannot be
  downgraded by config.
- `match_hash` (sha256 of the raw matched bytes) is always present, so two scans
  are comparable and a responder can confirm a match without the tool ever
  transporting the value.
- PR comments and SARIF `partialFingerprints` carry the hash, never the snippet,
  unless `--evidence full` is explicitly passed.
- The audit log records paths and rule ids, never content.

> The failure this prevents is specific and easy to introduce: a rule fires
> *because* a line contains key material, and the tool then prints that line into
> a CI log, a pull-request comment, and a SARIF file uploaded to a third party.
> The tool that finds a leaked secret must not be the tool that spreads it.

### T9 — Malicious or compromised rule packs

**Realised by:** an organisation's private pack, or a community pack, containing a
ReDoS pattern, an exfiltrating `ast` query, or a suppression that silently blanks
a detector.

**Controls.** Packs are declarative only — there is no code execution path in the
pack format. Patterns are validated (T4). A pack may **add** rules and may not
disable another pack's rules; disabling is a policy operation, not a pack one.
Third-party packs are signature-verified when a key is configured, and a pack's
hash appears in the scan result.

### T10 — Supply-chain compromise of Cordon's own distribution

**Controls.** Zero third-party runtime dependencies in the core (C1) — there is
almost nothing to compromise. Reproducible builds with a recorded
`SOURCE_DATE_EPOCH`. SBOM (CycloneDX + SPDX) attached to every release. Sigstore
keyless signing of wheel, sdist, binary and container image. SLSA build
provenance. All GitHub Actions pinned to commit SHAs. Release branch protected by
CODEOWNERS. The project scans itself with its own scanner in CI, and dogfoods
`cordon guard verify` on every commit.

### T11 — Denial of service against a CI pipeline

A repository crafted so scanning it never finishes, blocking a shared runner.

**Controls.** `total_timeout` (default 15 min) with a partial result emitted, not
an abort — `ScanResult.complete = False`, plus an `OPERATIONAL` finding naming what
was not reached. Policy decides whether an incomplete scan fails the build; the
default is *yes for `--fail-on-incomplete`, no otherwise*, and the reason is that
silently treating a timed-out scan as clean is itself the vulnerability.

### T12 — Network exposure when `--online` is used

**Controls.** Offline is the default (C2). `--online` logs every host contacted.
Only hosts on a fixed allowlist are reachable; a target-supplied config cannot add
one. TLS verification cannot be disabled by any flag. Responses are parsed as
untrusted input under the same limits as files. Nothing about the scanned code —
no path, no content, no hash of proprietary source — is transmitted; lookups are
by package coordinates only, and `--online` prints exactly what it will send
before sending it.

---

## 3. Optional dynamic analysis

Static analysis cannot see through a sufficiently dynamic payload. If dynamic
analysis is ever added it is **opt-in, out-of-process, and containerised**, with
an isolation profile no weaker than this:

```
--cap-drop ALL --security-opt no-new-privileges
--read-only --tmpfs /tmp
--pids-limit 512 --memory 4g --cpus 2
--network none
-v <target>:/scan:ro           # target only: no home directory, no key material
--user 65534:65534
seccomp + AppArmor/SELinux profile, default deny
```

Rules: never on the host, never with the developer's environment, never with
network unless a named `--dynamic-network` flag is given, always with a wall-clock
kill, and results are marked `dynamic: true` so a reader knows the code was run.

This is explicitly **out of scope for v1**. The static engine must be complete and
trusted first, because a sandbox escape in a security tool is worse than the
malware it was inspecting.

---

## 4. What Cordon does not defend against

Stated plainly, because a security tool that overclaims is worse than one that
underclaims:

- **A determined attacker who reads the rules and writes around them.** This is
  true of every signature-and-heuristic scanner. Capability-based rules raise the
  floor from "one campaign" to "the common shapes"; they do not make evasion
  impossible.
- **A malicious dependency that is behaviourally identical to a benign one** until
  a runtime trigger fires.
- **Compromise of the machine running the scan.** Cordon assumes its own
  environment is intact.
- **An attacker with commit access who also controls review.** The guard-integrity
  model converts tampering into a visible diff; it needs a reviewer to mean
  anything.
- **Registry-side attacks that leave the lockfile unchanged**, except in the one
  case where an integrity hash changed for an unchanged version, which is
  detected.

Defence in depth remains the posture. Cordon belongs alongside advisory
scanning, secret scanning, SAST, image scanning, deny-by-default install scripts,
a release-age cooldown on new dependency versions, and branch protection. Its job
is to make the supply-chain-specific layer consistent, testable and
machine-readable across every repository, not to replace the rest.
