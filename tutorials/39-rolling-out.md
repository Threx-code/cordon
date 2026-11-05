# 39 · Rolling out across an organisation

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Level 3, the organisation: one policy every repository is held to, a baseline so an old
codebase can start today, suppressions that expire and name who approved them, and the
people told when a gate fails. Every example here was run as shown.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  SECURITY TEAM                                                           │
│    policy.yaml ── published once, pinned by digest ── the CEILING        │
│         │          a repository may be stricter, never weaker            │
│         ▼                                                                │
│  EVERY REPOSITORY                                                        │
│    cordon.yaml ── its own settings, validated strictly                   │
│    .cordon-baseline.json ── what was already there on day 0              │
│    suppressions ── one rule, one path, a reason, an approver, an expiry  │
│         │                                                                │
│         ▼                                                                │
│  EVERY PIPELINE                                                          │
│    scan --policy <url>#sha256=… --baseline .cordon-baseline.json         │
│    new finding ──► fail, and notify       old finding ──► reported only  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Step 1: the organisation's policy

The security team writes one policy and publishes it where every pipeline can fetch it:

```yaml
# policy.yaml, published by the security team
version: 1
name: acme-baseline
issued: 2026-11-04
issuer: security@acme.example

enforce:
  detectors_required: [capability, manifest, lockfile, dependency, advisory]
  min_severity_threshold: medium      # a repository may report more, never less
  allow_plugins: false
  allow_extra_rule_packs: false

suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_categories: [malicious]      # never suppressible in a repository
  forbid_path_only: true

fail_on:
  - critical
  - high
  - category: malicious
```

It is a **ceiling**: a repository's settings that would weaken it are refused with exit 3 and
the conflict named, never quietly clamped.

```
$ cordon-scanner config explain cordon.yaml --policy policy.yaml
cordon-scanner: repository configuration conflicts with organisation policy:
  - additional rule packs are configured here but forbidden by policy
  Organisation policy is a ceiling, not a default. Make the repository configuration at
  least as strict, or request a policy change.
```

### Pin it by digest

A policy fetched by URL alone could be changed by whoever controls the server. Pipelines
name it with its SHA-256, so a changed file is refused:

```bash
sha256sum policy.yaml                       # the digest to publish alongside it
cordon-scanner config fetch-policy 'https://security.acme.example/policy.yaml#sha256=<64 hex>'
cordon-scanner scan . --policy 'https://security.acme.example/policy.yaml#sha256=<64 hex>'
```

`fetch-policy` verifies and caches it once, so every scan after reads it offline. A copy
vendored into a repository is checked against the published one with
`cordon-scanner config policy-drift <copy> <url>#sha256=…`, which exits 1 when they differ.
The `ci/github/cordon-pin-bump.yml` workflow (tutorial 24) keeps every pin of Cordon in each
repository current, with one pull request per new release.

## Step 2: each repository's configuration

```yaml
# cordon.yaml, at the repository root
version: 1

scan:
  severity_threshold: low
  exclude:
    - "fixtures/vendored/"

policy:
  fail_on:
    - critical
    - high
    - category: malicious
  fail_on_incomplete: true

notify:
  channels: [slack]
  on: [failed, incomplete]
```

```bash
cordon-scanner config validate cordon.yaml                 # exit 0 valid, 3 not
cordon-scanner config explain cordon.yaml --policy policy.yaml   # every effective value,
                                                                 # and which file set it
```

Unknown keys are errors, never warnings: a mistyped `sevrity_threshold` must not silently mean
the default. Configuration is YAML (`cordon.yaml`, `cordon.yml`, `.cordon.yaml` or
`.cordon.yml`), and it is data: no expressions, no includes, no environment interpolation.

## Step 3: a baseline, so an old codebase can start today

```
   DAY 0                                      EVERY DAY AFTER
   baseline create ──► .cordon-baseline.json  scan --baseline .cordon-baseline.json
   every current finding, "already known"     known ──► reported, not failing
                                              new ──► fails the build
```

```bash
cordon-scanner baseline create . -o .cordon-baseline.json --policy policy.yaml
git add .cordon-baseline.json        # review it first: every entry is something this
                                     # repository is choosing not to fix yet
cordon-scanner scan . --baseline .cordon-baseline.json --policy policy.yaml
cordon-scanner baseline compare . .cordon-baseline.json   # only what is outside it
```

A baseline inside a git repository covers tracked files only; `--all-files` includes what
git ignores. Shrink it as findings are fixed, by creating it again.

## Step 4: suppressions that expire

When a finding is understood and accepted, suppress exactly that rule on exactly that path,
with a reason, an approver and an end date:

```bash
cordon-scanner suppress add SUSPECT.INSTALL.SCRIPT.001 package.json \
  --justification "Our own postinstall builds the native addon from source in this repository; reviewed by security." \
  --days 30 --approved-by security-team --policy policy.yaml
cordon-scanner suppress list --policy policy.yaml     # each one, and whether it is in force
cordon-scanner suppress prune                         # remove the expired, and say which
```

`suppress add` checks the entry as the scanner will, against the policy, before it writes it
to `cordon.yaml`. Against the policy above:

```
   no --approved-by                 refused: organisation policy requires an approver
   --days 200                       refused: expiry is 200 days away, exceeding the maximum of 90
   MALWARE.DROPPER.001 build.js     refused: MALWARE.DROPPER.001 is a malicious rule, and
                                    organisation policy forbids suppressing those
```

An expired suppression stops suppressing and reports a `POLICY` finding, so nothing stays
hidden after its date. For vulnerabilities, a VEX statement (`--vex`) does the same job in
the format your suppliers already use (tutorial 15).

## Step 5: tell people when a gate fails

The channels are named in `cordon.yaml` (step 2); their URLs come only from the environment,
so a repository can never send its results somewhere else:

```bash
export CORDON_NOTIFY_SLACK='https://hooks.slack.com/services/…'      # from your CI secrets
export CORDON_NOTIFY_TEAMS='https://…'
export CORDON_NOTIFY_WEBHOOK='https://alerts.acme.example/cordon'
export CORDON_NOTIFY_WEBHOOK_SECRET='…'          # the webhook is signed; refused without it

cordon-scanner notify test                        # each channel, now, before a real failure
cordon-scanner scan . --notify slack,webhook --notify-on failed,incomplete
```

A delivery that fails is reported on stderr and never changes the exit code. Retries,
verifying the webhook's signature and rotating its secret: `docs/14-NOTIFICATIONS.md`.

## The rollout, week by week

```
   week 1   publish policy.yaml; the action or template in a few repositories with
            dependency review (tutorials 35 to 37); baselines created
   week 2   every repository: the template at a release tag, --policy by digest
   week 3   fail_on_incomplete everywhere; the nightly sweep; notifications on
   after    baselines shrink; suppressions expire and are renewed or fixed;
            the pin-bump workflow keeps the action and the templates current
```

Next: **[40 · Air-gapped](40-air-gapped.md)**.
