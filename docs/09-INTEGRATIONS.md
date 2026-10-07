# Running it somewhere

Pre-commit, CI, containers, and the organisation-wide policy that a
repository cannot weaken. Each block below is complete: copy it, change
the paths, and it runs.

## Environments

```
   LOCAL          cordon-scanner scan .
                  incremental cache in $XDG_CACHE_HOME/cordon (authenticated;
                  a foreign entry is ignored). --cache-dir moves it.

   PRE-COMMIT     cordon-scanner guard install     # fail-closed shims in .git/hooks
                  guard verify                      # check they're intact
                  guard verify --manifest-only      # in CI: the guarded files, no hooks
                  the hooks apply cordon-policy.yaml when the repository has one;
                  pre-push reads every tracked file and history.
                  hooks live in .git/hooks (untracked): no commit/switch/clean
                  removes them, and if cordon can't run, the commit is refused.
```

Or the `pre-commit` framework — pinned to a release tag:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Threx-code/cordon
    rev: v0.6.0
    hooks:
      - id: cordon
```

```
   GITHUB ACTIONS
   - uses: Threx-code/cordon/action@<sha>     # pin by commit, not tag
     with: {target: ., severity: medium, fail-on: high, sarif: true}

   inputs pass through the ENV, never interpolated into a shell. The action
   refuses to run under pull_request_target (writable token + secrets on a job
   that may check out untrusted code).
```

Or call the CLI directly — note `if: always()`, or uploading only on success
hides findings exactly when there are some:

```yaml
- run: pipx install cordon-scanner
- run: cordon-scanner scan . -f github -f sarif:cordon.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: cordon.sarif}
```

```
   GITLAB · JENKINS · AZURE   templates in ci/ — all reduce to two lines:
     pip install cordon-scanner
     cordon-scanner scan . --fail-on high -f junit:cordon-junit.xml

   MONOREPO      cordon-scanner scan . --tracked --jobs 8 --exclude 'third_party/**'
                 cordon-scanner scan . --git-diff origin/main     # pull requests
                 exclude generated trees rather than lowering a limit — an
                 exclusion is visible; a lowered limit is a coverage loss.

   AIR-GAP       CORDON_OFFLINE=1, no runtime deps. Nothing need be reachable.
                 --advisories ./advisories.json    to bring your own intel
                 see tutorial 11 for the signed offline bundle
```

Templates live in [`ci/`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci).
The advisory database ships inside the wheel (malicious entries + high/critical
vulns, to bound size); `cordon-scanner advisories sync` fetches the full,
unfiltered set (OSV, plus rubysec for RubyGems) into a local cache a scan then prefers — still no network at scan
time, only at the moment you ask for a refresh. A supplied `--advisories` file
*replaces* the bundled one rather than merging, so what you act on is what you chose.

```
   DYNAMIC ANALYSIS is a SEPARATE binary — on purpose, so nothing in a scan can
   ever execute what it scans:
     cordon-sandbox pypi suspicious-package --sandbox --fail-on high
```

### Enterprise — an organisation ceiling

```yaml
# org-policy.yaml   (point at it with --policy or $CORDON_POLICY)
version: 1
name: "acme-baseline"
enforce:
  min_severity_threshold: low       # repositories may not report less
  min_confidence_threshold: low
  detectors_required: [capability, manifest, secrets]
  allow_limit_increase: false
  allow_plugins: false
  allow_extra_rule_packs: false
  allow_network: false
  max_total_timeout: 600
policy: {fail_on: [high, {category: malicious}], fail_on_incomplete: true}
suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_path_only: true
  forbid_categories: [malicious]
```

A repository config that conflicts with the ceiling is **refused, with the
conflict named** — not silently clamped. Command-line flags are checked against
the same ceiling.

---

### CI templates

| Platform | Template | Upload identity | Closes findings when |
|---|---|---|---|
| GitHub Actions | [`action/`](https://github.com/Threx-code/cordon/tree/v0.6.0/action) | the job's OIDC token (`id-token: write`) | the job ran on the default branch (from the token) |
| GitLab CI | [`ci/gitlab/cordon.gitlab-ci.yml`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci/gitlab) | `id_tokens: CORDON_ID_TOKEN` (aud `cordon`), set by the template | the job ran on the default branch (from the token) |
| CircleCI | [`ci/circleci/orb.yml`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci/circleci) | `circleci run oidc get` with aud `cordon` | the job ran on the default branch (`vcs-origin`, `vcs-ref` in the token) |
| Bitbucket Pipelines | [`ci/bitbucket/`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci/bitbucket) (a pipe) | `oidc: true` on the step | the workspace is connected in Cordon (it names the repository) and the step ran on the default branch |
| Buildkite | [`ci/buildkite/pipeline.yml`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci/buildkite) | `buildkite-agent oidc request-token --audience cordon` | the trust rule names the pipeline's repository; the token names the branch |
| Azure Pipelines | [`ci/azure/cordon-task.yml`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci/azure) | the token of `serviceConnectionId`, a workload identity service connection | the trust rule pins that connection and names its repository and branch, and a branch control check limits the connection to that branch |
| Jenkins | [`ci/jenkins/vars/cordonScan.groovy`](https://github.com/Threx-code/cordon/tree/v0.6.0/ci/jenkins) (shared library) | `credentialsId`: an OIDC Provider plugin id token credential, aud `cordon` | the issuer is on a domain your organisation verified, and the trust rule pins the branch job (`sub`) and names its repository and branch |

Cordon holds each CI token to the repository and branch its identity stands for. Where the token
names them (GitHub, GitLab, CircleCI; the branch for Buildkite and Bitbucket) the token decides;
where it cannot (Azure, Jenkins), the trust rule an administrator writes declares them, for exactly
one pinned job or service connection that the CI system itself restricts to that branch. An upload
naming another repository is refused, and only a scan of the default branch may close a finding:
whatever branch the upload claims makes no difference.

Uploads from GitHub Actions, GitLab CI, CircleCI and Buildkite are also **signed** with the job's
own identity: the template installs `action/requirements-attest.txt` (sigstore and everything it
needs, each file pinned by hash) and asks the CI for a token with Sigstore's audience. Cordon
accepts a signature from an identity one of your trust rules matches, or from the very identity
the uploading job signed in with, for the repository its token is bound to; the certificate names
the commit, which is what lets a deploy gate require a scan signed for the exact revision.
Bitbucket Pipelines, Azure Pipelines and Jenkins have no identity public Sigstore accepts, so their
uploads are unsigned: an organisation deploying from them switches off "require signed scans" in
the deploy-gate settings.

Azure DevOps issues service-connection tokens for audience `api://AzureADTokenExchange` only, and
Bitbucket for its workspace only; Cordon accepts exactly those for those providers. Use a service
connection made for Cordon with no Azure role assignments, so its token is worth nothing anywhere
else. CircleCI's default token is never used: its audience is the one your cloud roles trust.

Every template installs the scanner with `pip --require-hashes --no-deps` from the pin committed at
the release tag it names, so a compromised package index cannot swap the scanner, and a tag with no
pin fails the job rather than installing one unverified. Every template publishes its reports even
when the gate fails.

### Notifications

`--notify slack,teams,webhook` posts once when the gate fails or the scan is incomplete. The URLs
come only from the environment (`CORDON_NOTIFY_SLACK`, `CORDON_NOTIFY_TEAMS`,
`CORDON_NOTIFY_WEBHOOK`). The webhook body is a `cordon.event/v1` envelope
([schema](https://github.com/Threx-code/cordon/blob/v0.6.0/schemas/cordon-event-v1.schema.json))
signed with `CORDON_NOTIFY_WEBHOOK_SECRET` as `X-Cordon-Signature: t=<unix>,v1=<hex HMAC-SHA256 of
"t.body">`; reject a delivery more than five minutes old. Messages carry rule, severity, path and
fingerprint, never evidence. A failed delivery is reported on stderr and never changes the exit code.

### Cordon Cloud

Everything here is opt-in and changes nothing about what a scan finds.

```
   cordon login                     device flow through your org's SSO; pins the org's policy key
   cordon scan . --upload           results as an in-toto statement; keyless-signed in CI
   cordon scan . --cloud-policy     the org's signed policy and approved suppressions
   cordon runner --allow-host github.com     scan jobs inside your network, outbound only
   cordon agent inventory | report  AI agents and MCP servers on this machine, for MDM
```

- **Uploads** are the JSON results plus a DSSE-wrapped in-toto statement over their SHA-256
  ([K2](https://github.com/Threx-code/cordon/blob/v0.6.0/schemas/cordon-upload-v1.schema.json)). In
  CI, with the `[cloud]` extra, Sigstore signs it with the job's identity; elsewhere it is marked
  unsigned. A failed upload never changes the exit code.
- **The policy bundle** is verified with Ed25519 against the key pinned at sign-in, refused if it
  names another organisation or is older than the cached one, and used from cache when the cloud is
  unreachable until it expires. With `--cloud-policy` and no current bundle the scan does not run.
  The pinned key never changes on a token renewal; rotating it is a fresh `cordon login`. CI has no
  sign-in to pin from, so set `CORDON_POLICY_KEYS` (`keyid:hex`, shown on the console's policy
  page) in the CI configuration: without it `--cloud-policy` refuses to apply a bundle checked
  against keys that arrived with the same token.
- **The runner** clones only from hosts its operator allows, with hooks off and the file protocol
  refused, and executes nothing from the target. It applies the repository's own configuration
  as an untrusted one, fails a scan that did not complete, makes no registry lookups unless its
  operator passes `--allow-online`, and uploads results without code excerpts. Its token comes from `CORDON_RUNNER_TOKEN`, never
  a flag.
- **The agent** reads a fixed list of agent and MCP config paths in the home directory, and the
  `package.json` of each extension installed in VS Code, Insiders, VSCodium, Cursor, Windsurf and
  their remote servers (publisher, name and version only), and sends an inventory and findings:
  the agent-chain rules, and every installed extension checked against OSV's malicious-extension
  records, Microsoft's removals and look-alikes. Never file contents or a credential. `cordon
  agent inventory` prints exactly what `report` would send.

The contracts, K1 to K9, are in [`schemas/`](https://github.com/Threx-code/cordon/tree/v0.6.0/schemas).

### The agent judge

Rules catch the wordings someone wrote down; `--judge` has a language model read agent-facing
text for the rest. Off by default. It only adds findings; every rule still runs.

```
   cordon scan . --judge cordon-cloud          recommended: Cordon Cloud's hosted judge (`cordon login`)
   cordon scan . --judge anthropic             your own Anthropic key (ANTHROPIC_API_KEY)
   cordon scan . --judge openai:<model>        OpenAI, or any compatible server (CORDON_JUDGE_URL)
   cordon scan . --judge ollama:<model>        a local model; nothing leaves the machine
```

| Judge | Measured | What leaves the machine |
|---|---|---|
| `cordon-cloud` | Not yet: the hosted endpoint ships with Cordon Cloud | Agent-facing text only |
| `anthropic`, `openai:` a current hosted model | Not by this project: run `bench/judge_bench.py` against it | Agent-facing text only, to that provider |
| `ollama:` qwen2.5 7B, on CPU | 70 of 100 new ATR attack wordings; 22 of 22 realistic benign configs clean; 11 of 75 of ATR's hardest benign texts flagged | Nothing |

Measure the model you choose with `bench/judge_bench.py` before `--judge-blocks` gates on it.

`cordon-cloud` answers only for organisations whose administrator has turned on the hosted judge
(Settings, AI). Until they do, the hosted judge refuses every request before reading its text,
and each scan that asks for it is reported as incomplete. A scan flag asks to send the
repository's text to a model; only the organisation can agree to it.

```
   repository ──▶ agent-facing text only ──▶ judge ──▶ verdict
                  (instructions, skills,      │          │
                   tool descriptions, hooks)  │          ├─ quotes text that IS there? ─▶ finding
                  ≤ 6,000 chars per request   │          └─ otherwise ───────────────▶ ignored
                  fenced as data              │
                                              ├─ malicious ──▶ MEDIUM  (--judge-blocks: HIGH)
                                              ├─ unreachable / budget spent ──▶ scan INCOMPLETE
                                              └─ cached by model + text: a rescan costs nothing

   refused when ......... --offline, or the org policy forbids network
   budget ............... --judge-max-calls (default 200)
   timeout per call ..... local 300 s · remote 90 s · CORDON_JUDGE_TIMEOUT
```

### Container images

`cordon-scanner scan image.tar` on a `docker save` or OCI-layout tarball inventories the operating
system's packages (dpkg, apk, RPM's SQLite database) as the final layer leaves them, whiteouts
applied, and lists them in the SBOM. With `--online` they are matched against Debian, Ubuntu,
Alpine, Red Hat, Rocky, Alma, SUSE, Wolfi and Chainguard advisories through OSV. The legacy
Berkeley DB rpmdb is reported as not read rather than guessed at.
