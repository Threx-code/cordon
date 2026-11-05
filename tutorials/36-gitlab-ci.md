# 36 · GitLab CI: the template, code quality and a merge-request gate

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Cordon ships a GitLab CI template, `ci/gitlab/cordon.gitlab-ci.yml`. It installs the scanner
hash-verified (pip refuses anything whose digest is not in the pin committed at that tag), runs
one scan, and writes every report GitLab reads: the job log, code quality on the merge
request, JUnit in the test tab, SARIF and the JSON result as artifacts.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  merge request / default branch                                          │
│      │                                                                   │
│      ▼                                                                   │
│  pip install --require-hashes  ── the pin committed at the tag you chose │
│      │                                                                   │
│      ▼                                                                   │
│  cordon-scanner scan . ── one scan, five outputs                         │
│      ├─ text ............ the job log                                    │
│      ├─ codeclimate ..... gl-code-quality-report.json: findings in the MR │
│      ├─ junit ........... cordon-junit.xml: the pipeline's Tests tab      │
│      ├─ sarif ........... cordon.sarif (artifact)                        │
│      └─ json ............ cordon-result.json (artifact, for your tools)  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Level 1: include it

```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://raw.githubusercontent.com/Threx-code/cordon/v0.7.0/ci/gitlab/cordon.gitlab-ci.yml'

stages: [test]
```

That adds `cordon:scan`, which runs on merge requests and on the default branch, fails at
`high`, and keeps its reports for 30 days. Include it at a tag, never a branch: the template
and the scanner it pins then move together.

## Level 2: your thresholds

Every setting is a variable, so override the job rather than copying it:

```yaml
cordon:scan:
  variables:
    CORDON_SEVERITY: "medium"     # what the reports list
    CORDON_FAIL_ON: "high"        # what fails the job
```

## Level 3: review what a merge request adds to the dependencies

A job of your own, beside the template's, compares the dependency graph at the merge
request's base with its head. The base commit comes from GitLab's own variable, is checked
to be a commit id, and is used through the environment, never pasted into the script:

```yaml
cordon:dependency-review:
  extends: .cordon
  stage: test
  variables:
    GIT_DEPTH: "0"                # the base commit must be in the clone
  script:
    - |
      printf '%s' "$CI_MERGE_REQUEST_DIFF_BASE_SHA" | grep -Eq '^[0-9a-f]{40}$' \
        || { echo "the merge request's base is not a commit id"; exit 1; }
      code=0
      cordon-scanner review . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --format markdown --quiet \
        > cordon-review.md || code=$?
      cat cordon-review.md
      exit "$code"                  # review's own verdict, not cat's
  artifacts:
    when: always
    paths: [cordon-review.md]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes: ["**/*lock*", "**/package.json", "**/requirements*.txt", "**/pyproject.toml", "**/go.mod", "**/Cargo.toml"]
```

`review` fails the job for a known-malicious release, or a high or critical vulnerability,
that the merge request adds. Add `--online` to also fetch each changed release from its
registry, verify it, and compare what it contains with the release it replaces (new install
hooks, new capabilities, new binaries, a new publisher). Tutorial 21 explains the output.

## Level 4: a nightly sweep that blocks nobody

```yaml
cordon:nightly:
  extends: cordon:scan
  variables:
    CORDON_FAIL_ON: "medium"
  allow_failure: true
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

Create the schedule under **Build → Pipeline schedules**. A new advisory against code nobody
touched shows up the next morning, without failing anyone's merge request.

## Level 5: send results to Cordon Cloud

```yaml
cordon:scan:
  variables:
    CORDON_UPLOAD: "true"
```

The job's own OIDC token (audience `cordon`, declared in the template) is exchanged for a
fifteen-minute Cordon token, so no secret is stored in GitLab. An organisation admin adds a
trust rule for the project first.

## Runners with no internet access

Extend `.cordon-airgapped` instead. The runner's image must already carry the scanner,
installed from the release wheel and its hash pin mirrored inside your network, and a signed
intel bundle (tutorial 40 builds one):

```yaml
cordon:scan-offline:
  extends: .cordon-airgapped
  stage: test
  image: registry.internal.example/cordon-runner:0.7.0
  script:
    - cordon-scanner scan . --fail-on high --fail-on-incomplete --format codeclimate:gl-code-quality-report.json --format text
```

`CORDON_OFFLINE: "1"` stops every network request, the advisory refresh included; intel
older than a week then makes the scan incomplete, so refresh the image's bundle weekly.

Next: **[37 · Other CI systems](37-other-ci.md)**.
