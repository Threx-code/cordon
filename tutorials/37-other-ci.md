# 37 · Jenkins, Azure Pipelines, Bitbucket, CircleCI, Buildkite, and any shell

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Every CI system gets the same contract, so moving from one to another changes nothing about
what passes. Each template in `ci/` installs the scanner hash-verified from the pin committed
at its release tag (a tag with no pin fails the job rather than installing an unverified
scanner), captures the exit code, publishes its reports whatever happened, and only then
marks the build.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  install ── pip --require-hashes, the pin at v0.7.0 ── or a pinned image │
│     │                                                                    │
│  scan ───── exit code captured, never allowed to abort the reporting     │
│     │                                                                    │
│  publish ── JUnit, SARIF: always, so a failed build still says why       │
│     │                                                                    │
│  mark ───── 0 clean · 1 findings · 2 scanner error · 3 config · 4 incomplete│
└──────────────────────────────────────────────────────────────────────────┘
```

Where a template can upload to Cordon Cloud, it uses the CI system's own OIDC identity:
no secret is stored anywhere.

## Jenkins

**As a shared library step.** Under *Manage Jenkins → System → Global Trusted Pipeline
Libraries*, add a library named `cordon` from `https://github.com/Threx-code/cordon`, with
*Library Path* set to `ci/jenkins`. Then, in any `Jenkinsfile`:

```groovy
@Library('cordon@v0.7.0') _

pipeline {
    agent { label 'linux' }          // python3 and curl on the agent
    stages {
        stage('Supply chain') {
            steps {
                cordonScan(failOn: 'high', severity: 'low')
            }
        }
    }
}
```

**As a container, with no network.** `ci/jenkins/Jenkinsfile.snippet` runs the scanner image
with `--network none` and the workspace mounted read-only, publishes JUnit and SARIF in
`post { always { … } }`, and turns each exit code into its own message, so a broken scanner
and a real finding are never confused. Pin the image by its digest
(`docker buildx imagetools inspect ghcr.io/threx-code/cordon:0.7.0` prints it): a tag can be
moved, a digest cannot.

## Azure Pipelines

```yaml
# azure-pipelines.yml
resources:
  repositories:
    - repository: cordon
      type: github
      name: Threx-code/cordon
      ref: refs/tags/v0.7.0
      endpoint: github            # your GitHub service connection

steps:
  - checkout: self
  - template: ci/azure/cordon-task.yml@cordon
    parameters:
      failOn: high
```

JUnit goes to the Tests tab and SARIF to the `CodeAnalysisLogs` artifact, which the SARIF
SAST Scans Tab extension renders. To upload, set `upload: true`, `serviceConnectionId` to a
workload identity service connection made for Cordon (no Azure role assignments), and
`organization` to your Cordon organisation id.

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Supply-chain scan
          script:
            - pipe: docker://ghcr.io/threx-code/cordon-bitbucket-pipe:0.7.0
              variables:
                FAIL_ON: "high"
```

Results land in `test-results/`, which Bitbucket reads as test reports, and `cordon.sarif`
beside them. To upload, add `oidc: true` to the step and `UPLOAD: "true"` to the variables.

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1
orbs:
  cordon: threx-code/cordon@0.7.0

workflows:
  supply-chain:
    jobs:
      - cordon/scan:
          fail-on: high
```

Or use its commands inside a job of your own: `cordon/install` then `cordon/scan`. The orb
never reads CircleCI's default token; uploading uses an OIDC token with audience `cordon` and
your Cordon organisation id (`organization`).

## Buildkite

Paste `ci/buildkite/pipeline.yml` into your pipeline, or upload it from a step:

```yaml
steps:
  - label: ":pipeline: Cordon"
    command: |
      curl -fsSLo .cordon-pipeline.yml \
        https://raw.githubusercontent.com/Threx-code/cordon/v0.7.0/ci/buildkite/pipeline.yml
      buildkite-agent pipeline upload .cordon-pipeline.yml
```

It installs into its own virtual environment, keeps JUnit and SARIF as artifacts, and
uploads with `CORDON_UPLOAD=true` and `CORDON_ORGANIZATION` set, using the agent's OIDC token.

## Any other CI system

`ci/generic/scan.sh` is the whole contract in a dozen lines: the scanner image with no
network, a read-only root, every capability dropped, an unprivileged user, capped memory and
processes, the source mounted read-only, and the reports written to `./out`.

```bash
curl -fsSLo cordon-scan.sh https://raw.githubusercontent.com/Threx-code/cordon/v0.7.0/ci/generic/scan.sh
sh cordon-scan.sh .                    # CORDON_FAIL_ON=medium to change the gate
```

Read the script before you run it, as you would any script you download. It is the
recommended posture for running any scanner: it needs neither write access nor the network,
so it gets neither. With no network the intel is the image's own, and older than a week it
makes the scan incomplete (exit 4): use the image of the current release, or one you refresh
weekly with a signed bundle (tutorial 40).

## The same check without a template

Every template is a wrapper around one command. If your CI system can run a shell, this
is enough:

```bash
pipx install cordon-scanner==0.7.0
cordon-scanner scan . --fail-on high --fail-on-incomplete \
  --format text --format junit:cordon-junit.xml --format sarif:cordon.sarif
```

Install it hash-verified where you can (`pip install --require-hashes -r` the pin at
`action/requirements.txt` in the release tag), as every template does.

Next: **[38 · Containers and images](38-containers-and-images.md)**.
