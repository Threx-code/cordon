# Cordon GitHub Action

```yaml
permissions:
  contents: read          # checkout
  security-events: write  # upload SARIF

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cordon-dev/cordon-action@v1
        with:
          severity: high
          sarif: true
```

## Permissions

Getting these wrong is the most common failure. `security-events: write` is
required for SARIF upload; without it the scan runs and the upload step fails.

## Triggers

| Trigger | Behaviour |
|---|---|
| `pull_request` | Scans the merge result. Dependency analysis always covers the whole tree, because a malicious transitive dependency appears in no diff. |
| `push` | Full scan, SARIF uploaded against the branch ref. |
| `schedule` | Full scan. The right place to allow network lookups, since no pull request is blocked on it. |
| `pull_request_target` | **Refused.** That trigger gives a writable token and repository secrets to a job that may check out untrusted code. |

## Recommended thresholds

| Where | `fail-on` | Why |
|---|---|---|
| Pull request | `high` | The gate that holds the line |
| Push to main | `high` | Same |
| Scheduled | `medium`, non-blocking | Makes the backlog visible without blocking anyone |
| Release | `high` + `fail-on-incomplete: true` | The one place a partial scan must not pass |

## Exit codes

`0` clean, `1` findings met the policy, `2` scanner error, `3` configuration
error, `4` scan incomplete. A pipeline that cannot tell a broken scanner from
bad code will eventually be configured to ignore both.
