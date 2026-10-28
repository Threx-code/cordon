# Notifications

A scan can tell people what it found: one message per channel, when the gate fails, when the scan
was incomplete, or when it passed, as you choose. Notifications are opt-in, read nothing about the
code beyond what the report already says, and never change the exit code.

## Channels

| Channel | `--notify` name | URL from | Message |
|---|---|---|---|
| Slack | `slack` | `CORDON_NOTIFY_SLACK` | Block Kit message |
| Microsoft Teams | `teams` | `CORDON_NOTIFY_TEAMS` | Adaptive Card |
| Any HTTPS endpoint | `webhook` | `CORDON_NOTIFY_WEBHOOK` | a signed `cordon.event/v1` envelope |

A channel's URL is a credential, so it comes only from the environment, never from a flag or a
file. URLs must be `https://`; redirects are not followed.

## When a scan posts

`--notify-on` names the occasions, comma-separated:

| Occasion | Posts when |
|---|---|
| `failed` | the gate failed: something met the failure policy (exit code 1) |
| `incomplete` | the scan could not read everything and the policy fails on that (exit code 4) |
| `passed` | the gate passed (exit code 0) |

The default is `failed,incomplete`, which is when a scan posted before `--notify-on` existed. A
message says which: "passed its gate" or "failed its gate", with the worst severity.

```bash
cordon-scanner scan . --notify slack,webhook                        # when the gate fails
cordon-scanner scan . --notify slack --notify-on failed,passed      # every outcome but incomplete
```

## Configuration

A repository can name its channels and occasions once, in `.cordon.yaml`, instead of on every
command line. The command line still wins when it names them.

```yaml
version: 1
notify:
  channels: [slack, webhook]
  on: [failed, incomplete]
```

`notify` takes only `channels` and `on`. Anything else there, a URL above all, is refused with an
error that says where a URL belongs. An organisation policy may set them too; a repository's own
choice comes first.

## Testing a channel

```bash
cordon-scanner notify test                 # every channel in notify.channels
cordon-scanner notify test slack,teams     # the ones named
```

Each channel is sent a message whose title begins "[test]". Each outcome is printed, and the command exits
non-zero if any did not arrive, so a pipeline can check its notifications before the first real
failure does.

## Delivery

- **In parallel.** Channels are sent at the same time, so one slow endpoint delays no other.
- **Retries.** A delivery that fails on the way (a dropped connection, 408, 429 or 5xx) is tried
  again, three times at most and within twenty seconds for the whole scan. `Retry-After` is
  honoured up to ten seconds. Any other 4xx is not retried: a wrong URL stays wrong.
- **One delivery id.** Every attempt carries the same `X-Cordon-Delivery` header, so a receiver can
  drop a duplicate.
- **Never fatal.** A failed delivery is reported on stderr, with its cause and never its URL, and
  the exit code stays the scan's.

## The audit record

With `--audit-log`, each delivery adds a line to the log after the scan's own record:

```json
{"attempts":1,"channel":"slack","delivery":"<id>","error":"","event":"notify","ok":true,"timestamp":"2026-10-28T20:00:00Z"}
```

The delivery id is the one the receiver saw, so the two records can be matched. The URL is never
written.

## Verifying a webhook

The webhook body is a `cordon.event/v1` envelope
([schema](https://github.com/Threx-code/cordon/blob/v0.6.0/schemas/cordon-event-v1.schema.json)),
signed with `CORDON_NOTIFY_WEBHOOK_SECRET` as
`X-Cordon-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">`. A receiver checks the signature
and rejects a delivery more than five minutes old. `EventSignature.verify` in
`cordon_scanner.notify.events` is a reference implementation.

**Changing the secret.** `verify` takes several secrets. Have the receiver accept the old and the
new one, move every sender to the new one, then drop the old: no delivery is refused on the way.

## What a message contains

Rule, severity, path and fingerprint for the worst findings, the counts, the target's name and
revision, and why the gate decided as it did. Never evidence: no matched text, no secret, no
snippet of code. A channel plugin is given the same summary, never the scan result.

## A channel of your own

PagerDuty, Google Chat or Mattermost is a class implementing the `Channel` protocol in
`cordon_scanner.notify.channel`: an `id`, the `variable` that holds its URL, and
`message(summary, occasion)` returning the body. Register it under the `cordon_scanner.notifiers`
entry point. It is loaded only with `--allow-plugins`. Cordon does the posting, so HTTPS only, no
redirects, and the retry limits hold for it too.
