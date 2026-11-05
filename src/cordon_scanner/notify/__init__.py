"""Telling someone how a scan went: a signed webhook, Slack, Microsoft Teams, or a channel a plugin adds.

A security tool nobody hears from gets uninstalled, so a scan can post one message per channel. The
rules, each of which is a way this could otherwise go wrong:

* **Destinations come only from the environment.** `CORDON_NOTIFY_SLACK`, `CORDON_NOTIFY_TEAMS`
  and `CORDON_NOTIFY_WEBHOOK`. A Slack or Teams incoming-webhook URL is a credential, and a URL on
  the command line leaks into process listings and CI logs. The command line names channels only
  (`--notify slack,teams,webhook`).
* **Notifying never changes the scan.** A failed delivery is reported on stderr and the exit code
  stays the gate's. It is also a separate, explicit request: `--notify` does not make the scan
  itself use the network.
* **Nothing sensitive leaves.** A message carries rule ids, severities, locations and fingerprints.
  Never a finding's message or evidence, which can quote a masked secret or a line of source. A
  channel, a plugin's included, is handed only the `Summary`, never the scan result.
* **HTTPS only, no redirects, five seconds an attempt.** A redirect could turn an https destination
  into an http one, so none is followed. A delivery that fails on the way (a dropped connection, a
  429, a 5xx) is tried again, three times at most and within twenty seconds for the whole scan, under
  the same delivery id so a receiver can drop a duplicate.

The generic webhook uses the Cordon event contract (`schemas/cordon-event-v1.schema.json`), the
same envelope and signature Cordon Cloud sends: headers `X-Cordon-Event`, `X-Cordon-Delivery`
(an idempotency key) and `X-Cordon-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">`
keyed by `CORDON_NOTIFY_WEBHOOK_SECRET`. A webhook without a secret is refused rather than sent
unsigned, because a receiver could not tell it from a forgery.

```
  channel.py    the port: Channel, the Message it builds, ChannelRefused
  channels/     the built-in channels, registered under `cordon_scanner.notifiers`
  summary.py    Summary: what a message may say
  events.py     the cordon.event/v1 envelope and its signature
  transport.py  HttpsTransport and RetryPolicy
  notifier.py   Notifier: the channels, delivery to all of them at once, the outcomes
```
"""
