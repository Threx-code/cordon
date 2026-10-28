# Notification payloads

`sent.json` is what Cordon's notifier sent, before it became the `cordon_scanner.notify` package
(0.6.0), for three made-up scans of a directory named `acme-api`: one finding, twenty-five, and
none. The findings are the test suite's own `Support.a_finding()`. Nothing in it comes from a real
repository, a corpus or a real webhook. The URLs are `.test` placeholders, and the secret is
`s3cret`.

The version is written `@VERSION@`, so a release does not change the file. Because the webhook's
signature covers the version, `tests/unit/notify/test_channels.py` verifies it rather than compares
it. Recorded once; if a payload is meant to change, change the test along with this file and say
why in the change.
