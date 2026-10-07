# 24 · Policy for every repository

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

An organisation policy is the ceiling (tutorial 14): what no repository may disable,
suppress or raise. With more than a handful of repositories it cannot be copied into
each one: the copies drift, and a drifted ceiling is worse than none, because everyone
believes it is in force. So the policy is published once and pinned by digest.

```
                 ┌───────────────────────────────────────────┐
                 │  https://policy.acme.example/cordon.yaml  │
                 └─────────────────────┬─────────────────────┘
                                       │ sha256 = 9f2c...e41a
          ┌────────────────────────────┼────────────────────────────┐
          ▼                            ▼                            ▼
   repo A: --policy URL#sha256   repo B: --policy URL#sha256   CI runner cache
   verified, then applied        verified, then applied        (by digest; no
                                                                network next time)
```

## Pin it by digest

```
   cordon-scanner scan . --allow-network \
     --policy "https://policy.acme.example/cordon.yaml#sha256=<64 hex>"
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│  A URL without #sha256=     refused                                      │
│  served bytes that differ   refused, and the scan stops                  │
│  network not allowed        refused: fetching needs --allow-network      │
│  verified once              cached by digest; the next scan is offline   │
└──────────────────────────────────────────────────────────────────────────┘
```

Whoever controls the host, the CDN or a stale DNS entry could otherwise switch the
control off in every repository at once. With the digest the network is only a
transport: a compromised host serves something that does not verify.

A local file can be pinned the same way, `path/to/cordon.yaml#sha256=<hex>`.

## Fetch it ahead of time

```
   cordon-scanner config fetch-policy "https://policy.acme.example/cordon.yaml#sha256=<hex>"
```

Verifies and caches it, so CI runners and air-gapped machines scan with no network.
An air-gapped site can fill the cache by hand: it is keyed by the digest.

## Catch a vendored copy that drifted

Some repositories keep a copy in the tree. Compare it with what is published:

```
   cordon-scanner config policy-drift cordon-policy.yaml \
     --published "https://policy.acme.example/cordon.yaml#sha256=<hex>"
```

Compared by digest; nothing is fetched. Exit 1 when the copy differs.

## Keeping every pin of Cordon current

Repositories pin the scanner exactly: the Action by commit, pip by version and hash,
pre-commit by rev, the runner image by digest. That is right, and it means a fix needs
the same four edits everywhere. `scripts/bump_cordon_pins.py` makes them, and only them:

```
   uses: <owner>/cordon/action@<40 hex>  # vX.Y.Z    ─►  the release's commit and tag
   cordon-scanner==X.Y.Z --hash=sha256:...           ─►  its version and wheel hashes
   rev: <tag or sha>      (.pre-commit-config.yaml)  ─►  the release tag
   ghcr.io/<owner>/cordon-runner@sha256:<digest>     ─►  the runner's digest
```

`ci/github/cordon-pin-bump.yml` runs it on a schedule and opens a pull request per
repository. Only pin files are opened, so a version in a README or a test fixture is
never rewritten.

Next: **[25 · Every ecosystem](25-every-ecosystem.md)**.
