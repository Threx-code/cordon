# 40 · Air-gapped: a verified install and current intel with no network

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

A machine with no network needs two things carried to it: the scanner, and intel recent
enough to trust. Each crossing has to be checkable at the far end, because "somebody brought
a wheel in on a laptop" is the exact attack Cordon looks for in other people's pipelines.
Tutorial 11 explains why; this one is the procedure.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CONNECTED SIDE                          ISOLATED SIDE                   │
│                                                                          │
│  the release's wheel                     pip --require-hashes            │
│  + action/requirements.txt  ── carry ──► refuses any wheel whose digest  │
│    (its hash pin, at the tag)            is not in the pin               │
│                                                                          │
│  the release's signed bundle             advisories sync --bundle DIR    │
│  cordon-advisories.tar.gz   ── carry ──► Ed25519 signature checked       │
│  cordon-advisories.tar.gz.sig            against the key pinned in the   │
│                                          scanner, before anything is     │
│                                          unpacked                        │
│                                                                          │
│                                          scan --offline: no request at   │
│                                          all, and stale intel is said    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Step 1: install the scanner, hash-verified

On the connected side, fetch the wheel and its pin from the release:

```bash
mkdir cordon-carry && cd cordon-carry
curl -fsSLO https://raw.githubusercontent.com/Threx-code/cordon/v0.7.0/action/requirements.txt
python -m pip download --no-deps --only-binary=:all: --require-hashes -r requirements.txt -d .
```

Carry the folder across. On the isolated side, install from it with the index switched off;
pip refuses any file whose SHA-256 is not the one the release committed:

```bash
python -m venv /opt/cordon && . /opt/cordon/bin/activate
python -m pip install --no-index --find-links ./cordon-carry --require-hashes -r ./cordon-carry/requirements.txt
cordon-scanner --version
cordon-scanner verify          # every installed file against the wheel's RECORD
```

Offline, `verify` exits 4 rather than 0 on purpose: matching the RECORD proves the files were
not changed after install, not who built the wheel. The pin you carried is what ties the
wheel to the release; on the connected side `cordon-scanner verify --online` checks the
wheel's PyPI provenance, signed by Cordon's release workflow, as well.

## Step 2: keep the intel current

Intel older than a week makes a scan incomplete (exit 4) instead of quietly out of date, so
an isolated machine needs a way in for fresh intel. There are two, depending on how isolated
it is.

### If the site has an internal mirror (once the signed feed is on)

0.7.0 ships with Cordon's signed feed off: no feed root is pinned in this release, so until
one is, use the carried bundle below. When a release pins it, most air-gapped networks can
mirror the feed on their internal HTTPS mirror and point the scanner at it; every byte is
still verified against the root key pinned in the scanner, so the mirror needs no trust:

```bash
export CORDON_FEED_URL=https://mirror.internal.example/cordon-feed/v1
cordon-scanner intel update        # verify and apply the latest signed feed
cordon-scanner intel status        # source, serial and age
```

### If the machine has no network at all

Carry the release's signed advisory bundle, the two files `cordon-advisories.tar.gz` and
`cordon-advisories.tar.gz.sig` from the release's assets, and install them from the folder:

```bash
cordon-scanner advisories sync --bundle /media/usb/cordon-0.7.0/
```

The signature is checked against the key pinned in the scanner before anything is unpacked;
a bundle that does not verify writes nothing. What makes it trustworthy is the signature, not
the way it travelled, so the folder is as good as a download.

**Do not copy one machine's synced cache to another.** The cache is sealed by the install
that wrote it; copied files are reported as `OPERATIONAL.ADVISORY.TAMPERED` and ignored, and
the scan falls back to the intel the wheel shipped with.

### If your site refreshes less often than weekly

The week is a default, not a ceiling for the operator. A site that refreshes monthly says so
in its own configuration, passed with `--config`, where reviewers can see it:

```yaml
# /etc/cordon/operator.yaml: the operator's file, not the repository's
version: 1
scan:
  max_intel_age: 2592000     # 30 days, in seconds
```

```bash
cordon-scanner scan . --offline --config /etc/cordon/operator.yaml
```

A repository's own `cordon.yaml` can only make the limit shorter: a longer one there is
withheld and reported, because a scan target must not decide its own intel is never stale.

## Step 3: scan with no network

```bash
export CORDON_OFFLINE=1                 # or --offline on each command
cordon-scanner scan . --fail-on high --fail-on-incomplete
```

With `CORDON_OFFLINE` set nothing is attempted, not even the advisory refresh a normal scan
makes. An image's operating-system packages need their distribution's advisories, which are
synced on the scanning machine itself (`advisories sync --os debian`, which needs network);
where that cannot happen they are inventoried and reported as not matched
(`OPERATIONAL.IMAGE.NOT_MATCHED`), never as clean.

## In CI on an isolated runner

Bake steps 1 and 2 into the runner's image, rebuilt whenever a release or a fresh bundle
arrives, and use the templates' offline jobs: `.cordon-airgapped` in GitLab (tutorial 36),
or `ci/generic/scan.sh`, which runs the scanner image with `--network none` (tutorial 37).

Next: **[41 · AI agents](41-ai-agents.md)**.
