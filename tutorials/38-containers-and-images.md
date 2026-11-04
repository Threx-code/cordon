# 38 · Containers and images: before they are pushed or run

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

An image is everything a repository scan never sees: the base image's operating-system
packages, what `npm install` or `pip install` put in the layers, a binary copied in by a
`curl`. Cordon reads an image as an archive, layer by layer, without Docker and without
running it. Tutorial 08 covers the `Dockerfile` and Kubernetes files themselves; this one is
the built image.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  docker build ──► app.tar (docker save) ──► cordon-scanner scan app.tar  │
│                                                  │                       │
│        every layer, checked against its digest ──┤                       │
│                                                  ├─ OS packages ──► distribution advisories
│                                                  ├─ language packages ─► advisories, malware
│                                                  ├─ files the image adds beyond its
│                                                  │   packages ──► read for what they do
│                                                  └─ a file a later layer deleted is still
│                                                      read in the layer that holds it
│                                                                          │
│  exit 0 ──► docker push        exit 1 / 4 ──► the image is not shipped   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Level 1: an image you built, before you push it

```bash
docker build -t app:candidate .
docker save app:candidate -o app.tar
cordon-scanner scan app.tar --fail-on high
```

The result ends with what was read and what was matched instead, so nothing is left out
unsaid. For `node:22-slim` (250 MB), in 4 seconds:

```
OPERATIONAL.IMAGE.CONTENTS  66 files the image adds beyond its distribution's packages
                            were scanned, 9 file(s) a later layer removed were scanned in
                            the layer that holds them, and 199 installed language packages
                            were inventoried ...
```

## Level 2: match the operating-system packages offline

Language packages are matched against the bundled advisories. The distribution's own
packages need that distribution's advisories, synced once per machine (and weekly after):

```bash
cordon-scanner advisories sync --os debian            # or ubuntu, alpine, wolfi, chainguard,
                                                       # rocky, almalinux, redhat, suse, opensuse
cordon-scanner scan app.tar --offline --fail-on high
```

The same `node:22-slim`, after `advisories sync --os debian`: 227 operating-system package
findings (`VULNERABLE.IMAGE.PACKAGE.001`), 23 in its language packages, and the scan complete,
in 7 seconds. Without the sync, the result says the packages were inventoried and not matched
(`OPERATIONAL.IMAGE.NOT_MATCHED`) rather than calling them clean. `--online` matches them
through OSV's API instead, which sends the package names and versions to OSV.

## Level 3: an image from a registry, before you run it

```bash
cordon-scanner scan pkg:docker/nginx@1.27 --online
cordon-scanner scan pkg:docker/ghcr.io/acme/app@sha256:<digest> --online
```

Pulled from its registry without Docker: every layer checked against its digest, every
platform of a multi-platform image inventoried. A public image needs no account. One that
asks for credentials is refused, with the way round it: pull it with your own, `docker save`
it, and scan the archive as in level 1.

## Level 4: in the pipeline, between build and push

```yaml
# GitHub Actions
jobs:
  image:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      packages: write
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .
      - run: docker save ghcr.io/${{ github.repository }}:${{ github.sha }} -o image.tar
      - uses: Threx-code/cordon/action@v0.7.0
        with:
          target: image.tar
          fail-on: high
          sarif-file: cordon-image.sarif
      - run: docker push ghcr.io/${{ github.repository }}:${{ github.sha }}   # only after a pass
```

```yaml
# GitLab CI: build in one job, scan the saved image in the next, push only after both
image:build:
  stage: build
  image: docker:27
  services: [docker:27-dind]
  script:
    - docker build -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
    - docker save "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" -o image.tar
  artifacts:
    paths: [image.tar]
    expire_in: 1 day

image:scan:
  extends: .cordon                 # from the template, tutorial 36
  stage: test
  needs: [image:build]
  script:
    - cordon-scanner scan image.tar --fail-on high --format text --format codeclimate:gl-code-quality-report.json
```

Push in a later stage from the same `image.tar` (`docker load`), so what ships is what was
read.

## Level 5: what is already running

For a machine or a container that is already up, read its installed packages directly:

```bash
cordon-scanner scan --host /                    # this machine: OS and language packages
cordon-scanner scan --host / --home "$HOME"     # and this user's own installs (pipx, ~/.local)
```

And for the record of what an image contains, its SBOM (tutorial 23):

```bash
cordon-scanner sbom generate app.tar --format cyclonedx --output app.cdx.json
```

Next: **[39 · Rolling out across an organisation](39-rolling-out.md)**.
