"""Where the configuration rules look, and the patterns several of them share.

The path sets that name each kind of configuration file (CI, container, IaC, Helm, Ansible,
CloudFormation, build systems), the markers that recognise a file's dialect from its content, and
the patterns more than one rule, or the detector itself, reads: a verified fetch, an untrusted
trigger or destination, a secret beside egress.
"""

from __future__ import annotations

import re

VERIFIED_FETCH = re.compile(
    rb"(?i)(?:"
    # A pinned reference, as well as a verified one. The two are not the same
    # strength and they are both answers to the same question: what the build will
    # run is decided before the build, not by whoever controls a host today.
    #
    # `dotnet/dotnet-docker` produced 34 findings at HIGH, every one this line in
    # the official .NET base images:
    #
    #     curl --output /usr/bin/chisel-wrapper \
    #       https://raw.githubusercontent.com/canonical/rocks-toolbox/v1.2.0/chisel-wrapper
    #     chmod 755 /usr/bin/chisel-wrapper
    #
    # Downloading a released binary and making it executable is how a container image
    # installs a tool, and `vimagick/dockerfiles` supplied the same shape for cadvisor,
    # confd, the Home Assistant CLI and yt-dlp. The rule's comment claimed the pair
    # "has no innocent reading", and the measurement disagreed: 291 findings across 122
    # of 1,487 repositories.
    #
    # A step down rather than silence, and the unpinned forms keep their severity --
    # `curl https://sh.rustup.rs | sh` and `curl https://bootstrap.saltstack.com | bash`
    # are in the same corpus and are exactly what this rule is for.
    rb"/v?\d+\.\d+(?:\.\d+)?/"
    # A version supplied by a VARIABLE, which is how a pipeline writes the same pin.
    # `FuelLabs/fuels-rs` downloads
    # `.../sway/releases/download/v${{ env.FORC_VERSION }}/forc-binaries-linux_amd64.tar.gz`
    # and the `/releases/download/[^/\s]{1,80}/` alternative below could not see it,
    # because a GitHub Actions expression has SPACES inside its braces and `[^/\s]`
    # refuses them. The version is pinned; it is pinned one line further up, in `env`.
    #
    # The variable has to NAME a version. `${{ github.event.pull_request.head.ref }}`
    # in a download path is attacker-controlled and is the opposite of a pin, so an
    # expression on its own is not enough.
    rb"|\$\{\{[^}]{0,60}(?:VERSION|TAG|RELEASE|REVISION|version|tag|release)[^}]{0,40}\}\}"
    # `MAJOR`, `MINOR` and `VER` as well as `VERSION`. `linuxserver` and half a dozen
    # others write `setup_${NODE_MAJOR}.x`, which is the same pin under the name the
    # NodeSource documentation uses.
    rb"|\$\{?(?:[A-Z_]{0,30})(?:VERSION|VER|MAJOR|MINOR|TAG|RELEASE|REVISION)[A-Z_]{0,30}\}?"
    # A version TOKEN that is not bounded by slashes. `curl -fsSL https://bun.com/install
    # | bash -s "bun-v1.3.14"` puts the pin in the argument rather than the path, and
    # `sccache-v0.4.1-${RUNNER_ARCH}` puts it in the filename. The leading separator is
    # what keeps this from matching a version inside an opaque token.
    rb"|[-@_ \"']v?\d+\.\d+\.\d+\b"
    # A checksum computed from what was fetched. The `echo ... | sha256sum` form was
    # here; `ACTUAL=$(curl ... | sha256sum | cut -d\' \' -f1)` is the same verification
    # written the other way round, and Puppeteer's Chrome-for-Testing download does it.
    rb"|\|[ \t]*sha(?:256|512)sum"
    rb"|/releases/download/[^/\s]{1,80}/"
    rb"|/archive/refs/tags/"
    rb"|/refs/tags/"
    rb"|@[0-9a-f]{40}\b"
    rb"|[?&](?:ref|sha|commit)=[0-9a-f]{7,40}\b"
    rb"|sha(?:1|256|512)sum[ \t]+(?:-c|--check)"
    rb"|shasum[ \t]+-a[ \t]*\d+[^\n]{0,80}(?:-c|--check)"
    rb"|md5sum[ \t]+(?:-c|--check)"
    rb"|gpg[^\n]{0,80}--verify"
    rb"|cosign[ \t]+verify"
    rb"|minisign[ \t]+-V"
    rb"|--checksum[= \t]"
    rb"|CHECKSUM[ \t]*="
    rb"|_sum[ \t]*="
    rb"|echo[^\n]{0,120}\|[ \t]*sha(?:256|512)sum"
    rb")"
)

CI_PATHS = (
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
    "**/.gitlab-ci.yml",
    "**/.gitlab-ci.yaml",
    "**/Jenkinsfile",
    "**/Jenkinsfile.*",
    "**/azure-pipelines.yml",
    "**/azure-pipelines.yaml",
    "**/.azure-pipelines/*.yml",
    "**/.circleci/config.yml",
    "**/.circleci/config.yaml",
    "**/bitbucket-pipelines.yml",
    "**/.buildkite/*.yml",
    "**/.buildkite/*.yaml",
    "**/cloudbuild.yaml",
    "**/cloudbuild.yml",
    "**/.drone.yml",
    "**/.woodpecker.yml",
)

DOCKER_PATHS = (
    "**/Dockerfile",
    "**/Dockerfile.*",
    "**/Containerfile",
    "**/docker-compose.yml",
    "**/docker-compose.yaml",
    "**/compose.yml",
    "**/compose.yaml",
)

IAC_PATHS = (
    "**/*.tf",
    "**/*.tfvars",
    "**/k8s/**/*.yaml",
    "**/k8s/**/*.yml",
    "**/kubernetes/**/*.yaml",
    "**/kubernetes/**/*.yml",
    "**/*.k8s.yaml",
    "**/helm/**/*.yaml",
    "**/manifests/**/*.yaml",
    "**/manifests/**/*.yml",
    "**/deploy/**/*.yaml",
    "**/deploy/**/*.yml",
    "**/charts/**/*.yaml",
    "**/overlays/**/*.yaml",
    "**/base/**/*.yaml",
)
"""Fast path only. `**/k8s/*.yaml` matched files directly in a `k8s` directory
and not `k8s/prod/pod.yaml` one level down, which is why every entry now uses
`**`. Correctness comes from K8S_MARKER, not from this list."""

K8S_MARKER = b"apiVersion"
"""What actually identifies a Kubernetes manifest.

Checked in the first few kilobytes of any `.yaml`/`.yml` file, wherever it
lives. Byte-identical privileged pod manifests were previously found in `k8s/`
and missed in `deploy/`, `manifests/` and the repository root."""


__all__ = ["CI_PATHS", "DOCKER_PATHS", "IAC_PATHS", "K8S_MARKER", "VERIFIED_FETCH"]
