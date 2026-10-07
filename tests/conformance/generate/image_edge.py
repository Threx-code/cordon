"""Writes cases/image/edge-layers-and-history/image.tar: an OCI image layout whose index names a
platform index (as a multi-platform push leaves it), built layer by layer so the shapes a real
build leaves behind are all present at once:

* Debian 12's dpkg database -- real bookworm package names, versions and `Depends` -- with apt's
  `extended_states` marking what `apt-get install curl ca-certificates` pulled in automatically;
* a layer that adds `app/.env` and a later layer whose whiteout deletes it: gone from the running
  container, still in the image for anyone who pulls it;
* a build argument expanded into the history (`|1 NPM_TOKEN=... RUN npm ci`) and a credential set
  with `ENV`, both shipped in the configuration;
* the base image named, and pinned, in the OCI base labels.

The credentials are placeholders in the shapes the secret rules recognise, and belong to nothing.
Deterministic: fixed timestamps and member order. Run inside Docker only:

    docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/image_edge.py
"""

import hashlib
import io
import json
import tarfile
from pathlib import Path

CASE = Path("/conformance/cases/image/edge-layers-and-history")
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class Build:
    """What the image is made of."""

    @staticmethod
    def placeholder(label: str, length: int) -> str:
        """Base62 from a fixed hash: the shape a real credential has, and none of its use."""
        number = int.from_bytes(
            hashlib.sha512(f"cordon-conformance:{label}".encode()).digest(), "big"
        )
        out = ""
        while len(out) < length:
            number, digit = divmod(number, 62)
            out += ALPHABET[digit]
        return out

    @staticmethod
    def stanza(name: str, version: str, source: str, depends: str, provides: str) -> str:
        lines = [
            f"Package: {name}",
            "Status: install ok installed",
            "Architecture: amd64",
            f"Version: {version}",
        ]
        if source:
            lines.append(f"Source: {source}")
        if depends:
            lines.append(f"Depends: {depends}")
        if provides:
            lines.append(f"Provides: {provides}")
        lines.append("Description: from Debian 12")
        return "\n".join(lines) + "\n"

    @staticmethod
    def layer(files: dict[str, bytes | None]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, data in files.items():
                if data is None:
                    directory, _, base = path.rpartition("/")
                    path, data = (f"{directory}/.wh.{base}" if directory else f".wh.{base}"), b""
                info = tarfile.TarInfo(path)
                info.size, info.mtime, info.mode = len(data), 1767225600, 0o644
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def sha(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()


GITHUB_TOKEN = "ghp_" + Build.placeholder("github", 36)
NPM_TOKEN = "npm_" + Build.placeholder("npm", 36)
# Shorter than a real Stripe key (24 characters and up): the secret rule, which accepts 20 or more,
# still matches it, and it is not the shape of a key anybody could hold, which is also why a
# hosting provider's push protection accepts it.
STRIPE_KEY = "sk_test_" + Build.placeholder("stripe", 22)

DEBIAN_RELEASE = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nID=debian\n'
PACKAGES = [
    ("base-files", "12.4+deb12u9", "", "", ""),
    ("libc6", "2.36-9+deb12u9", "glibc", "libgcc-s1", ""),
    ("libgcc-s1", "12.2.0-14", "gcc-12", "gcc-12-base, libc6 (>= 2.35)", ""),
    ("gcc-12-base", "12.2.0-14", "gcc-12", "", ""),
    ("libssl3", "3.0.15-1~deb12u1", "openssl", "libc6 (>= 2.34)", ""),
    ("openssl", "3.0.15-1~deb12u1", "", "libc6 (>= 2.34), libssl3 (>= 3.0.9)", ""),
    ("ca-certificates", "20230311", "", "openssl (>= 1.1.1), debconf (>= 0.5) | debconf-2.0", ""),
    ("debconf", "1.5.82", "", "", "debconf-2.0"),
    (
        "libcurl4",
        "7.88.1-10+deb12u8",
        "curl",
        "libc6 (>= 2.34), libssl3 (>= 3.0.0) | libgnutls30",
        "",
    ),
    ("curl", "7.88.1-10+deb12u8", "", "libc6 (>= 2.34), libcurl4 (= 7.88.1-10+deb12u8)", ""),
]
AUTOMATIC = ["libcurl4", "openssl", "libssl3"]


layers = [
    Build.layer(
        {
            "etc/os-release": DEBIAN_RELEASE,
            "var/lib/dpkg/status": "\n".join(Build.stanza(*p) for p in PACKAGES).encode(),
            "var/lib/apt/extended_states": "\n".join(
                f"Package: {n}\nArchitecture: amd64\nAuto-Installed: 1\n" for n in AUTOMATIC
            ).encode(),
        }
    ),
    Build.layer(
        {
            "app/.env": f"GITHUB_TOKEN={GITHUB_TOKEN}\n".encode(),
            "app/server.js": b"require('http').createServer().listen(8080);\n",
        }
    ),
    Build.layer({"app/.env": None}),
]
config = json.dumps(
    {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-01-01T00:00:00Z",
        "config": {
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                f"STRIPE_API_KEY={STRIPE_KEY}",
            ],
            "Cmd": ["node", "/app/server.js"],
            "Labels": {
                "org.opencontainers.image.base.name": "docker.io/library/debian:12-slim",
                "org.opencontainers.image.base.digest": "sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587",
                "org.opencontainers.image.source": "https://github.com/acme/edge-app",
            },
        },
        "rootfs": {"type": "layers", "diff_ids": [Build.sha(data) for data in layers]},
        "history": [
            {"created_by": "# debian.sh --arch 'amd64' out/ 'bookworm' '@1767225600'"},
            {
                "created_by": "RUN /bin/sh -c apt-get update && apt-get install -y --no-install-recommends curl ca-certificates # buildkit"
            },
            {
                "created_by": f"RUN |1 NPM_TOKEN={NPM_TOKEN} /bin/sh -c npm ci && rm -f /app/.env # buildkit"
            },
        ],
    },
    sort_keys=True,
).encode()
manifest = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": Build.sha(config),
            "size": len(config),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": Build.sha(data),
                "size": len(data),
            }
            for data in layers
        ],
    },
    sort_keys=True,
).encode()
platforms = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": Build.sha(manifest),
                "size": len(manifest),
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    },
    sort_keys=True,
).encode()
index = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": Build.sha(platforms),
                "size": len(platforms),
                "annotations": {
                    "io.containerd.image.name": "ghcr.io/acme/edge-app:2.1.0",
                    "org.opencontainers.image.ref.name": "2.1.0",
                },
            }
        ],
    },
    sort_keys=True,
).encode()
CASE.mkdir(parents=True, exist_ok=True)
with tarfile.open(CASE / "image.tar", mode="w", format=tarfile.PAX_FORMAT) as archive:
    members = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", index)]
    members += [
        (f"blobs/sha256/{Build.sha(blob)[7:]}", blob)
        for blob in (*layers, config, manifest, platforms)
    ]
    for name, data in members:
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.mode = len(data), 1767225600, 0o644
        archive.addfile(info, io.BytesIO(data))
print(
    "image.tar",
    (CASE / "image.tar").stat().st_size,
    "index",
    Build.sha(platforms),
    "config",
    Build.sha(config),
)
print("layers", [Build.sha(data) for data in layers])
print("never_disclosed", GITHUB_TOKEN, NPM_TOKEN, STRIPE_KEY)
