"""Planted credentials, and what the install did with them.

A payload that steals credentials needs credentials to steal. The sandbox's `$HOME` held nothing,
so a stealer found nothing, read nothing worth recording and sent nothing -- and the run read as
clean. Every run now plants decoys where real ones live (`~/.aws/credentials`, `~/.ssh/id_rsa`,
`~/.docker/config.json`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.kube/config`,
`~/.pypirc`, `~/.netrc`, `~/.npmrc`) and in the environment (`NPM_TOKEN`, `GITHUB_TOKEN`, the AWS
pair), each value generated for this run alone and shaped like the real thing, so a payload that
checks a token's format still takes it. None of them authenticates anywhere.

Two things are then read back:

* which decoy files were READ. Each is planted with its access time set far in the past, so any
  read moves it forward (the kernel's relatime rule updates an access time older than the file's
  modification); afterwards the times are listed. A package manager reading its own configuration
  (`npm` its `.npmrc`, `pip` its `.netrc`) is expected and not reported; anything else reading
  `~/.aws/credentials` during an install is.
* whether a decoy VALUE left the process: in the payload of a traced `sendto`/`sendmsg`, or in a
  name the install tried to resolve -- raw, hex-encoded or base64-encoded.

The install also sees `CI=true` and the variables a GitHub Actions runner sets, so a payload that
waits for CI before acting acts here.
"""

from __future__ import annotations

import base64
import binascii
import secrets
import shlex
import string
from dataclasses import dataclass, field
from typing import Final

PLANTED_ATIME: Final = 946684800
"""2000-01-01: older than any file's modification time, so a read always moves it."""

#: What each ecosystem's own installer reads of the planted files, and is therefore not reported.
EXPECTED_READS: Final[dict[str, frozenset[str]]] = {
    "npm": frozenset({".npmrc"}),
    "pypi": frozenset({".netrc", ".pypirc"}),
    "rubygems": frozenset({".gemrc", ".netrc"}),
}

CI_ENVIRONMENT: Final = (
    ("CI", "true"),
    ("GITHUB_ACTIONS", "true"),
    ("GITHUB_WORKFLOW", "release"),
    ("GITHUB_REPOSITORY", "acme/service"),
    ("GITHUB_REF", "refs/heads/main"),
    ("RUNNER_OS", "Linux"),
)


@dataclass
class Canaries:
    """One run's decoy credentials."""

    aws_key_id: str
    aws_secret: str
    github_token: str
    npm_token: str
    pypi_token: str
    ssh_key_body: str
    files: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def _random(alphabet: str, length: int) -> str:
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @classmethod
    def generate(cls) -> Canaries:
        upper = string.ascii_uppercase + "234567"
        mixed = string.ascii_letters + string.digits
        b64 = mixed + "+/"
        made = cls(
            aws_key_id="AKIA" + cls._random(upper, 16),
            aws_secret=cls._random(b64, 40),
            github_token="ghp_" + cls._random(mixed, 36),
            npm_token="npm_" + cls._random(mixed, 36),
            pypi_token="pypi-AgEIcHlwaS5vcmc" + cls._random(mixed, 60),
            ssh_key_body=cls._random(b64, 280),
        )
        made.files = {
            ".aws/credentials": (
                "[default]\n"
                f"aws_access_key_id = {made.aws_key_id}\n"
                f"aws_secret_access_key = {made.aws_secret}\n"
            ),
            ".ssh/id_rsa": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + "\n".join(made.ssh_key_body[i : i + 70] for i in range(0, 280, 70))
                + "\n-----END OPENSSH PRIVATE KEY-----\n"
            ),
            ".docker/config.json": (
                '{"auths": {"https://index.docker.io/v1/": {"auth": "'
                + base64.b64encode(f"deploy:{made.github_token}".encode()).decode()
                + '"}}}\n'
            ),
            ".git-credentials": f"https://deploy:{made.github_token}@github.com\n",
            ".config/gh/hosts.yml": f"github.com:\n    oauth_token: {made.github_token}\n    user: deploy\n",
            ".kube/config": (
                "apiVersion: v1\nkind: Config\nusers:\n- name: deploy\n  user:\n"
                f"    token: {made.aws_secret}\n"
            ),
            ".pypirc": f"[pypi]\nusername = __token__\npassword = {made.pypi_token}\n",
            ".netrc": f"machine github.com login deploy password {made.github_token}\n",
            ".npmrc": f"//registry.npmjs.org/:_authToken={made.npm_token}\n",
        }
        return made

    @property
    def environment(self) -> tuple[tuple[str, str], ...]:
        return (
            *CI_ENVIRONMENT,
            ("NPM_TOKEN", self.npm_token),
            ("GITHUB_TOKEN", self.github_token),
            ("AWS_ACCESS_KEY_ID", self.aws_key_id),
            ("AWS_SECRET_ACCESS_KEY", self.aws_secret),
        )

    def env_assignments(self) -> str:
        """`NAME=value` words for `env -i`, shell-quoted."""
        return " ".join(f"{name}={shlex.quote(value)}" for name, value in self.environment)

    def plant(self, home: str, uid: int) -> str:
        """Shell that writes each decoy, read time set far in the past.

        The decoys are ROOT's and world-readable; their directories are the install's. The install
        can read every decoy, which is the point, and write beside them (`~/.config` is a tool's
        too), but cannot set a decoy's times back -- only an owner can -- so a read cannot be
        hidden, and replacing a decoy leaves a file whose read time was never planted. Root reads
        the times afterwards, and with no `CAP_DAC_OVERRIDE` it can only do that in directories it
        may traverse, hence 0755.
        """
        steps = []
        directories: list[str] = []
        for relative, content in self.files.items():
            path = f"{home}/{relative}"
            parts = relative.split("/")[:-1]
            for depth in range(1, len(parts) + 1):
                directory = f"{home}/{'/'.join(parts[:depth])}"
                if directory not in directories:
                    directories.append(directory)
            encoded = base64.b64encode(content.encode()).decode()
            steps.append(
                f"mkdir -p {shlex.quote(path.rpartition('/')[0])} && echo {encoded} | base64 -d > "
                f"{shlex.quote(path)} && chmod 0644 {shlex.quote(path)}"
            )
        paths = " ".join(shlex.quote(f"{home}/{r}") for r in self.files)
        steps.append(f"touch -a -d @{PLANTED_ATIME} {paths}")
        if directories:
            quoted = " ".join(shlex.quote(d) for d in directories)
            steps.append(f"chmod 0755 {quoted} && chown {uid}:{uid} {quoted}")
        return " && ".join(steps)

    def planted_paths(self, home: str) -> frozenset[str]:
        """Every path the planting created: the decoys and the directories that hold them."""
        out: set[str] = set()
        for relative in self.files:
            parts = relative.split("/")
            for depth in range(1, len(parts) + 1):
                out.add(f"{home}/{'/'.join(parts[:depth])}")
        return frozenset(out)

    def read_times(self, home: str) -> str:
        paths = " ".join(shlex.quote(f"{home}/{r}") for r in self.files)
        return f"stat -c '%X %n' {paths} 2>/dev/null"

    # -- interpretation ------------------------------------------------------------------------

    def values(self) -> tuple[str, ...]:
        return (
            self.aws_key_id,
            self.aws_secret,
            self.github_token,
            self.npm_token,
            self.pypi_token,
            self.ssh_key_body[:40],
        )

    def _forms(self) -> list[tuple[str, str]]:
        """Each value in the encodings a payload sends it in, and what to call it."""
        forms: list[tuple[str, str]] = []
        for value in self.values():
            label = value[:4] + "..."
            forms.append((value, label))
            forms.append((value.lower(), label))
            forms.append((binascii.hexlify(value.encode()).decode(), label))
            forms.append((base64.b64encode(value.encode()).decode().rstrip("="), label))
        return forms

    def leaked_in(self, text: str | None) -> list[str]:
        if not text:
            return []
        lowered = text.lower()
        found = []
        for form, label in self._forms():
            if form and (form in text or (form.islower() and form in lowered)):
                found.append(label)
        return sorted(set(found))

    def reads(self, listing: str | None, home: str, ecosystem: str) -> list[str] | None:
        """Decoy files whose read time moved, less the installer's own; None if not listed."""
        if listing is None:
            return None
        expected = EXPECTED_READS.get(ecosystem, frozenset())
        read: list[str] = []
        for line in listing.splitlines():
            stamp, _, path = line.strip().partition(" ")
            if not stamp.isdigit() or not path.startswith(home + "/"):
                continue
            relative = path[len(home) + 1 :]
            if int(stamp) != PLANTED_ATIME and relative not in expected:
                read.append(relative)
        return sorted(read)


__all__ = ["CI_ENVIRONMENT", "EXPECTED_READS", "PLANTED_ATIME", "Canaries"]
