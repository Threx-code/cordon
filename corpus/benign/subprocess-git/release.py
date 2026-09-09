"""Ordinary tooling that spawns processes with command strings.

The commands are real and the spawn is real; none of them reaches the network
with a credential, which is what separates this from the malicious samples.
"""

import subprocess


def current_revision() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def build() -> None:
    subprocess.run(["python", "-m", "build", "--sdist", "--wheel"], check=True)
    subprocess.run("git describe --tags --always", shell=True, check=True)
