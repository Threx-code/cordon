"""Deploy: push the branch, then tell the team. Ordinary ops work.

Fetches nothing and runs nothing it fetched -- but it does make a network call
and start a subprocess, which is what SUSPECT.DROPPER.001 used to require.
"""

import subprocess

import requests


def deploy(branch: str) -> None:
    subprocess.run(["git", "push", "origin", branch], check=True)
    requests.post("https://hooks.example.com/deploy", json={"branch": branch})
