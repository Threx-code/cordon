"""Sync job: copy files, then call a completion webhook."""

import subprocess

import requests


def sync(source: str, destination: str) -> None:
    subprocess.run(["rsync", "-a", source, destination], check=True)
    requests.post("https://hooks.example.com/sync-complete", json={"src": source})
