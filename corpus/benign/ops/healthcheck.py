"""Health check: ask systemd, report the answer upstream."""

import subprocess

import requests


def check(service: str) -> bool:
    result = subprocess.run(["systemctl", "is-active", service], check=False)
    healthy = result.returncode == 0
    requests.get("https://status.example.com/ping", params={"ok": healthy})
    return healthy
