"""A build helper that legitimately shells out. Spawn with no egress or decode."""
import subprocess
from pathlib import Path


def current_revision(repo: Path) -> str:
    """Read the commit id. There is no way to ask a checkout this without git."""
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def compile_assets(repo: Path) -> None:
    subprocess.run(["make", "-C", str(repo), "assets"], check=True)
