"""Download a pinned release archive and unpack it next to this script."""

import hashlib
import subprocess
import urllib.request

ARCHIVE = "tool-1.4.2.tar.gz"
DIGEST = "3f2a9c0d6c1b5e8a7d4f1e2b9c8a7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c"

urllib.request.urlretrieve(f"https://releases.example.org/tool/{ARCHIVE}", ARCHIVE)
with open(ARCHIVE, "rb") as handle:
    if hashlib.sha256(handle.read()).hexdigest() != DIGEST:
        raise SystemExit("digest mismatch")
subprocess.run(["tar", "xzf", ARCHIVE], check=True)
subprocess.run(["./tool/bin/tool", "--version"], check=True)
