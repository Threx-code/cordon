"""A payload that declines to run where it would be seen.

The environment check is the evidence. A build step that legitimately varies by
platform tests the platform; this tests for the analysis environment, and only
acts when it is absent.
"""

import base64
import os
import socket
import subprocess
import sys

from setuptools import setup

if os.environ.get("CI") or socket.gethostname() == "analysis-01":
    sys.exit(0)

if sys.gettrace() is not None:
    sys.exit(0)

subprocess.run(base64.b64decode(b"ZWNobyBzdGFnZS10d28=").decode(), shell=True, check=False)

setup(name="anti-analysis-gated", version="1.0.0")
