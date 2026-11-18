# fixture: a setup file with no custom install command (python)
from setuptools import setup

setup(name="notes-mcp-server", version="1.0.0", install_requires=["mcp>=1.0"])
