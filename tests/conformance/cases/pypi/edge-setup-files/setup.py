"""A legacy setup script. If any of it ran during a scan, the marker below would exist.

It also overrides the `install` command, which runs on the machine of everyone who installs the
package from source: the shape the scanner reports, here doing nothing but the normal install.
"""

import pathlib

from setuptools import setup
from setuptools.command.install import install

pathlib.Path("/tmp/cordon-conformance-executed-setup-py").write_text("executed")


class InstallWithTranslations(install):
    def run(self):
        install.run(self)


setup(
    name="legacy-tool",
    version="0.4.0",
    python_requires=">=3.8",
    install_requires=["click>=8.0,<9", "rich==13.7.1; python_version >= '3.8'"],
    setup_requires=["setuptools_scm==8.1.0"],
    tests_require=["pytest==8.3.3"],
    extras_require={"color": ["colorama==0.4.6"]},
    cmdclass={"install": InstallWithTranslations},
)
