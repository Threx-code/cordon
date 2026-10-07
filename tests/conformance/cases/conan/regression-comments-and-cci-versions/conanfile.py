"""Builds the service.

Older revisions called self.requires("legacy-docs/1.0") here; see the changelog.
"""

from conan import ConanFile


class Service(ConanFile):
    name = "service"
    version = "2.4.0"

    def requirements(self):
        # self.requires("removed-in-review/0.9")
        self.requires("gnu-config/cci.20210814")
        self.requires("abseil/[>=20230802 <20250000]")
        message = 'self.requires("in-a-string/1.0")'
        self.output.info(message)
