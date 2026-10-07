from conan import ConanFile


class LibB(ConanFile):
    name = "libb"
    version = "0.1"

    def requirements(self):
        self.requires("liba/0.1")
        self.requires("zlib/1.3.1")
        self.requires("fmt/10.2.1")
