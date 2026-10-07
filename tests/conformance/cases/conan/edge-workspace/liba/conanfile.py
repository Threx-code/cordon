from conan import ConanFile


class LibA(ConanFile):
    name = "liba"
    version = "0.1"

    def requirements(self):
        self.requires("zlib/1.3.1")
