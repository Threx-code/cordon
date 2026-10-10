from conan import ConanFile


class LibpngConan(ConanFile):
    name = "libpng"
    settings = "os", "arch", "compiler", "build_type"

    def requirements(self):
        self.requires("zlib/[>=1.2.11 <2]")
