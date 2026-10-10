from conan import ConanFile


class ZlibConan(ConanFile):
    name = "zlib"
    settings = "os", "arch", "compiler", "build_type"
