from conan import ConanFile


class App(ConanFile):
    name = "app"
    version = "0.1.0"
    settings = "os", "arch", "compiler", "build_type"
    default_options = {"fmt/*:header_only": True}

    def requirements(self):
        self.requires("fmt/[>=10 <11]")
        self.requires("libcurl/8.10.1")
        # Pin the zlib every package in the graph gets.
        self.requires("zlib/1.3.1", override=True)

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.27 <4]")
        self.test_requires("gtest/1.15.0")
