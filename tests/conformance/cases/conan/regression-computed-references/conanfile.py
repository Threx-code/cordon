from conan import ConanFile


class MagnumConan(ConanFile):
    name = "magnum"
    version = "2020.06"
    settings = "os", "arch", "compiler", "build_type"
    options = {"with_audio": [True, False]}
    default_options = {"with_audio": False}
    _boost_version = "1.83.0"

    def requirements(self):
        # conan-center builds references as often as it writes them.
        self.requires("corrade/{}".format(self.version))
        self.requires(f"boost/{self._boost_version}")
        self.requires("zlib/%s" % self._zlib_version())
        self.requires("fmt/" + "10.2.1")
        if self.options.with_audio:
            self.requires("openal/{0}@community/{1}".format("1.21.1", "stable"))

    def build_requirements(self):
        self.tool_requires(f"cmake/[>={self._cmake_minimum}]")

    def _zlib_version(self):
        return "1.3.1"
