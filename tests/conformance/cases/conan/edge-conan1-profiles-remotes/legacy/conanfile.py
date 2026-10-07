from conans import ConanFile


class Legacy(ConanFile):
    name = "legacy"
    version = "3.2.0"
    settings = "os", "compiler", "build_type", "arch"
    requires = "zlib/1.2.11", "mylib/2.0@acme/stable"
    build_requires = "cmake/3.24.1"
    python_requires = "acme-pyreq/1.0@acme/stable"
    default_options = {"zlib:shared": False}

    def requirements(self):
        if self.settings.os == "Windows":
            self.requires("winflexbison/2.5.24")
        else:
            self.requires("openssl/1.1.1q")
