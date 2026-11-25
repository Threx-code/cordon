"""An install names a package and, when it pins one, a version."""

from __future__ import annotations

from cordon_scanner.ecosystems.specs.install_specs import InstallSpec


class TestInstallSpec:
    def test_npm_names_with_and_without_a_version(self) -> None:
        assert InstallSpec.split("npm", "left-pad@1.3.0") == ("left-pad", "1.3.0")
        assert InstallSpec.split("npm", "left-pad") == ("left-pad", None)

    def test_a_scoped_npm_name_keeps_its_scope(self) -> None:
        assert InstallSpec.split("npm", "@acme/util@2.1.0") == ("@acme/util", "2.1.0")
        assert InstallSpec.split("npm", "@acme/util") == ("@acme/util", None)

    def test_pip_pins_only_with_a_double_equals(self) -> None:
        assert InstallSpec.split("pypi", "requests==2.31.0") == ("requests", "2.31.0")
        assert InstallSpec.split("pypi", "requests>=2") == ("requests", None)
        assert InstallSpec.split("pypi", "requests") == ("requests", None)

    def test_pip_extras_are_not_part_of_the_name(self) -> None:
        assert InstallSpec.split("pypi", "requests[socks]==2.31.0") == ("requests", "2.31.0")
