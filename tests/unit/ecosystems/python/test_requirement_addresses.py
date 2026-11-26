"""A requirement written as a bare address (pip's direct URL and VCS forms) is a dependency named as pip names it: the
`#egg=` fragment, else the file or repository the address names. Never `git` or `https`, the address's scheme."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent


class Kit:
    @staticmethod
    def names(text: str) -> dict[str, str]:
        adapter = EcosystemRegistry.get("pypi")
        assert adapter is not None
        parsed = adapter.parse_manifest(FileContent.from_bytes("requirements.txt", text.encode()))
        return {d.name: d.spec for d in parsed.dependencies}


class TestABareAddress:
    @pytest.mark.parametrize(
        ("line", "name"),
        [
            ("git+https://github.com/owner/y.git#egg=y", "y"),
            ("git+https://github.com/owner/repo.git@v1.2", "repo"),
            ("hg+https://hg.example.org/tool#egg=tool-x", "tool-x"),
            ("https://files.example.org/pkgs/z-1.2.0.tar.gz", "z"),
            ("https://files.example.org/w-2.0-py3-none-any.whl", "w"),
            ("https://files.example.org/archive/v3.zip#egg=v3pkg", "v3pkg"),
        ],
    )
    def test_it_is_named_as_pip_names_it(self, line: str, name: str) -> None:
        names = Kit.names(line + "\n")
        assert name in names, names
        assert "git" not in names and "https" not in names and "hg" not in names
        assert names[name].endswith(line.split("#", 1)[0][-10:]) or line in names[name]

    def test_a_named_requirement_is_unchanged(self) -> None:
        assert Kit.names("requests>=2\nflask @ https://files.example.org/flask-3.0.tar.gz\n") == {
            "requests": ">=2",
            "flask": "https://files.example.org/flask-3.0.tar.gz",
        }
