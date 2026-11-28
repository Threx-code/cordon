"""A file a rule reads for the dependencies it names is a file that dependency's ecosystem reads too.

The agent and CI rules read their own path lists. Where a listed file names packages, images or extensions, the
ecosystem that owns those must claim the same file, or the inventory misses what a rule sees (and two readers of one
file once reported one fact twice). Each list is held to its owning ecosystem here, every glob of it; a file that
names no dependency carries its reason; a file the owner does not read yet is a strict expected failure until it does.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner.detect.agents.paths import (
    BREWFILE_PATHS,
    EXTENSION_PATHS,
    GITPOD_PATHS,
    WORKFLOW_PATHS,
)
from cordon_scanner.detect.infra.config_paths import CI_PATHS, DOCKER_PATHS, IAC_PATHS
from cordon_scanner.ecosystems.registry import EcosystemRegistry


class Parity:
    #: Each rule's path list and the ecosystem that owns what its files name.
    LISTS: ClassVar[tuple[tuple[str, tuple[str, ...], str], ...]] = (
        ("workflows", WORKFLOW_PATHS, "actions"),
        ("ci", CI_PATHS, "image"),
        ("docker", DOCKER_PATHS, "image"),
        ("iac", IAC_PATHS, "image"),
        ("brewfile", BREWFILE_PATHS, "homebrew"),
        ("extensions", EXTENSION_PATHS, "vscode"),
        ("gitpod", GITPOD_PATHS, "vscode"),
    )
    #: A GitHub workflow's packages are its actions (the images it names are read by the same adapter).
    OWNER_OF: ClassVar[dict[str, str]] = {
        "**/.github/workflows/*.yml": "actions",
        "**/.github/workflows/*.yaml": "actions",
        "**/*.tf": "terraform",
    }
    #: Files a rule reads that name no dependency, each with why.
    NAMES_NONE: ClassVar[dict[str, str]] = {
        "**/*.tfvars": "a Terraform variables file sets values; providers and modules are named in the .tf files",
    }
    #: Files a rule reads that the owner does not read yet: each fails loudly once it does, until it comes off. None now:
    #: the image adapter reads every CI pipeline file and chart-folder manifest (`CiFiles`).
    BUILDING: ClassVar[frozenset[str]] = frozenset()

    @staticmethod
    def sample(glob: str) -> str:
        """A path the glob matches: each wildcard replaced by a plain name."""
        return glob.replace("**/", "").replace("**", "x").replace("*", "app")

    @classmethod
    def cells(cls) -> list[object]:
        out: list[object] = []
        for label, paths, owner in cls.LISTS:
            for glob in paths:
                if glob in cls.NAMES_NONE:
                    continue
                marks = (
                    [pytest.mark.xfail(strict=True, reason="the owner does not read this file yet")]
                    if glob in cls.BUILDING
                    else []
                )
                out.append(
                    pytest.param(
                        glob, cls.OWNER_OF.get(glob, owner), marks=marks, id=f"{label}:{glob}"
                    )
                )
        return out


class TestEveryRuleFileIsReadByItsEcosystem:
    @pytest.mark.parametrize(("glob", "owner"), Parity.cells())
    def test_the_owner_claims_the_file(self, glob: str, owner: str) -> None:
        path = Parity.sample(glob)
        claimed = {
            EcosystemRegistry.manifest_ecosystem(path),
            EcosystemRegistry.lockfile_ecosystem(path),
        }
        assert owner in claimed, (
            f"{path}: read by a rule, claimed by {claimed - {None} or 'nothing'}"
        )

    def test_every_exception_is_a_listed_file_with_a_reason(self) -> None:
        listed = {g for _, paths, _ in Parity.LISTS for g in paths}
        assert set(Parity.NAMES_NONE) <= listed
        assert listed >= Parity.BUILDING
        assert all(len(why) > 30 for why in Parity.NAMES_NONE.values())
