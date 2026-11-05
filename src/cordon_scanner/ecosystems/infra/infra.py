"""Ecosystems outside the language package managers: infrastructure, systems and functional.

Terraform providers and modules, Helm charts, Ansible Galaxy roles and collections, Nix flakes,
vcpkg ports, Homebrew formulae, casks and taps, and the Haskell, Julia and OCaml package sets.
Each one fetches and runs code someone else wrote -- a Terraform provider is a binary with the
cloud credentials, a Galaxy role runs as root on every host it touches. Each lives in its own
module; this one gathers them where they have always been imported from.

Graphed so the shared layers reach them: provenance (a provider from a host that is not a
registry, a role from a git URL, a third-party Homebrew tap), the advisory layer where OSV
publishes a feed (Hackage, Julia, opam), registry verification, look-alike names, and the SBOM.

Several formats carry no per-package hash (`records_integrity = False`), and several ecosystems
have no single registry (Helm repositories, Nix flake inputs): a missing hash or a chart from its
own repository is the format, not an anomaly, and is not reported as one.
"""

from __future__ import annotations

from cordon_scanner.ecosystems.infra.ansible import AnsibleGalaxyEcosystem
from cordon_scanner.ecosystems.infra.helm import HelmEcosystem
from cordon_scanner.ecosystems.infra.image import ImageEcosystem
from cordon_scanner.ecosystems.infra.terraform import TerraformEcosystem
from cordon_scanner.ecosystems.packages.hackage import HackageEcosystem
from cordon_scanner.ecosystems.packages.homebrew import HomebrewEcosystem
from cordon_scanner.ecosystems.packages.julia import JuliaEcosystem
from cordon_scanner.ecosystems.packages.nix import NixEcosystem
from cordon_scanner.ecosystems.packages.ocaml.opam import OpamEcosystem
from cordon_scanner.ecosystems.packages.vcpkg import VcpkgEcosystem

INFRA_ECOSYSTEMS = (
    TerraformEcosystem(),
    HelmEcosystem(),
    AnsibleGalaxyEcosystem(),
    NixEcosystem(),
    VcpkgEcosystem(),
    HomebrewEcosystem(),
    HackageEcosystem(),
    JuliaEcosystem(),
    OpamEcosystem(),
    ImageEcosystem(),
)

__all__ = [
    "INFRA_ECOSYSTEMS",
    "AnsibleGalaxyEcosystem",
    "HackageEcosystem",
    "HelmEcosystem",
    "HomebrewEcosystem",
    "ImageEcosystem",
    "JuliaEcosystem",
    "NixEcosystem",
    "OpamEcosystem",
    "TerraformEcosystem",
    "VcpkgEcosystem",
]
