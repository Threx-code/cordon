"""The remaining ecosystems: Maven, Gradle, Cargo, Go, NuGet, Composer,
RubyGems, CocoaPods and pub.

Each is deliberately small. That is the architectural claim being tested:
supporting an ecosystem should cost a parser and a name-normalisation rule, not
a change to the engine, the rule packs or the detectors.

Every one of them implements the same two things that actually matter for
supply-chain risk: which paths execute during a build, and whether a dependency
resolves from somewhere other than the ecosystem's own registry.
"""

from __future__ import annotations

# Each `*Ecosystem` imported below from its own module (GitHub Actions, Bazel, CocoaPods, Composer,
# Conan, Conda, CRAN, Gradle, Hex, NuGet, Pub, RubyGems, Swift) is re-exported where it always lived.
from cordon_scanner.ecosystems.infra.actions import GitHubActionsEcosystem
from cordon_scanner.ecosystems.infra.bazel import BazelEcosystem
from cordon_scanner.ecosystems.packages.cocoapods import CocoaPodsEcosystem
from cordon_scanner.ecosystems.packages.composer import ComposerEcosystem
from cordon_scanner.ecosystems.packages.conan import ConanEcosystem
from cordon_scanner.ecosystems.packages.conda import CondaEcosystem
from cordon_scanner.ecosystems.packages.cran import CranEcosystem
from cordon_scanner.ecosystems.packages.hex import HexEcosystem
from cordon_scanner.ecosystems.packages.jvm.gradle import GradleEcosystem
from cordon_scanner.ecosystems.packages.nuget import NuGetEcosystem
from cordon_scanner.ecosystems.packages.pub import PubEcosystem
from cordon_scanner.ecosystems.packages.rubygems import RubyGemsEcosystem
from cordon_scanner.ecosystems.packages.swift import SwiftEcosystem

__all__ = [
    "BazelEcosystem",
    "CocoaPodsEcosystem",
    "ComposerEcosystem",
    "ConanEcosystem",
    "CondaEcosystem",
    "CranEcosystem",
    "GitHubActionsEcosystem",
    "GradleEcosystem",
    "HexEcosystem",
    "NuGetEcosystem",
    "PubEcosystem",
    "RubyGemsEcosystem",
    "SwiftEcosystem",
]
