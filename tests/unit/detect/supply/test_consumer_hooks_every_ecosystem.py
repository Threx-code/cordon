"""The commands a package runs when it is installed as a dependency, declared by every ecosystem (`ConsumerHooks` / `NoConsumerHooks`),
and the install-hook shapes read off them.

The files are real (`hook_captures/CAPTURES.md`): a Terraform module with a `local-exec` provisioner, a composite action, a nixpkgs
`package.nix`, a `.targets` file with `<Exec>` and Homebrew's jq formula. A shape fires on a real hook whose command is replaced by
one that carries an inline program, so each case proves the table, the parser and the severity together: HIGH where the shapes were
measured (npm), MEDIUM everywhere else."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.supply.manifests.install_hook_shapes import (
    INLINE_RULE,
    InstallHookShapes,
)
from cordon_scanner.ecosystems.install_marks import ConsumerHooks, NoConsumerHooks
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Hook
from cordon_scanner.rules.loader import RuleSet
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "detect" / "supply" / "hook_captures"

#: (ecosystem, the path a package carries the file at, the real file, a hook name the parser surfaces from it)
REAL = [
    ("terraform", "main.tf", "terraform-aws-lambda-package.tf", "local-exec"),
    ("actions", "action.yml", "upload-pages-artifact-action.yml", "steps-0"),
    ("nix", "package.nix", "bash-completion-package.nix", "checkPhase"),
    ("nuget", "build/tests.targets", "dotnet-runtime-tests.targets", "Exec"),
    ("homebrew", "Formula/j/jq.rb", "jq.rb", "system"),
]


class Real:
    @staticmethod
    def hooks(ecosystem: str, path: str, capture: str) -> list[Hook]:
        raw = (CAPTURES / capture).read_bytes()
        adapter = EcosystemRegistry.get(ecosystem)
        assert adapter is not None
        return list(adapter.parse_manifest(FileContent.from_bytes(path, raw)).hooks)


class TestEveryEcosystemDeclaresItsConsumerHooks:
    def test_each_declares_the_hooks_or_why_it_has_none(self) -> None:
        for adapter in EcosystemRegistry.all_ecosystems():
            declared = adapter.consumer_hooks
            assert isinstance(declared, ConsumerHooks | NoConsumerHooks), adapter.id
            if isinstance(declared, NoConsumerHooks):
                assert len(declared.reason.split()) >= 10, adapter.id
            else:
                assert declared.names, adapter.id

    def test_only_npm_was_measured(self) -> None:
        measured = {
            a.id
            for a in EcosystemRegistry.all_ecosystems()
            if isinstance(a.consumer_hooks, ConsumerHooks) and a.consumer_hooks.measured
        }
        assert measured == {"npm"}

    def test_the_ecosystems_with_hooks_are_the_ones_whose_commands_a_parser_surfaces(self) -> None:
        declared = {
            a.id
            for a in EcosystemRegistry.all_ecosystems()
            if isinstance(a.consumer_hooks, ConsumerHooks)
        }
        assert declared == {
            "npm",
            "cocoapods",
            "opam",
            "actions",
            "homebrew",
            "nix",
            "terraform",
            "nuget",
        }


class TestRealFilesSurfaceTheirHooks:
    @pytest.mark.parametrize(
        ("ecosystem", "path", "capture", "name"), REAL, ids=[r[0] for r in REAL]
    )
    def test_the_parser_surfaces_the_command_and_the_table_holds_its_name(
        self, ecosystem: str, path: str, capture: str, name: str
    ) -> None:
        hooks = Real.hooks(ecosystem, path, capture)
        declared = EcosystemRegistry.consumer_hooks(ecosystem)
        assert declared is not None
        held = [h for h in hooks if declared.holds(h.name) and h.command]
        assert held, [(h.name, h.command) for h in hooks]
        assert any(h.name == name for h in held), [h.name for h in held]


class TestTheShapesAreReadOffEveryDeclaredHook:
    @staticmethod
    def findings(ecosystem: str, hook: Hook, command: str) -> list:
        from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
        from cordon_scanner.ecosystems.base import Manifest

        unit = FileUnit(content=FileContent.from_bytes("pkg.tgz!manifest", b""))
        ctx = ScanContext(config=Config.default(), rules=RuleSet(()))
        programs = InlinePrograms.found(unit.path, hook.name, command)
        manifest = Manifest(path=unit.path, ecosystem=ecosystem)
        return [
            f.severity.name
            for f in InstallHookShapes.findings(hook, command, programs, manifest, unit, ctx)
            if f.rule_id == INLINE_RULE
        ]

    @pytest.mark.parametrize(
        ("ecosystem", "path", "capture", "name"), REAL, ids=[r[0] for r in REAL]
    )
    def test_an_inline_program_in_a_real_hook_is_a_medium_finding_outside_npm(
        self, ecosystem: str, path: str, capture: str, name: str
    ) -> None:
        hook = next(h for h in Real.hooks(ecosystem, path, capture) if h.name == name)
        severities = self.findings(
            ecosystem, hook, "node -e \"require('child_process').exec('id')\""
        )
        assert severities == ["MEDIUM"]

    def test_npm_stays_where_it_was_measured(self) -> None:
        hook = Hook(
            kind="consumerinstall",
            path="package.json",
            name="postinstall",
            command="x",
            ecosystem="npm",
        )
        assert self.findings("npm", hook, "node -e \"require('child_process').exec('id')\"") == [
            "HIGH"
        ]

    def test_a_hook_the_table_does_not_name_is_not_read(self) -> None:
        hook = Hook(kind="build", path="x", name="prepare", command="x", ecosystem="npm")
        assert self.findings("npm", hook, "node -e \"require('child_process').exec('id')\"") == []
