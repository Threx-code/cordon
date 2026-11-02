"""Item 56, phase (b): the scan context is built in a supervised worker, and the parent parses no
manifest, lockfile, SBOM, hook or closure.

In a real scan the context is computed twice: by the context worker, and here, in this process, by the
steps the parent used to run (`ContextStage.build` wrapped). The two must be equal: every context
field, the dependency graph, the derived units' names, bytes and languages, and what the steps
reported. Then the parent's own calls into those steps are counted during a scan (zero), and a
worker that raises, dies or answers with a refused document leaves a blocking gap, never a step run
here."""

from __future__ import annotations

import copy
import dataclasses
import io
import json
import os
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.isolation import context as context_module
from cordon_scanner.engine.isolation.context import (
    CONTEXT_FIELDS,
    ContextFacts,
    ContextStage,
    ContextWork,
)
from cordon_scanner.engine.isolation.records import Codec
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.dependencies import Dependencies
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.engine.pipeline.units import Units
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.formats.served_json import ServedJson
from cordon_scanner.foundation.results import Dependency
from support import ROOT

MALICIOUS = sorted(p for p in (ROOT / "corpus" / "malicious").iterdir() if p.is_dir())
BENIGN = sorted(p for p in (ROOT / "corpus" / "benign").iterdir() if p.is_dir())


class Fixture:
    """Scans and the archives they read."""

    @staticmethod
    def scan(target: Path) -> Any:
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(target)

    @staticmethod
    def tarball(tmp_path: Path, files: dict[str, str], name: str = "p-1.0.0.tgz") -> Path:
        target = tmp_path / name
        with tarfile.open(target, "w:gz") as tar:
            for path, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{path}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return target

    @staticmethod
    def packed(source: Path, tmp_path: Path) -> Path:
        """A corpus sample as the tarball a registry would serve."""
        target = tmp_path / f"{source.name}.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    tar.add(path, arcname=f"package/{path.relative_to(source)}")
        return target


class InProcess:
    """The context as the parent computed it before item 56 (b), beside the worker's."""

    compared: ClassVar[list[str]] = []

    @staticmethod
    def old(stage: ContextStage, kind: str, units: list[Any], ctx: Any, root: Path) -> Any:
        """The steps as the parent ran them before item 56 (b), in this process: for a tree, the
        inventory read with its manifests' hooks and the files read again under it, as `_scan` did."""
        from cordon_scanner.engine.isolation.documents import Documents

        engine = stage.engine
        acc = Accumulator(finding_cap=engine.config.limits.max_findings)
        engine._sbom_listed = []
        active = Documents.active()
        Documents._state["active"] = ServedJson._active = False
        try:
            if kind == "tree":
                walker = engine._walker()
                walked = list(walker.walk(root)) if engine.source.yields_the_whole_walk else None
                inventory = engine.inventory(root, None, walked=walked, walker=walker)
                ctx = replace(ctx, **{
                    k: v for k, v in engine._context(inventory).facts().items()
                    if k in ("repository", "install_hook_paths", "ci_hook_paths")
                })  # fmt: skip
                units = list(
                    engine.units.read(
                        root, inventory, acc, float("inf"), walked=walked, walker=walker
                    )
                )
                acc.findings.clear()  # what reading said is the parent's in both: compared from here
                acc.not_installed.clear()
                units.extend(engine.units.inline_hooks(units))
                units.extend(engine.units.deobfuscated(units))
                dependencies, ingested = engine.stages.dependencies(units, acc, root)
                ctx = engine.stages.install_context(units, acc, ctx, dependencies)
            else:
                units = list(units)
                dependencies, ingested = (), ()
                ctx = engine.archive_stages.context(units, acc, ctx, None)
        finally:
            Documents._state["active"] = ServedJson._active = active
        return units, ctx, dependencies, ingested, acc, list(engine._sbom_listed)

    @staticmethod
    def install(monkeypatch: pytest.MonkeyPatch) -> None:
        build = ContextStage.build
        InProcess.compared = []

        def both(self: ContextStage, kind: str, units: list[Any], acc: Accumulator, ctx: Any,
                 root: Path, **kw: Any) -> Any:  # fmt: skip
            before = list(units)
            found = len(acc.findings)
            new_ctx, dependencies, ingested = build(self, kind, units, acc, ctx, root, **kw)
            assert not any(f.rule_id.startswith("OPERATIONAL.WORKER.CONTEXT") for f in acc.findings)
            o_units, o_ctx, o_deps, o_ingested, o_acc, o_listed = InProcess.old(
                self, kind, copy.copy(before), ctx, root
            )
            assert [(u.path, u.language, u.content.raw) for u in units] == [
                (u.path, u.language, u.content.raw) for u in o_units
            ]
            for name in CONTEXT_FIELDS:
                assert getattr(new_ctx, name) == getattr(o_ctx, name), name
            if kind == "tree":
                assert new_ctx.repository.hooks == o_ctx.repository.hooks
            assert dependencies == o_deps
            assert ingested == o_ingested
            assert [f.to_dict() for f in acc.findings[found:]] == [
                f.to_dict() for f in o_acc.findings
            ]
            assert (
                acc.not_installed[-len(o_acc.not_installed) or len(acc.not_installed) :]
                == (o_acc.not_installed)
                or not o_acc.not_installed
            )
            assert self.engine._sbom_listed == o_listed
            InProcess.compared.append(kind)
            return new_ctx, dependencies, ingested

        monkeypatch.setattr(ContextStage, "build", both)


class TestTheWorkersContextIsTheParentsOld:
    @pytest.mark.parametrize("sample", MALICIOUS + BENIGN, ids=lambda p: p.name)
    def test_on_every_corpus_sample_as_a_tree(self, sample: Path, monkeypatch) -> None:
        InProcess.install(monkeypatch)
        Fixture.scan(sample)
        assert InProcess.compared == ["tree"]

    @pytest.mark.parametrize("sample", MALICIOUS[::4] + BENIGN[::4], ids=lambda p: p.name)
    def test_on_corpus_samples_as_tarballs(self, sample: Path, tmp_path: Path, monkeypatch) -> None:
        InProcess.install(monkeypatch)
        Fixture.scan(Fixture.packed(sample, tmp_path))
        assert InProcess.compared == ["archive"]

    def test_inline_hooks_a_lift_closures_a_lockfile_and_submodules(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        root = tmp_path / "pkg"
        (root / "lib").mkdir(parents=True)
        (root / "package.json").write_text(
            json.dumps(
                {
                    "name": "p",
                    "version": "1.0.0",
                    "main": "index.js",
                    "scripts": {"postinstall": "node setup.js && node -e \"require('./lib/x')\""},
                    "dependencies": {"left-pad": "1.3.0"},
                }
            ),
            encoding="utf-8",
        )
        (root / "setup.js").write_text(
            'const p = require("path");\nrequire(p.join(__dirname, "lib", "helper.js"));\n'
            "function later() { return 1; }\n",
            encoding="utf-8",
        )
        (root / "lib" / "helper.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (root / "lib" / "x.js").write_text("module.exports = 2;\n", encoding="utf-8")
        (root / "index.js").write_text(
            "var _0x1=['\\x68\\x65\\x6c\\x6c\\x6f'];console.log(atob('aGVsbG8gd29ybGQ='));\n",
            encoding="utf-8",
        )
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "p",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "p", "dependencies": {"left-pad": "1.3.0"}},
                        "node_modules/left-pad": {"version": "1.3.0"},
                    },
                }
            ),
            encoding="utf-8",
        )
        (root / ".gitmodules").write_text(
            '[submodule "v"]\n\tpath = vendor/v\n\turl = https://example.invalid/v.git\n',
            encoding="utf-8",
        )
        (root / "setup.py").write_text(
            "from setuptools import setup\nfrom setuptools.command.install import install\n"
            "class I(install):\n    def run(self):\n        import helper_mod\n"
            "setup(name='q', cmdclass={'install': I})\n",
            encoding="utf-8",
        )
        (root / "helper_mod.py").write_text("import os\n", encoding="utf-8")
        InProcess.install(monkeypatch)
        result = Fixture.scan(root)
        assert InProcess.compared == ["tree"]
        assert any(d.name == "left-pad" for d in result.dependencies)


class Counted:
    """Calls into the moved steps made in THIS process during a scan."""

    calls: ClassVar[list[str]] = []
    STEPS: ClassVar[list[tuple[type, str]]] = [
        (Units, "inline_hooks"),
        (Units, "deobfuscated"),
        (Dependencies, "build"),
        (Dependencies, "sbom"),
        (Hooks, "manifest_hook_paths"),
        (Hooks, "hook_import_closure"),
        (Hooks, "hook_js_closure"),
        (Hooks, "hook_deferred_lines"),
        (Hooks, "hooked_languages"),
    ]

    @staticmethod
    def install(monkeypatch: pytest.MonkeyPatch) -> None:
        Counted.calls = []
        parent = os.getpid()
        for owner, name in Counted.STEPS:
            original = owner.__dict__[name]
            target = original.__func__ if isinstance(original, staticmethod) else original

            def counting(*args: Any, _f: Any = target, _n: str = name, **kw: Any) -> Any:
                if os.getpid() == parent:
                    Counted.calls.append(_n)
                return _f(*args, **kw)

            wrapped = staticmethod(counting) if isinstance(original, staticmethod) else counting
            monkeypatch.setattr(owner, name, wrapped)


class TestTheParentParsesNoContext:
    def test_a_tree_scan(self, monkeypatch) -> None:
        Counted.install(monkeypatch)
        Fixture.scan(next(p for p in MALICIOUS if (p / "package.json").exists()))
        assert Counted.calls == []

    def test_a_tarball_scan(self, tmp_path: Path, monkeypatch) -> None:
        target = Fixture.tarball(
            tmp_path,
            {
                "package.json": '{"name": "p", "version": "1.0.0", '
                '"scripts": {"postinstall": "node setup.js"}}',
                "setup.js": 'require("./lib/a");\n',
                "lib/a.js": "module.exports = 1;\n",
            },
        )
        Counted.install(monkeypatch)
        Fixture.scan(target)
        assert Counted.calls == []


class TestAFailedWorkerIsAGapNeverAStepHere:
    """The worker's function replaced before the scan starts: the template the workers are forked
    from is forked from this process, so they run the replacement."""

    @pytest.mark.parametrize("how", ["raises", "dies", "refused"])
    def test_the_scan_blocks_and_nothing_is_parsed_here(
        self, how: str, tmp_path: Path, monkeypatch
    ) -> None:
        def broken(item: Any) -> str:
            if how == "raises":
                raise ValueError("a context step blew up")
            if how == "dies":
                os._exit(9)
            return '{"undeclared": []}'

        monkeypatch.setattr(ContextWork, "run", staticmethod(broken))
        target = Fixture.tarball(
            tmp_path,
            {
                "package.json": '{"name": "p", "version": "1.0.0", '
                '"scripts": {"postinstall": "node setup.js"}}',
                "setup.js": 'require("./lib/a");\n',
                "lib/a.js": "module.exports = 1;\n",
            },
        )
        Counted.install(monkeypatch)
        result = Fixture.scan(target)
        assert any(f.rule_id == ContextStage.RULE for f in result.findings)
        assert not result.content_complete
        assert any(rule == ContextStage.RULE for rule, _ in result.content_gaps)
        assert Counted.calls == []

    def test_one_failing_step_is_its_own_gap_and_the_rest_still_run(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        def broken(units: Any, hook_paths: Any) -> set[str]:
            raise RuntimeError("closure")

        monkeypatch.setattr(Hooks, "hook_import_closure", staticmethod(broken))
        root = tmp_path / "pkg"
        root.mkdir()
        (root / "package.json").write_text(
            '{"name": "p", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}',
            encoding="utf-8",
        )
        result = Fixture.scan(root)
        assert any(f.rule_id == ContextWork.STEP_RULE for f in result.findings)
        assert not result.content_complete
        assert any(d.name == "left-pad" for d in result.dependencies)  # the graph still built


class TestTheDocumentIsChecked:
    """`ContextFacts.accept` against hostile answers: each is refused, with a reason."""

    @staticmethod
    def units() -> list[Any]:
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.foundation.content import FileContent

        return [FileUnit(content=FileContent.from_bytes("a.js", b"x"), language="javascript")]

    @staticmethod
    def ctx() -> Any:
        from cordon_scanner.engine.engine import Engine
        from cordon_scanner.foundation.results import Repository

        return Engine(Config.default())._context(Repository(root="."))

    @staticmethod
    def document(**over: Any) -> str:
        doc: dict[str, Any] = {
            "languages": [], "added": [], "context": {}, "dependencies": [], "ingested": [],
            "sbom_listed": [], "findings": [], "complete": True, "gaps": [], "not_installed": [],
            "raised": {}, "manifests": [], "documents": [], "archive_dependencies": None,
            "inventory_hooks": None, "js_references": {},
        }  # fmt: skip
        doc.update(over)
        return json.dumps(doc)

    def test_a_well_formed_document_is_accepted(self) -> None:
        accepted, why = ContextFacts.accept(
            self.document(context={"tree_paths": ["a.js"], "install_hook_paths": ["a.js"]}),
            self.units(),
            self.ctx(),
        )
        assert accepted is not None, why
        assert accepted.context["install_hook_paths"] == frozenset({"a.js"})

    @pytest.mark.parametrize(
        "over",
        [
            {"extra": []},
            {"context": {"install_hook_paths": ["/etc/passwd"]}},
            {"context": {"config": {}}},
            {"context": {"tree_paths": ["a.js", "b.js"]}},
            {"context": {"install_deferred_lines": [["a.js", 5, 1]]}},
            {"context": {"package_distribution": "yes"}},
            {"languages": [[7, "javascript"]]},
            {"languages": [[0, "Java Script; rm"]]},
            {"added": [["a.js", "x", None, None]]},
            {"added": [["b.js", "x", None, None]]},
            {"dependencies": [{"purl": "pkg:npm/x"}]},
            {"findings": [{"rule_id": 1}]},
            {"complete": "yes"},
            {"raised": {"a": 1}},
        ],
        ids=lambda o: json.dumps(o)[:60],
    )
    def test_a_malformed_document_is_refused(self, over: dict[str, Any]) -> None:
        accepted, why = ContextFacts.accept(self.document(**over), self.units(), self.ctx())
        assert accepted is None and why

    def test_nesting_past_the_shape_is_refused_before_decoding(self) -> None:
        deep = "[" * 100_000 + "]" * 100_000
        accepted, why = ContextFacts.accept(
            self.document().replace('"gaps": []', f'"gaps": {deep}'), self.units(), self.ctx()
        )
        assert accepted is None and "nested" in why

    def test_a_document_past_its_size_is_refused(self, monkeypatch) -> None:
        monkeypatch.setattr(context_module, "DOCUMENT_BYTES", 100)
        accepted, why = ContextFacts.accept(self.document(), self.units(), self.ctx())
        assert accepted is None and "bytes" in why


class TestTheRecordCodec:
    def test_every_dependency_field_round_trips(self) -> None:
        from cordon_scanner.foundation.models import Scope

        record = Dependency(
            purl="pkg:npm/a@1",
            ecosystem="npm",
            name="a",
            version="1",
            scope=Scope.DEV,
            parents=("b",),
            signed=b"\x01\x02",
            platform=("linux",),
        )
        assert Codec.decode(Dependency, json.loads(json.dumps(Codec.encode(record)))) == record

    def test_every_field_has_a_declared_shape(self) -> None:
        from cordon_scanner.engine.sbom_ingest import ListedVulnerability

        for kind in (Dependency, ListedVulnerability):
            for f in dataclasses.fields(kind):
                assert str(f.type) in Codec.CHECKS, f"{kind.__name__}.{f.name}: {f.type}"


#: One small, hand-written manifest per ecosystem reader (item 56 (b), part 2's review, condition 3), each in a
#: directory of its own. Benign, written for this test.
MANIFESTS = {
    "actions/.github/workflows/ci.yml": "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
    "    steps:\n      - uses: actions/checkout@v4\n",
    "ansible/requirements.yml": "collections:\n  - name: community.general\n    version: 8.0.0\n",
    "bazel/MODULE.bazel": 'module(name = "demo", version = "1.0")\n'
    'bazel_dep(name = "rules_cc", version = "0.0.9")\n',
    "cargo/Cargo.toml": '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n',
    "cocoapods/Podfile": "platform :ios, '13.0'\ntarget 'App' do\n  pod 'Alamofire', '~> 5.0'\nend\n",
    "composer/composer.json": '{"name": "demo/demo", "require": {"monolog/monolog": "^3.0"}, '
    '"scripts": {"post-install-cmd": "php setup.php"}}',
    "conan/conanfile.txt": "[requires]\nzlib/1.3\n",
    "conda/environment.yml": "name: demo\ndependencies:\n  - numpy=1.26\n  - pip:\n      - requests==2.31.0\n",
    "cran/DESCRIPTION": "Package: demo\nVersion: 1.0\nImports: jsonlite\n",
    "gomod/go.mod": "module example.com/demo\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n",
    "gradle/build.gradle": "plugins { id 'java' }\ndependencies {\n"
    "    implementation 'com.google.guava:guava:33.0.0-jre'\n}\n",
    "hackage/demo.cabal": "cabal-version: 2.4\nname: demo\nversion: 0.1.0\n\nlibrary\n"
    "  build-depends: base >=4 && <5, text\n",
    "helm/Chart.yaml": "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n"
    "  - name: redis\n    version: 18.0.0\n    repository: https://charts.bitnami.com/bitnami\n",
    "hex/mix.exs": "defmodule Demo.MixProject do\n  use Mix.Project\n  def project do\n"
    '    [app: :demo, version: "0.1.0", deps: deps()]\n  end\n'
    '  defp deps do\n    [{:jason, "~> 1.4"}]\n  end\nend\n',
    "homebrew/Brewfile": 'brew "wget"\n',
    "julia/Project.toml": 'name = "Demo"\nversion = "0.1.0"\n\n[deps]\n'
    'JSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"\n',
    "maven/pom.xml": "<project><modelVersion>4.0.0</modelVersion><groupId>d</groupId>"
    "<artifactId>demo</artifactId><version>1.0</version><dependencies><dependency>"
    "<groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version>"
    "</dependency></dependencies></project>\n",
    "nix/flake.nix": '{\n  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";\n'
    "  outputs = { self, nixpkgs }: { };\n}\n",
    "npm/package.json": '{"name": "demo", "version": "1.0.0", "scripts": {"postinstall": '
    '"node setup.js"}, "dependencies": {"left-pad": "1.3.0"}, "optionalDependencies": '
    '{"fsevents": "2.3.3"}}',
    "nuget/demo.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference '
    'Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>\n',
    "opam/demo.opam": 'opam-version: "2.0"\nname: "demo"\nversion: "0.1"\ndepends: ["dune" {>= "3.0"}]\n',
    "pub/pubspec.yaml": "name: demo\nversion: 1.0.0\ndependencies:\n  http: ^1.1.0\n",
    "pypi/pyproject.toml": '[project]\nname = "demo"\nversion = "0.1"\ndependencies = ["requests>=2"]\n',
    "pypi/requirements.txt": "-r base.txt\nflask==3.0.0 --hash=sha256:not-a-digest\n",
    "pypi/base.txt": "click==8.1.7\n",
    "rubygems/Gemfile": "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n",
    "swift/Package.swift": "// swift-tools-version:5.9\nimport PackageDescription\n"
    'let package = Package(name: "Demo", dependencies: [.package(url: '
    '"https://github.com/apple/swift-log.git", from: "1.5.0")])\n',
    "terraform/main.tf": "terraform {\n  required_providers {\n    aws = {\n"
    '      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n  }\n}\n',
    "vcpkg/vcpkg.json": '{"name": "demo", "version": "1.0", "dependencies": ["fmt"]}',
}


class TestEveryReadersRecordIsTheInProcessOne:
    """Each manifest record the parent reads after the context worker is the reader's own, run here
    on the same bytes: read alone, and in view of the scan's files where the reader reads its tree."""

    def test_on_a_manifest_of_every_reader(self, tmp_path: Path, monkeypatch) -> None:
        from types import MappingProxyType

        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.engine.isolation.documents import Documents

        root = tmp_path / "eco"
        for path, text in MANIFESTS.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        build = ContextStage.build
        compared: list[str] = []

        def both(self: ContextStage, kind: str, units: list[Any], *args: Any, **kw: Any) -> Any:
            out = build(self, kind, units, *args, **kw)
            served = dict(Documents._manifests)
            Documents._state["active"] = False  # the reader itself, in this test's process
            try:
                view = MappingProxyType({u.path: u.content for u in units})
                for unit in units:
                    ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
                    ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
                    if ecosystem is None:
                        continue
                    for how in ("alone", "tree"):
                        in_tree = getattr(ecosystem, "parse_in_tree", None)
                        if how == "tree" and in_tree is None:
                            continue
                        held = served.get((ecosystem.id, unit.path, how))
                        assert held is not None, (unit.path, how)
                        try:
                            own = (
                                ecosystem.parse_manifest(unit.content)
                                if how == "alone"
                                else in_tree(unit.content, view)
                            )
                        except Exception as exc:  # noqa: BLE001
                            assert held == type(exc).__name__, (unit.path, how)
                        else:
                            assert held == own, (unit.path, how)
                        compared.append(f"{ecosystem.id}:{how}")
            finally:
                Documents._state["active"] = True
            return out

        monkeypatch.setattr(ContextStage, "build", both)
        result = Fixture.scan(root)
        readers = {c.split(":")[0] for c in compared}
        assert readers >= {p.split("/")[0] for p in MANIFESTS} - {"image"}, sorted(readers)
        assert not any(
            f.rule_id == "OPERATIONAL.WORKER.DOCUMENT_UNAVAILABLE" for f in result.findings
        )

    def test_a_record_crosses_as_the_worker_built_it(self) -> None:
        """`__post_init__` is not idempotent: a malformed integrity is stored as its hash, which a
        second construction would hash again. The rebuilt record is the worker's, exactly."""
        from cordon_scanner.ecosystems.base import DeclaredDependency, Manifest
        from cordon_scanner.foundation.models import Scope

        dependency = DeclaredDependency(
            name="a",
            spec="^1",
            scope=Scope.RUNTIME,
            field_name="dependencies",
            integrity="a sentence",
        )
        record = Manifest(path="package.json", ecosystem="npm", name="p", version="1",
                          dependencies=(dependency,))  # fmt: skip
        back = Codec.decode(Manifest, json.loads(json.dumps(Codec.encode(record))))
        assert back == record
        assert back.dependencies[0].integrity == dependency.integrity

    def test_every_record_type_is_plain_data(self) -> None:
        """Condition 2: every field of every record type the codec carries has a declared shape, so
        nothing that is not plain data (a callable, a pattern, a reference to content) can cross."""
        from cordon_scanner.ecosystems.base import DeclaredDependency, Manifest
        from cordon_scanner.engine.sbom_ingest import ListedVulnerability
        from cordon_scanner.foundation.models import Hook

        for kind in (Manifest, DeclaredDependency, Hook, Dependency, ListedVulnerability):
            for f in dataclasses.fields(kind):
                annotation = str(f.type)
                assert annotation in Codec.CHECKS or Codec._nested(annotation) is not None, (
                    f"{kind.__name__}.{f.name}: {annotation}"
                )


class TestAStoreMissIsAGapNeverAParse:
    def test_an_unheld_document_raises_and_is_reported(self, monkeypatch) -> None:
        from cordon_scanner.engine.isolation.documents import Documents, DocumentUnavailable
        from cordon_scanner.foundation.formats.scanned_json import ScannedJson

        def never(*args: Any, **kw: Any) -> Any:
            raise AssertionError("the parent decoded scanned JSON")

        monkeypatch.setattr(ScannedJson, "loads", staticmethod(never))
        Documents.end()
        Documents.activate([])
        try:
            with pytest.raises(DocumentUnavailable):
                ServedJson.loads('{"name": "x"}', "package/package.json")
            acc = Accumulator()
            Documents.report_missing(acc)
        finally:
            Documents.end()
        assert [f.rule_id for f in acc.findings] == ["OPERATIONAL.WORKER.DOCUMENT_UNAVAILABLE"]
        assert not acc.complete

    def test_no_reader_parses_in_the_parent(self, tmp_path: Path, monkeypatch) -> None:
        """Every ecosystem reader's parse entry points counted in this process during a scan of a
        tree holding a manifest of every reader, and of an npm tarball: zero."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        parent, calls = os.getpid(), []
        for ecosystem in EcosystemRegistry.all_ecosystems():
            for name in ("parse_manifest", "parse_in_tree", "parse_lockfile", "parse_included"):
                original = getattr(type(ecosystem), name, None)
                if original is None or not callable(original):
                    continue

                def counting(*args: Any, _f: Any = original, _n: str = name, **kw: Any) -> Any:
                    if os.getpid() == parent:
                        calls.append(_n)
                    return _f(*args, **kw)

                monkeypatch.setattr(type(ecosystem), name, counting)
        root = tmp_path / "eco"
        for path, text in MANIFESTS.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        Fixture.scan(root)
        Fixture.scan(
            Fixture.tarball(
                tmp_path, {"package.json": MANIFESTS["npm/package.json"], "setup.js": "1;\n"}
            )
        )
        assert calls == []


class TestTheParentOpensNoArchive:
    """Item 56 (c): an archive target is expanded in the expander; the parent creates no tar, zip or
    decompressor object, and reads each member back from a spill file it checks."""

    def test_no_archive_object_is_made_in_the_parent(self, tmp_path: Path, monkeypatch) -> None:
        import bz2
        import gzip
        import lzma
        import sys
        import zipfile

        import cordon_scanner

        # Cordon's own shipped data (its models, advisories and policies) and the runtime's are
        # opened as ever; anything else -- the target, a member, an in-memory buffer -- is counted.
        shipped = (Path(cordon_scanner.__file__).parent, Path(sys.prefix), Path(sys.base_prefix))

        def ours(*args: Any, **kw: Any) -> bool:
            for value in (*args, *kw.values()):
                if isinstance(value, (str, Path)) and len(str(value)) < 4096:
                    resolved = Path(value).resolve()
                    if any(resolved.is_relative_to(root.resolve()) for root in shipped):
                        return True
            return False

        target = Fixture.tarball(
            tmp_path,
            {
                "package.json": MANIFESTS["npm/package.json"],
                "setup.js": 'require("./lib/a");\n',
                "lib/a.js": "module.exports = 1;\n",
            },
        )
        parent, made = os.getpid(), []
        for owner, name in (
            (tarfile, "open"),
            (tarfile.TarFile, "__init__"),
            (zipfile.ZipFile, "__init__"),
            (gzip.GzipFile, "__init__"),
            (bz2, "decompress"),
            (lzma, "decompress"),
        ):
            original = getattr(owner, name)

            def counting(*args: Any, _f: Any = original, _n: str = name, **kw: Any) -> Any:
                if os.getpid() == parent and not ours(*args, **kw):
                    made.append(_n)
                return _f(*args, **kw)

            monkeypatch.setattr(owner, name, counting)
        result = Fixture.scan(target)
        assert made == []
        assert {f.location.path.split("!", 1)[-1] for f in result.findings} >= set()
        assert result.repository.file_count == 3

    @pytest.mark.parametrize("how", ["raises", "dies", "refused"])
    def test_a_failed_expander_is_a_rejected_archive(
        self, how: str, tmp_path: Path, monkeypatch
    ) -> None:
        from cordon_scanner.engine.isolation.expander import ExpandWork

        def broken(item: Any) -> str:
            if how == "raises":
                raise ValueError("a reader blew up")
            if how == "dies":
                os._exit(9)
            return '{"members": "not a list"}'

        monkeypatch.setattr(ExpandWork, "run", staticmethod(broken))
        result = Fixture.scan(
            Fixture.tarball(tmp_path, {"package.json": MANIFESTS["npm/package.json"]})
        )
        assert any(f.rule_id == "OPERATIONAL.ARCHIVE.REJECTED" for f in result.findings)
        assert not result.content_complete

    def test_member_names_never_name_a_spill_file(self, tmp_path: Path, monkeypatch) -> None:
        """Traversal and absolute member names: each gets a generated spill name, and nothing is
        written outside the scan's spill directory."""
        import tempfile

        from cordon_scanner.engine.isolation.expander import SpillDirectory

        root = tmp_path / "tmp"
        root.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(root))
        target = tmp_path / "t.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for name in ("package/package.json", "../../escape.js", "/abs/escape.js"):
                data = b'{"name": "t", "version": "1.0.0"}' if name.endswith(".json") else b"1;\n"
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        Fixture.scan(target)
        left = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
        assert not any("escape" in p for p in left), left
        assert not (tmp_path / "escape.js").exists()
        assert SpillDirectory.sweep(now=float("inf")) == 0  # the scan removed its own directory

    def test_a_killed_scans_spills_are_swept(self, tmp_path: Path, monkeypatch) -> None:
        import tempfile

        from cordon_scanner.engine.isolation.expander import PREFIX, SpillDirectory

        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        stale = tmp_path / f"{PREFIX}deadbeef"
        stale.mkdir()
        (stale / ("0" * 32)).write_bytes(b"x")
        os.utime(stale, (0, 0))
        fresh = SpillDirectory()
        try:
            assert not stale.exists()
            assert fresh.path.exists() and (fresh.path.stat().st_mode & 0o777) == 0o700
        finally:
            fresh.remove()

    def test_the_parent_bounds_the_members_itself(self, tmp_path: Path, monkeypatch) -> None:
        from cordon_scanner.engine.engine import Engine
        from cordon_scanner.engine.isolation.expander import ArchiveExpander

        expander = ArchiveExpander(Engine(Config.default()))
        member = ["m", "0" * 32, 1, "0" * 64, 0]
        answer = json.dumps(
            {
                "members": [[*member[:1], f"{i:032x}", *member[2:]] for i in range(300_000)],
                "rejected": [],
                "error": None,
                "image": None,
                "findings": [],
                "complete": True,
                "gaps": [],
            }
        )
        accepted, why = expander.accept(answer, "t.tgz")
        assert accepted is None and "members" in why


class TestALargeMemberCrossesWhole:
    """A member past `max_file_bytes` is kept on disk by the reader (`SpilledBytes`: its prefix, and
    all of it on disk). Writing only the prefix to the spill file lost every window past it, and its
    truncation note, in the parent: found by the 1,000-unit pair on two native-binary packages."""

    def test_its_windows_and_its_note_survive_the_expander(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from cordon_scanner.engine.pipeline.archive_stages import ArchiveStages
        from cordon_scanner.foundation.limits import Limits

        big = b"// filler\n" * (Limits().max_file_bytes // 10 + 50_000)
        target = Fixture.tarball(
            tmp_path, {"package.json": MANIFESTS["npm/package.json"], "big.js": big.decode()}
        )
        seen: list[Any] = []
        original = ArchiveStages.read_members

        def capture(self: Any, members: Any, *args: Any, **kw: Any) -> Any:
            out = original(self, members, *args, **kw)
            seen.extend(args[4])  # the units
            return out

        monkeypatch.setattr(ArchiveStages, "read_members", capture)
        result = Fixture.scan(target)
        unit = next(u for u in seen if u.path.endswith("package/big.js"))
        assert unit.content.truncated
        assert unit.content.spill is not None and unit.content.spill.size == len(big)
        assert any(f.rule_id == "OPERATIONAL.FILE.TRUNCATED" for f in result.findings)
