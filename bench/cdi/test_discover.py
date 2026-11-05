"""Discovery turns shared text of confirmed misses into a candidate pack, and refuses what benign has."""

from __future__ import annotations

from pathlib import Path

from bench.cdi.discover import Discovery

SHARED = "run: send-marker --to collector.invalid --token placeholder-value"
BENIGN_TOO = "runs-on: ubuntu-latest with a fairly long line here"


class DiscoverKit:
    @staticmethod
    def unit(root: Path, name: str, *lines: str) -> str:
        path = root / name / ".github" / "workflows"
        path.mkdir(parents=True)
        (path / "ci.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(root / name)


class TestDiscovery:
    def test_a_line_shared_by_the_misses_and_absent_from_benign_becomes_the_rule(
        self, tmp_path: Path
    ) -> None:
        misses = [
            DiscoverKit.unit(tmp_path, f"m{i}", SHARED, BENIGN_TOO, f"unique line number {i} x")
            for i in range(4)
        ]
        benign = [DiscoverKit.unit(tmp_path, "b0", BENIGN_TOO)]
        pack, report = Discovery.run(
            misses, benign, min_support=3, max_rules=5, pack_id="cdi.test", reference="t", paths=[]
        )
        assert pack is not None and report["misses_covered"] == 4
        assert pack.count("- id: 'CDI.DISCOVERED.") == 1
        positive = pack.split("positive:", 1)[1].split("negative:", 1)[0]
        assert f"- '{SHARED}'" in positive

    def test_a_line_that_appears_in_benign_is_never_an_indicator(self, tmp_path: Path) -> None:
        misses = [DiscoverKit.unit(tmp_path, f"m{i}", BENIGN_TOO) for i in range(4)]
        benign = [DiscoverKit.unit(tmp_path, "b0", BENIGN_TOO)]
        pack, report = Discovery.run(
            misses, benign, min_support=3, max_rules=5, pack_id="cdi.test", reference="t", paths=[]
        )
        assert pack is None and report["candidates"] == 0

    def test_too_little_support_proposes_nothing(self, tmp_path: Path) -> None:
        misses = [
            DiscoverKit.unit(tmp_path, f"m{i}", SHARED if i < 2 else "other text entirely here!")
            for i in range(4)
        ]
        pack, _ = Discovery.run(
            misses, [], min_support=3, max_rules=5, pack_id="cdi.test", reference="t", paths=[]
        )
        assert pack is None

    def test_the_generated_pack_loads_and_passes_its_own_samples(self, tmp_path: Path) -> None:
        from cordon_scanner.rules.loader import RuleLoader
        from cordon_scanner.rules.tester import RuleTester

        misses = [DiscoverKit.unit(tmp_path, f"m{i}", SHARED) for i in range(3)]
        benign = [DiscoverKit.unit(tmp_path, "b0", BENIGN_TOO)]
        pack, _ = Discovery.run(
            misses, benign, min_support=3, max_rules=5, pack_id="cdi.test", reference="t", paths=[]
        )
        assert pack is not None
        target = tmp_path / "rulepack-cdi-test.yaml"
        target.write_text(pack, encoding="utf-8")
        loaded = RuleLoader().load_file(target)
        assert RuleTester.run(loaded) == ()
