"""The package verdict's flow and framework facts for the files a consumer runs (`ReachedFlows`)."""

from __future__ import annotations

from types import SimpleNamespace

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.reached_flows import ReachedFlows
from cordon_scanner.engine.isolation.analysis_facts import WorkerAnalysis
from cordon_scanner.engine.isolation.facts import Facts, WorkerFacts
from cordon_scanner.foundation.content import FileContent

# The whole environment posted to an address the file does not name: a flow to `unknown`.
SENDS = (
    "function send(url) {\n"
    '  fetch(url, { method: "POST", body: JSON.stringify(process.env) });\n'
    "}\n"
    "send(process.argv[2]);\n"
)
NODE = (
    "async function execute() {\n"
    "  const c = await this.getCredentials('svcApi');\n"
    "  return this.helpers.request({ uri: c.url });\n"
    "}\n"
)


class Fixture:
    @staticmethod
    def ctx(
        hook: frozenset[str] = frozenset(),
        entries: frozenset[str] = frozenset(),
        closure: frozenset[str] = frozenset(),
    ) -> SimpleNamespace:
        return SimpleNamespace(
            install_hook_paths=hook,
            install_entry_paths=frozenset(),
            import_entry_paths=entries,
            library_closure_paths=closure,
        )

    @staticmethod
    def unit(path: str, text: str) -> FileUnit:
        return FileUnit(content=FileContent.from_bytes(path, text.encode()))

    @staticmethod
    def facts(units: list[FileUnit], ctx: SimpleNamespace) -> dict[str, dict[str, list[str]]]:
        """Each unit's reached-flow facts as its worker computes them (item 56)."""
        out: dict[str, dict[str, list[str]]] = {}
        for unit in units:
            WorkerFacts.begin()
            try:
                WorkerAnalysis._reached(unit, ctx)
            finally:
                text = WorkerFacts.end()
            accepted, why = Facts.accept(text, 0)
            assert accepted is not None, why
            if accepted:
                out[unit.path] = accepted
        return out

    @staticmethod
    def of(units: list[FileUnit], ctx: SimpleNamespace) -> dict[str, float]:
        return ReachedFlows.of(units, ctx, Fixture.facts(units, ctx))  # type: ignore[arg-type]


class TestPlaces:
    def test_an_entry_point_flow_is_named_by_source_sink_and_destination(self) -> None:
        facts = Fixture.of(
            [Fixture.unit("index.js", SENDS)], Fixture.ctx(entries=frozenset({"index.js"}))
        )
        assert facts.get("import_flow_environment_request_unknown") == 1.0

    def test_a_file_the_entry_loads_is_the_closure_not_the_entry(self) -> None:
        ctx = Fixture.ctx(
            entries=frozenset({"index.js"}), closure=frozenset({"index.js", "lib/send.js"})
        )
        facts = Fixture.of([Fixture.unit("lib/send.js", SENDS)], ctx)
        assert "closure_flow_environment_request_unknown" in facts
        assert not any(k.startswith("import_") for k in facts)

    def test_a_hook_script_is_the_install_place(self) -> None:
        facts = Fixture.of(
            [Fixture.unit("scripts/setup.js", SENDS)],
            Fixture.ctx(hook=frozenset({"scripts/setup.js"})),
        )
        assert "install_flow_environment_request_unknown" in facts

    def test_code_nothing_runs_has_no_facts(self) -> None:
        assert Fixture.of([Fixture.unit("tools/release.js", SENDS)], Fixture.ctx()) == {}

    def test_only_code_is_read(self) -> None:
        facts = Fixture.of(
            [Fixture.unit("notes.txt", SENDS)], Fixture.ctx(entries=frozenset({"notes.txt"}))
        )
        assert facts == {}


class TestFramework:
    def test_an_n8n_node_reading_credentials_and_sending_is_two_facts(self) -> None:
        facts = Fixture.of(
            [Fixture.unit("dist/nodes/Svc.node.js", NODE)],
            Fixture.ctx(entries=frozenset({"dist/nodes/Svc.node.js"})),
        )
        assert facts.get("import_can_framework_credential") == 1.0
        assert facts.get("import_can_framework_request") == 1.0

    def test_a_plain_library_has_neither(self) -> None:
        facts = ReachedFlows.facts("import", "module.exports = (a, b) => a + b;\n")
        assert facts == {}


class TestBudget:
    def test_each_place_reads_at_most_the_profile_budget(self) -> None:
        """The parent joins at most FILES files' facts per place, in unit order (each worker reads
        only its own file)."""
        paths = [f"lib/f{i}.js" for i in range(ReachedFlows.FILES + 5)]
        units = [Fixture.unit(p, NODE) for p in paths]
        ctx = Fixture.ctx(entries=frozenset(paths))
        read: list[str] = []

        class Counting(dict):  # type: ignore[type-arg]
            def get(self, key, default=None):  # type: ignore[no-untyped-def]
                read.append(key)
                return super().get(key, default)

        ReachedFlows.of(units, ctx, Counting(Fixture.facts(units, ctx)))  # type: ignore[arg-type]
        assert read == paths[: ReachedFlows.FILES]

    def test_a_file_past_the_size_limit_is_not_read(self) -> None:
        big = SENDS + " " * (ReachedFlows.MAX_SIZE + 1)
        facts = Fixture.of(
            [Fixture.unit("index.js", big)], Fixture.ctx(entries=frozenset({"index.js"}))
        )
        assert facts == {}
