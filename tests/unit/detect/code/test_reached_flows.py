"""The package verdict's flow and framework facts for the files a consumer runs (`ReachedFlows`)."""

from __future__ import annotations

from types import SimpleNamespace

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.reached_flows import ReachedFlows
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


class TestPlaces:
    def test_an_entry_point_flow_is_named_by_source_sink_and_destination(self) -> None:
        facts = ReachedFlows.of(
            [Fixture.unit("index.js", SENDS)], Fixture.ctx(entries=frozenset({"index.js"}))
        )
        assert facts.get("import_flow_environment_request_unknown") == 1.0

    def test_a_file_the_entry_loads_is_the_closure_not_the_entry(self) -> None:
        ctx = Fixture.ctx(
            entries=frozenset({"index.js"}), closure=frozenset({"index.js", "lib/send.js"})
        )
        facts = ReachedFlows.of([Fixture.unit("lib/send.js", SENDS)], ctx)
        assert "closure_flow_environment_request_unknown" in facts
        assert not any(k.startswith("import_") for k in facts)

    def test_a_hook_script_is_the_install_place(self) -> None:
        facts = ReachedFlows.of(
            [Fixture.unit("scripts/setup.js", SENDS)],
            Fixture.ctx(hook=frozenset({"scripts/setup.js"})),
        )
        assert "install_flow_environment_request_unknown" in facts

    def test_code_nothing_runs_has_no_facts(self) -> None:
        assert ReachedFlows.of([Fixture.unit("tools/release.js", SENDS)], Fixture.ctx()) == {}

    def test_only_javascript_is_read(self) -> None:
        facts = ReachedFlows.of(
            [Fixture.unit("index.py", SENDS)], Fixture.ctx(entries=frozenset({"index.py"}))
        )
        assert facts == {}


class TestFramework:
    def test_an_n8n_node_reading_credentials_and_sending_is_two_facts(self) -> None:
        facts = ReachedFlows.of(
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
        paths = [f"lib/f{i}.js" for i in range(ReachedFlows.FILES + 5)]
        units = [Fixture.unit(p, NODE) for p in paths]
        seen: list[str] = []
        original = ReachedFlows.facts

        def counting(place: str, text: str) -> dict[str, float]:
            seen.append(place)
            return original(place, text)

        ReachedFlows.facts = staticmethod(counting)  # type: ignore[method-assign]
        try:
            ReachedFlows.of(units, Fixture.ctx(entries=frozenset(paths)))
        finally:
            ReachedFlows.facts = staticmethod(original)  # type: ignore[method-assign]
        assert len(seen) == ReachedFlows.FILES

    def test_a_file_past_the_size_limit_is_not_read(self) -> None:
        big = SENDS + " " * (ReachedFlows.MAX_SIZE + 1)
        facts = ReachedFlows.of(
            [Fixture.unit("index.js", big)], Fixture.ctx(entries=frozenset({"index.js"}))
        )
        assert facts == {}
