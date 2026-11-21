"""The terms package-scope rules and the learning loop's distiller share (`rules/fact_terms.py`)."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.base import ScanContext
from cordon_scanner.rules.fact_terms import ANY, UNREACHED, FactTerms


class TestTermsFromFacts:
    def test_a_file_gives_each_capability_and_each_pair_anywhere_and_where_it_runs(self) -> None:
        terms = FactTerms.of_file(True, ["install_entry"], ["spawn", "egress"])
        assert ("file", ANY, "spawn") in terms
        assert ("file", "install_entry", "egress", "spawn") in terms
        assert not any(t[1] == UNREACHED for t in terms)

    def test_a_file_no_place_reaches_is_unreached(self) -> None:
        assert ("file", UNREACHED, "egress", "spawn") in FactTerms.of_file(
            False, [], ["spawn", "egress"]
        )

    def test_a_facts_record_gives_the_union_of_its_files_and_its_package(self) -> None:
        record = {
            "files": [{"reached": False, "places": [], "capabilities": ["spawn"]}],
            "package": {
                "rules": {"SUSPECT.X.001": 1},
                "hooks": [{"kind": "preinstall", "programs": ["node"]}],
            },
        }
        terms = FactTerms.of_facts(record)
        assert {
            ("file", UNREACHED, "spawn"),
            ("package_rule", "SUSPECT.X.001"),
            ("hook", "preinstall"),
        } <= terms

    def test_the_places_are_the_scan_contexts_places(self) -> None:
        assert set(ScanContext.PLACES) == FactTerms.PLACES


class TestTermsFromARulesWrittenForm:
    def test_the_three_kinds(self) -> None:
        assert FactTerms.of_spec(
            {"file": {"where": "unreached", "capabilities": ["spawn", "egress"]}}
        ) == (
            "file",
            "unreached",
            "egress",
            "spawn",
        )
        assert FactTerms.of_spec({"package_rule": "SUSPECT.X.001"}) == (
            "package_rule",
            "SUSPECT.X.001",
        )
        assert FactTerms.of_spec({"hook": "postinstall"}) == ("hook", "postinstall")

    @pytest.mark.parametrize(
        ("spec", "said"),
        [
            ({"host": "a.example"}, "refused term kind"),
            ({"age": "younger-than-30-days"}, "refused term kind"),
            ({"publisher": "someone"}, "refused term kind"),
            ({"file": {"where": "somewhere", "capabilities": ["spawn"]}}, "unknown where"),
            ({"file": {"capabilities": ["spawn", "egress", "decode"]}}, "one or two capabilities"),
            ({"file": {"capabilities": ["teleport"]}}, "unknown capability"),
            ({"package_rule": "not a rule id"}, "not a rule id"),
            ({"hook": "Pre Install"}, "not a hook kind"),
            ({"file": {}, "hook": "x"}, "exactly one key"),
            ({"weather": "sunny"}, "unknown term kind"),
        ],
    )
    def test_anything_else_is_an_error_naming_what_is_wrong(self, spec, said) -> None:
        with pytest.raises(ValueError, match=said):
            FactTerms.of_spec(spec)


class TestTheDirectCheckAgreesWithTheExpansion:
    def test_every_file_shape_and_every_term_agree(self) -> None:
        import itertools

        caps = ("spawn", "egress", "decode")
        wheres = (ANY, UNREACHED, "install_entry", "agent_tool")
        for reached, places, held in itertools.product(
            (True, False),
            ((), ("install_entry",), ("install_entry", "agent_tool")),
            [c for n in range(4) for c in itertools.combinations(caps, n)],
        ):
            expanded = FactTerms.of_file(reached, places, held)
            for where in wheres:
                for wanted in [c for n in (1, 2) for c in itertools.combinations(sorted(caps), n)]:
                    term = ("file", where, *wanted)
                    assert FactTerms.file_satisfies(reached, places, held, term) == (
                        term in expanded
                    ), term


class TestALearnedRuleIsNeverBuiltOnAnother:
    def test_a_learned_rule_id_is_refused_as_a_term_and_never_read_as_one(self) -> None:
        with pytest.raises(ValueError, match="another learned rule"):
            FactTerms.of_spec({"package_rule": "LEARNED.MCP.001"})
        assert FactTerms.of_package(["LEARNED.MCP.001", "SUSPECT.X.001"], []) == {
            ("package_rule", "SUSPECT.X.001")
        }


class TestTermsByHowAFileIsReached:
    """`facts_version` 2 carries `reach` per file; a term can say `reach:KIND` (a closed list, `decide/reach.py`)."""

    def test_a_file_gives_its_terms_under_the_way_it_is_reached(self) -> None:
        terms = FactTerms.of_file(False, [], ["spawn", "egress"], "path_string")
        assert ("file", "reach:path_string", "egress", "spawn") in terms
        assert ("file", UNREACHED, "egress", "spawn") in terms
        assert not any(t[1] == "reach:unreached" for t in terms)

    def test_nothing_reaches_it_is_its_own_reach(self) -> None:
        assert ("file", "reach:unreached", "spawn") in FactTerms.of_file(
            False, [], ["spawn"], "unreached"
        )

    def test_a_reach_outside_the_closed_list_gives_no_term(self) -> None:
        terms = FactTerms.of_file(True, ["import_entry"], ["spawn"], "not_code")
        assert not any(str(t[1]).startswith("reach:") for t in terms)
        assert not any(
            str(t[1]).startswith("reach:") for t in FactTerms.of_file(True, [], ["spawn"], "OTHER")
        )

    def test_a_facts_record_gives_the_reach_of_each_file(self) -> None:
        record = {
            "files": [
                {
                    "reached": False,
                    "places": [],
                    "capabilities": ["spawn"],
                    "reach": "require_chain",
                }
            ],
            "package": {},
        }
        assert ("file", "reach:require_chain", "spawn") in FactTerms.of_facts(record)

    def test_a_rule_may_write_a_reach_and_an_unknown_one_is_an_error(self) -> None:
        assert FactTerms.of_spec(
            {"file": {"where": "reach:unreached", "capabilities": ["spawn", "egress"]}}
        ) == ("file", "reach:unreached", "egress", "spawn")
        with pytest.raises(ValueError, match="unknown where"):
            FactTerms.of_spec({"file": {"where": "reach:sideways", "capabilities": ["spawn"]}})

    def test_the_reach_kinds_are_those_the_engine_names(self) -> None:
        from cordon_scanner.decide.reach import FileReach

        assert frozenset(FileReach.KINDS) == FactTerms.REACH

    def test_the_direct_check_agrees_with_the_expansion_for_every_reach(self) -> None:
        import itertools

        caps = ("spawn", "egress")
        wheres = (ANY, UNREACHED, "install_entry", *(f"reach:{k}" for k in sorted(FactTerms.REACH)))
        for reached, places, held, reach in itertools.product(
            (True, False),
            ((), ("install_entry",)),
            [c for n in range(3) for c in itertools.combinations(caps, n)],
            (None, "not_code", *sorted(FactTerms.REACH)),
        ):
            expanded = FactTerms.of_file(reached, places, held, reach)
            for where in wheres:
                for wanted in [c for n in (1, 2) for c in itertools.combinations(sorted(caps), n)]:
                    term = ("file", where, *wanted)
                    assert FactTerms.file_satisfies(reached, places, held, term, reach) == (
                        term in expanded
                    ), (term, reach)
