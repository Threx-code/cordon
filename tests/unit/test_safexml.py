"""The build-descriptor XML reader: structure kept, hazards refused."""

from __future__ import annotations

import pytest

from cordon_scanner.core.safexml import MAX_DEPTH, SafeXml, SafeXmlError


class TestStructure:
    def test_a_dependency_keeps_its_own_coordinates_beside_an_exclusion(self) -> None:
        root = SafeXml.parse(
            "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId>"
            "<exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>"
            "</dependency></dependencies></project>"
        )
        [dependency] = root.find_all("dependencies", "dependency")
        assert dependency.value("groupId") == "a" and dependency.value("artifactId") == "b"
        assert dependency.find_all("exclusions", "exclusion")[0].value("groupId") == "x"

    def test_attributes_entities_cdata_comments_and_namespaces(self) -> None:
        root = SafeXml.parse(
            '<?xml version="1.0"?>\n<!-- c --><p:Project xmlns:p="u">'
            '<PackageReference Include="Newtonsoft.Json" Version="13.0.1"/>'
            "<d><![CDATA[<raw>]]> &amp; &#65;&#x42;</d></p:Project>"
        )
        assert root.local == "Project"
        assert root.children[0].attributes == {"Include": "Newtonsoft.Json", "Version": "13.0.1"}
        assert root.value("d") == "<raw> & AB"


class TestHazardsAreRefused:
    @pytest.mark.parametrize(
        "text",
        [
            '<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>',
            '<!DOCTYPE x SYSTEM "file:///etc/passwd"><x/>',
            '<?xml-stylesheet href="x"?><x/>',
            "<x><y></x>",
            "<x>",
            "<x/><y/>",
        ],
    )
    def test_refused(self, text) -> None:
        with pytest.raises(SafeXmlError):
            SafeXml.parse(text)

    def test_an_undefined_entity_is_left_as_text_not_expanded(self) -> None:
        assert SafeXml.parse("<x>&undefined;</x>").text == "&undefined;"

    def test_depth_is_bounded(self) -> None:
        depth = MAX_DEPTH + 5
        with pytest.raises(SafeXmlError):
            SafeXml.parse("<a>" * depth + "</a>" * depth)
