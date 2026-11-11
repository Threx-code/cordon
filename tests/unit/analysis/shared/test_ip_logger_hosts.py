"""IP-logger services are drop points and interaction hosts (`analysis/shared/destinations.py`).

Every host is assembled here from pieces and only parsed: nothing is contacted. The twins are
ordinary hosts that share a word or a suffix with one."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.shared.destinations import IP_LOGGER_HOSTS, Destinations
from cordon_scanner.detect.code.capability.destinations import DestinationLabels
from cordon_scanner.foundation.content import FileContent


def _labels(text: str) -> list[str]:
    raw = text.encode()
    content = FileContent(path="pkg/mod.py", raw=raw, size=len(raw))
    return [hit.rule_id for hit in DestinationLabels.destination_capabilities(content, "python")]


class TestAnIpLoggerLink:
    @pytest.mark.parametrize("host", sorted(IP_LOGGER_HOSTS))
    def test_each_host_is_an_interaction_host(self, host: str) -> None:
        assert Destinations.is_interaction_host(host)
        assert Destinations.is_interaction_host("x1." + host)

    def test_a_request_to_a_short_link_is_a_drop_point_and_an_interaction(self) -> None:
        host = "grab" + "ify.link"
        source = f"import urllib.request\nurllib.request.urlopen('https://{host}/a1b2')\n"
        assert _labels(source) == ["INTEL.EGRESS.DROP_POINT.001", "INTEL.EGRESS.INTERACTION.001"]

    def test_the_second_family(self) -> None:
        host = "ip" + "logger.org"
        source = f"import requests\nrequests.get('https://{host}/1abc')\n"
        assert "INTEL.EGRESS.INTERACTION.001" in _labels(source)


class TestOrdinaryHostsThatLookLikeOne:
    def test_a_host_that_only_ends_in_the_same_letters(self) -> None:
        for host in ("notgrabify.link.example.com", "grabify.example.org", "myiplogger.example.net"):
            assert not Destinations.is_interaction_host(host)

    def test_a_logging_library_site(self) -> None:
        source = "import requests\nrequests.get('https://docs.python.org/3/library/logging.html')\n"
        assert _labels(source) == []
