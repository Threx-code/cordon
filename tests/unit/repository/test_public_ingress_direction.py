"""An egress rule open to the internet is not ingress from it.

Found scanning terraform-aws-eks: its recommended node security-group rules end in `egress_all`
(`type = "egress"`, `from_port = 0`, `cidr_blocks = ["0.0.0.0/0"]`) -- what every AWS security
group allows by default -- and it was reported HIGH as "ingress permitted from the entire
internet". The rule's own shape, range and all-ports in one block, says nothing about direction.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner

RULE = "SUSPECT.IAC.PUBLIC_INGRESS.001"
OPEN = '  from_port = 0\n  to_port = 0\n  protocol = "-1"\n  cidr_blocks = ["0.0.0.0/0"]\n'


class TestDirection:
    @staticmethod
    def found(tmp_path, body: str, name: str = "main.tf") -> set[str]:
        (tmp_path / name).write_text(body, encoding="utf-8")
        return {f.rule_id for f in Scanner().scan(tmp_path).findings}

    @pytest.mark.parametrize(
        "body",
        [
            # aws_security_group_rule
            'resource "aws_security_group_rule" "out" {\n  type = "egress"\n' + OPEN + "}\n",
            # an inline block on aws_security_group
            'resource "aws_security_group" "sg" {\n  name = "x"\n  egress {\n' + OPEN + "  }\n}\n",
            # a module's rule map, as terraform-aws-eks writes it
            'locals {\n  rules = {\n    egress_all = {\n      description = "Allow all egress"\n'
            + OPEN
            + '      type = "egress"\n    }\n  }\n}\n',
            # Azure
            'resource "azurerm_network_security_rule" "out" {\n  direction = "Outbound"\n'
            '  access = "Allow"\n  destination_port_range = "*"\n'
            '  source_address_prefix = "*"\n}\n',
        ],
    )
    def test_an_outbound_rule_is_not_reported(self, tmp_path, body: str) -> None:
        assert RULE not in self.found(tmp_path, body)

    @pytest.mark.parametrize(
        "body",
        [
            'resource "aws_security_group_rule" "in" {\n  type = "ingress"\n' + OPEN + "}\n",
            'resource "aws_security_group" "sg" {\n  name = "x"\n  ingress {\n' + OPEN + "  }\n}\n",
            # An egress block elsewhere in the resource does not excuse the ingress one.
            'resource "aws_security_group" "sg" {\n  egress {\n'
            + OPEN
            + "  }\n  ingress {\n"
            + OPEN
            + "  }\n}\n",
            'resource "azurerm_network_security_rule" "in" {\n  direction = "Inbound"\n'
            '  access = "Allow"\n  destination_port_range = "*"\n'
            '  source_address_prefix = "*"\n}\n',
        ],
    )
    def test_an_inbound_rule_still_is(self, tmp_path, body: str) -> None:
        assert RULE in self.found(tmp_path, body)
