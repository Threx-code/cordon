"""The agent permission surface beyond hooks: what an agent can be declared to do, as a closed vocabulary a policy can restrict.

An agent's declared capabilities are the facts `agent.capabilities` reads. A policy that forbids one of them, for example
`when: {agent.capabilities: delegation}` with `then: block`, blocks every agent that declares it. The four ceiling entries of the agent registry
(network, shell, file write outside the repository, secrets) are a different list, kept by the registry record; these eight are the surface
beyond them.
"""

from __future__ import annotations

from typing import ClassVar, Final


class AgentCapabilities:
    #: Each a declared capability a policy can restrict, in the order the plan names them.
    NAMES: ClassVar[tuple[str, ...]] = (
        "documents",
        "code_execution",
        "package_installs",
        "apis",
        "repository_changes",
        "databases",
        "financial_or_operational_workflows",
        "delegation",
    )
    FIELD: Final = "agent.capabilities"

    @classmethod
    def unknown(cls, declared: tuple[str, ...]) -> tuple[str, ...]:
        """The declared names that are not in the vocabulary."""
        return tuple(name for name in declared if name not in cls.NAMES)


__all__ = ["AgentCapabilities"]
