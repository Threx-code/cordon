"""The rule id each Python analyser fact is labelled with (`Labelling.resolved_capabilities`).

The analyser describes what it resolved in a detail string (`identity sent: requests.post`,
`hidden request: urlopen dest=decoded`); a composite matches on a rule id. This is the one table
from the first to the second, read in order: the first entry whose test holds names the fact,
and a fact no entry names is labelled by its capability (`AST.PY.EGRESS`).
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.foundation.capabilities import Capability


class PythonFactIds:
    """Detail string -> rule id, for the Python analyser's facts."""

    #: Facts named by how their detail starts, in the order they are tried.
    PREFIXES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("identity sent", "AST.PY.IDENTITY_SENT"),
        ("environment sent", "AST.PY.ENVIRONMENT_SENT"),
        ("secret sent", "AST.PY.SECRET_SENT"),
        # A request whose destination the code decodes, reverses or builds from character codes,
        # whatever it sends (`HiddenDestination`).
        ("hidden request", "AST.PY.HIDDEN_REQUEST"),
        # What arrives on a connection, a bot update or a fetched sheet, run as a command.
        ("received run", "AST.PY.RECEIVED_RUN"),
    )
    #: A payload carried encoded, written out and made runnable or run.
    DROPPED: ClassVar[tuple[str, ...]] = (
        "a decoded file runnable",
        "runs a decoded file",
        "decoded file as code",
    )
    #: Model loading facts (see `MALWARE.INSTALL.HIDDEN_ACTION.001` for executed literals).
    MODEL: ClassVar[tuple[tuple[str, str], ...]] = (
        ("unsafe model load", "AST.PY.UNSAFE_MODEL_LOAD"),
        ("remote model code", "AST.PY.REMOTE_MODEL_CODE"),
        ("unsafe model option", "AST.PY.UNSAFE_MODEL_OPTION"),
    )
    #: A spawn, request or credential read written inside a string the file then executes.
    HIDDEN_ACTION: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.SPAWN, Capability.EGRESS, Capability.FETCH_EXEC, Capability.CREDENTIAL}
    )

    @classmethod
    def rule_id(cls, detail: str, capability: Capability) -> str:
        """The rule id this fact is labelled with."""
        for prefix, rule in cls.PREFIXES:
            if detail.startswith(prefix):
                return rule
        if detail.endswith(cls.DROPPED):
            return "AST.PY.DECODED_DROP_RUN"
        for prefix, rule in cls.MODEL:
            if detail.startswith(prefix):
                return rule
        if detail.startswith("executed literal") and capability in cls.HIDDEN_ACTION:
            return "AST.PY.HIDDEN_ACTION"
        return f"AST.PY.{capability.name}"


__all__ = ["PythonFactIds"]
