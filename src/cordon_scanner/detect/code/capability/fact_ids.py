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
        # A credential store's contents sent outside the store's own service: to a hidden, chat,
        # raw-IP or unknown host, or a fixed-home store (aws, ssh) off its home. An upload tool
        # sending .pypirc to the index it names is not this (MALWARE.EXFIL.CREDENTIAL_STORE.002).
        ("secret sent: CREDENTIAL_FILE outside=", "AST.PY.CREDSTORE_SENT"),
        ("identity sent", "AST.PY.IDENTITY_SENT"),
        ("environment sent", "AST.PY.ENVIRONMENT_SENT"),
        ("secret sent", "AST.PY.SECRET_SENT"),
        # A request whose destination the code decodes, reverses or builds from character codes,
        # whatever it sends (`HiddenDestination`).
        ("hidden request", "AST.PY.HIDDEN_REQUEST"),
        # What arrives on a connection, a bot update or a fetched sheet, run as a command.
        ("received run", "AST.PY.RECEIVED_RUN"),
        # Encoded data resolved as DNS names: a channel out that no firewall rule for HTTP sees.
        ("dns tunnel", "AST.PY.DNS_TUNNEL"),
        ("code from a data file", "AST.PY.CODE_FROM_DATA"),
        # A persistence location written by code that runs when the file is loaded.
        ("persist at load", "AST.PY.PERSIST_AT_LOAD"),
        # The clipboard read, matched against a pattern, and set to a value the package brings.
        ("clipboard replaced", "AST.PY.CLIPBOARD_REPLACED"),
        # Keystrokes captured and written down or sent.
        ("keystrokes logged", "AST.PY.KEYSTROKES_LOGGED"),
        # A link that logs the address of whoever opens it, handed to a request or a command.
        ("ip logger fetched", "AST.PY.IP_LOGGER_FETCHED"),
        # A persistence write with a hidden launch (no window) beside it.
        ("autostart hidden", "AST.PY.AUTOSTART_HIDDEN"),
        # A persistence write with a run of a program the package downloaded, decoded or ships beside it.
        ("persist and run", "AST.PY.PERSIST_RUN"),
        ("shipped program run", "AST.PY.SHIPPED_RUN"),
        # Packages installed from an index the user did not choose, or with host checks off.
        ("foreign index install", "AST.PY.FOREIGN_INDEX"),
        # A file that gives someone else a way in written: authorized_keys, sudoers, passwd/shadow, ssh rc.
    )
    #: The suffix the analyser puts on a downloaded program's start when it hides the window.
    HIDDEN_START: ClassVar[str] = "hidden=1"
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
        if " runs a downloaded " in detail and detail.split()[-1] == cls.HIDDEN_START:
            # A downloaded program started with its window hidden: concealment on top of a
            # dropper (MALWARE.DROPPER.HIDDEN.001), never lowered for running only when called.
            return "AST.PY.HIDDEN_FETCH_EXEC"
        for prefix, rule in cls.PREFIXES:
            if detail.startswith(prefix):
                return rule
        if detail.startswith("backdoor write"):
            # A file that gives someone else a way in, written. `carried`: what is written is the
            # package's own (a literal, a module constant, a decode of one), whoever calls it.
            return "AST.PY.BACKDOOR_CARRIED" if detail.endswith(" carried") else "AST.PY.BACKDOOR_WRITE"
        if detail.endswith(cls.DROPPED):
            return "AST.PY.DECODED_DROP_RUN"
        for prefix, rule in cls.MODEL:
            if detail.startswith(prefix):
                return rule
        if detail.startswith("executed literal") and capability in cls.HIDDEN_ACTION:
            return "AST.PY.HIDDEN_ACTION"
        return f"AST.PY.{capability.name}"


__all__ = ["PythonFactIds"]
