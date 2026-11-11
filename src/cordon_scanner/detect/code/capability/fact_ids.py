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
        # Files swept from the disk, sent through a helper to a destination the code hides.
        ("swept files sent", "AST.PY.SWEPT_SENT"),
        # What a caller hands a class, sent on by the class to a destination it hides.
        ("relayed to hidden", "AST.PY.RELAYED_HIDDEN"),
        # What arrives on a connection, a bot update or a fetched sheet, run as a command.
        ("received run", "AST.PY.RECEIVED_RUN"),
        # Encoded data resolved as DNS names: a channel out that no firewall rule for HTTP sees.
        ("dns tunnel", "AST.PY.DNS_TUNNEL"),
        ("code from a data file", "AST.PY.CODE_FROM_DATA"),
        # A program the file assembles from its literals (indexed, joined from codes,
        # reversed) and executes: fixed, but written so that no literal is it.
        ("computed code executed", "AST.PY.COMPUTED_EXEC"),
        # A process start whose command holds a piece spelled the same way (openblox 1.0.0).
        ("computed command run", "AST.PY.COMPUTED_COMMAND"),
        # A module or function reached by a name spelled the same way (apkeep 1.0.1).
        ("concealed name resolved", "AST.PY.CONCEALED_NAME"),
        # A value decoded (base64, hex, XOR) and then never read: carried for something else.
        ("decoded and left unused", "AST.PY.DORMANT_DECODE"),
        # Files written into a directory, and the files listed there executed (scrapetools2).
        ("dropped into a directory and executed", "AST.PY.DIRECTORY_DROP_RUN"),
        # Text decoded out of bytes and executed (rasterkit_demo).
        ("bytes decoded and executed", "AST.PY.BYTES_EXEC"),
        # Mail sent at import from an account the module logs into with literal credentials.
        ("mail sent on import", "AST.PY.IMPORT_MAIL"),
        # A payload literal handed at import to a function nothing defines (cubaflixdownload).
        ("unresolved call on a payload literal", "AST.PY.UNRESOLVED_PAYLOAD"),
        # A literal command on a system temp path, at module level (maliciouspackage 0.1).
        ("literal command on a temp path", "AST.PY.TEMP_COMMAND"),
        # A password sent to a free-hosting, paste, tunnel or interaction host (project47).
        ("credentials sent to a free host", "AST.PY.CREDENTIALS_FREE_HOST"),
        # A Defender exclusion or switch-off run as a command (rainbowcolors 0.1.0).
        ("antivirus exclusion added", "AST.PY.AV_EXCLUSION"),
        # A persistence location written by code that runs when the file is loaded.
        ("persist at load", "AST.PY.PERSIST_AT_LOAD"),
        # The clipboard read, matched against a pattern, and set to a value the package brings.
        ("clipboard replaced", "AST.PY.CLIPBOARD_REPLACED"),
        # Keystrokes captured and written down or sent.
        ("keystrokes logged", "AST.PY.KEYSTROKES_LOGGED"),
        # A link that logs the address of whoever opens it, handed to a request or a command.
        ("ip logger fetched", "AST.PY.IP_LOGGER_FETCHED"),
        # What the machine knows (environment, host and user names, platform) put in a cloud store.
        ("machine facts uploaded", "AST.PY.MACHINE_FACTS_UPLOADED"),
        # A program started and left running when the package is imported.
        ("program started at import", "AST.PY.PROGRAM_STARTED_AT_IMPORT"),
        # Files swept from a directory and sent to a free-hosting, paste, tunnel or interaction host.
        ("sweep sent to a rentable host", "AST.PY.SWEPT_TO_RENTABLE_HOST"),
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
        # The same drop with the program carried as plain source, started detached (CarriedPrograms).
        "starts a carried program detached",
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
            return (
                "AST.PY.BACKDOOR_CARRIED"
                if detail.endswith(" carried")
                else "AST.PY.BACKDOOR_WRITE"
            )
        if detail.endswith(cls.DROPPED):
            return "AST.PY.DECODED_DROP_RUN"
        for prefix, rule in cls.MODEL:
            if detail.startswith(prefix):
                return rule
        if detail.startswith("executed literal") and capability in cls.HIDDEN_ACTION:
            return "AST.PY.HIDDEN_ACTION"
        return f"AST.PY.{capability.name}"


__all__ = ["PythonFactIds"]
