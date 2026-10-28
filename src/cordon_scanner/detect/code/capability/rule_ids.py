"""The composite rules the capability detector treats by name.

Most composites are graded the same way: matched, ceilinged by where they sit, escalated by when they
run. These are the ones a check names because its reasoning is about that rule: the dropper and remote
code rules a verified download withdraws, the exfiltration rules a credential's own service excuses,
the beacon, persistence, callback and credential-store rules, the composites whose context is never
install time, and the ones that run only on request."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    pass


class CompositeRuleIds:
    """Composite rule ids, and sets of them, that the detector's checks name."""

    #: Composites whose severity does not depend on where the code runs. An orchestrator starts
    #: its agent with the checks off on purpose, from its activation code as anywhere; what makes
    #: that an attack is the instruction it carries, which is `MALWARE.AGENT.HIJACK.001`.
    CONTEXT_FREE: ClassVar[frozenset[str]] = frozenset({"SUSPECT.AGENT.UNATTENDED.001"})

    PERSIST_RULE = "MALWARE.INSTALL.PERSIST.001"

    CALLBACK_RULE = "MALWARE.EXFIL.INSTALL_CALLBACK.001"

    EXFIL_RULES = frozenset({"SUSPECT.EXFIL.001", "MALWARE.EXFIL.001"})

    ON_REQUEST_RULES = frozenset(
        {
            "SUSPECT.DROPPER.001",
            "SUSPECT.DROPPER.REMOTE_CODE.001",
            "SUSPECT.DYNAMIC_DISPATCH.001",
            "SUSPECT.EXFIL.BEACON.001",
            "SUSPECT.ANTI_ANALYSIS.001",
            "SUSPECT.DECODE_EXEC.001",
            "SUSPECT.MODEL.LOADED_ON_IMPORT.001",
            "SUSPECT.PERSIST.001",
        }
    )

    DROPPER_RULE = "SUSPECT.DROPPER.001"

    #: The flow dropper (a response reaching execute/process, including written to disk then run --
    #: review 98 round 2 B). Lowered like DROPPER_RULE when the download is a verified own release,
    #: so a sha256-checked self-update stays below the gate; kept out of VERIFIABLE_DROPPERS so the
    #: no-download-run escalations do not apply to it.
    REMOTE_CODE_RULE = "SUSPECT.DROPPER.REMOTE_CODE.001"

    #: Malware grade -> its suspect grade, which a verified download leaves reporting (review 98 #28).
    WITHDRAWN_WHEN_VERIFIED: ClassVar[dict[str, str]] = {
        "MALWARE.DROPPER.001": DROPPER_RULE,
        "MALWARE.INSTALL.REMOTE_CODE.001": REMOTE_CODE_RULE,
    }

    #: Rules whose act is destroying data. They keep their severity in build tooling: a recipe
    #: runs unattended on every machine that builds, so "written to be read" does not hold.
    DESTRUCTION_RULES: ClassVar[frozenset[str]] = frozenset(
        {"SUSPECT.DESTROY.HOME_OR_ROOT.001", "MALWARE.PROTESTWARE.001"}
    )

    BEACON_RULE: ClassVar[str] = "MALWARE.EXFIL.BEACON.001"

    #: The two grades of the same dropper pattern, the only findings `VerifiedDownload` may lower.
    VERIFIABLE_DROPPERS: ClassVar[frozenset[str]] = frozenset(
        {"MALWARE.DROPPER.001", "SUSPECT.DROPPER.001"}
    )

    CREDENTIAL_STORE_RULE = "SUSPECT.EXFIL.CREDENTIAL_STORE.001"

    #: Composites whose source half is what a file sends: a setting it reads to configure itself is
    #: not that. See `LegitimateUse.a_setting`.
    SETTINGS_ARE_NOT_LOOT: ClassVar[frozenset[str]] = frozenset({"SUSPECT.EXFIL.DROP_POINT.001"})


__all__ = ["CompositeRuleIds"]
