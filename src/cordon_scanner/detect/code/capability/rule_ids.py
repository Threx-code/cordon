"""The composite rules the capability detector treats by name.

Most composites are graded the same way: matched, ceilinged by where they sit, escalated by when they
run. These are the ones a check names because its reasoning is about that rule: the dropper and remote
code rules a verified download withdraws, the exfiltration rules a credential's own service excuses,
the beacon, persistence, callback and credential-store rules, the composites whose context is never
install time, and the ones that run only on request."""

from __future__ import annotations

from typing import ClassVar


class CompositeRuleIds:
    """Composite rule ids, and sets of them, that the detector's checks name."""

    #: Composites whose severity does not depend on where the code runs. An orchestrator starts
    #: its agent with the checks off on purpose, from its activation code as anywhere; what makes
    #: that an attack is the instruction it carries, which is `MALWARE.AGENT.HIJACK.001`.
    CONTEXT_FREE: ClassVar[frozenset[str]] = frozenset({"SUSPECT.AGENT.UNATTENDED.001"})

    PERSIST_RULE = "MALWARE.INSTALL.PERSIST.001"

    #: Composites graded as code that runs unasked when a line runs at import of a published Python
    #: package (`ScanContext.import_reaches`): admitted by their measured pair on M3 half A against
    #: the benign work half (reviews/pypi-98/10). Not INSTALL.PERSIST (1 malware for 2 benign: celery
    #: beat and cron tools schedule by design) nor the model-loading rules (no malware, 2 benign).
    IMPORT_REACH_WITHOUT_MAIN: ClassVar[frozenset[str]] = frozenset(
        {"MALWARE.EXFIL.001", "MALWARE.EXFIL.BEACON.001"}
    )
    """Read at import against what `import pkg` runs, not `python -m pkg`
    (`ScanContext.import_deferred_lines_without_main`, reviews/pypi-98/19): a credential sent or the
    machine reported from a body only `__main__.py` reaches is a program the user started. Only
    these two; every other import-graded composite keeps the full reach."""

    IMPORT_GRADED: ClassVar[frozenset[str]] = frozenset(
        {
            "SUSPECT.DECODE_CHAIN.001",
            "SUSPECT.DECODE_EXEC.001",
            "MALWARE.DROPPER.001",
            "SUSPECT.DROPPER.001",
            "MALWARE.EXFIL.001",
            "MALWARE.EXFIL.BEACON.001",
            "SUSPECT.EXFIL.BEACON.001",
            "MALWARE.EXFIL.INSTALL_CALLBACK.001",
            "SUSPECT.EXFIL.CREDENTIAL_STORE.001",
        }
    )

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
            "SUSPECT.REGISTRY.SELF_PUBLISH.001",
        }
    )
    """Composites lowered when nothing on the load path runs them. A dynamic import in the method
    of a YAML library that resolves `!!python/name:` tags is that library's feature, and a
    function that checks for GitHub Actions before minting its OIDC token is doing its job; the
    same code at a module's top level, or in a hook, is not lowered. A library that exports a publishing
    routine publishes when its caller asks, as a release CLI does (4 benign units on c9e1a4d0's rows, no
    malware); a self-renaming republish loop takes no ceiling at all (item 57)."""

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
    """The one composite the authentication-filename ceiling applies to."""

    #: Composites whose source half is what a file sends: a setting it reads to configure itself is
    #: not that. See `LegitimateUse.a_setting`.
    SETTINGS_ARE_NOT_LOOT: ClassVar[frozenset[str]] = frozenset({"SUSPECT.EXFIL.DROP_POINT.001"})


__all__ = ["CompositeRuleIds"]
