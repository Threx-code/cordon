"""The `package` rule module: what the scanner knows of the package a file belongs to.

    package.ecosystem / name / version      the release the scan names (its manifest)
    package.place                           where this file runs: install, import, closure,
                                            agent, ci, or ""
    package.install_time                    an install hook, or a file it runs, exists
    package.can(place, capability)          the capability profile: what the code run at
                                            `place` can do ("runs_download", "network", ...)
    package.flow(place, source, sink, dest) a reached file's value from `source` reaches `sink`
                                            with a `dest` kind of destination; "" is any
    package.flows                           how many such flows the reached code has
    package.campaign.siblings / shared      condemned releases sharing two facets with this
                                            one, and the most facets one shares
    package.registry.known / age_days / ... the registry's record of this release

Each value is a fact the package verdict reads (`scanner_facts.facts`). Where the scanner has no
fact, the field is undefined, never false or 0: no registry record means `registry.known` is false
and every other registry field undefined, so a rule cannot mistake no record for a clean one; no
campaign index lookup (a non-npm package) leaves `campaign` undefined.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.binary.modules.scanner_facts.facts import ScanFacts
from cordon_scanner.detect.binary.modules.values import Call, Module, Record, Scalar, Sig

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.detect.base import ScanContext

INT, FLOAT, TEXT, BOOL = Scalar.INT, Scalar.FLOAT, Scalar.TEXT, Scalar.BOOL


class Package:
    """The declaration, and one file's values."""

    #: registry field -> (its reg_* fact, its type)
    REGISTRY: ClassVar[dict[str, tuple[str, Scalar]]] = {
        "age_days": ("reg_name_age_days", FLOAT),
        "first_release": ("reg_first_release", BOOL),
        "prior_versions": ("reg_prior_versions", INT),
        "prior_24h": ("reg_prior_24h", INT),
        "new_publisher": ("reg_new_publisher", BOOL),
        "maintainers": ("reg_maintainers", INT),
        "hooks": ("reg_hooks", INT),
        "hooks_added": ("reg_hooks_added", INT),
        "dependencies_added": ("reg_dependencies_added", INT),
        "confusion_version": ("reg_confusion_version", BOOL),
        "prerelease_build": ("reg_prerelease_build", BOOL),
    }

    SCHEMA: ClassVar[Record] = Record(
        {
            "ecosystem": TEXT,
            "name": TEXT,
            "version": TEXT,
            "place": TEXT,
            "install_time": BOOL,
            "can": Call(Sig(("text", "text"), BOOL)),
            "flow": Call(Sig(("text", "text", "text", "text"), BOOL)),
            "flows": INT,
            "campaign": Record({"siblings": INT, "shared": INT}),
            "registry": Record(
                {"known": BOOL, **{name: kind for name, (_, kind) in REGISTRY.items()}}
            ),
        }
    )

    #: Outside a scan's deferred pass: no facts, every field undefined.
    EMPTY: ClassVar[Module] = Module(SCHEMA, lambda data: {})

    @staticmethod
    def module(facts: Mapping[str, Any], path: str, ctx: ScanContext) -> Module:
        values = Package.values(facts, path, ctx)
        return Module(Package.SCHEMA, lambda data: values)

    @staticmethod
    def values(facts: Mapping[str, Any], path: str, ctx: ScanContext) -> dict[str, Any]:
        t = ScanFacts.text
        can = [tuple(c) for c in facts.get("can", [])]
        flows = [tuple(f) for f in facts.get("flows", [])]
        out: dict[str, Any] = {
            "place": ScanFacts.place(path, ctx).encode(),
            "install_time": bool(ctx.install_hook_paths or ctx.install_entry_paths),
            "can": (lambda place, name: (t(place), t(name)) in can,),
            "flow": (lambda *wanted: any(ScanFacts.matches(map(t, wanted), f) for f in flows),),
            "flows": len(flows),
            "registry": Package.registry(facts.get("registry")),
        }
        identity = facts.get("identity")
        if identity:
            names = ("ecosystem", "name", "version")
            out.update(zip(names, (p.encode() for p in identity), strict=True))
        campaign = facts.get("campaign", {}).get(path.rpartition("!")[0])
        if campaign is not None:
            out["campaign"] = {"siblings": campaign[0], "shared": campaign[1]}
        return out

    @staticmethod
    def registry(reg: Mapping[str, float] | None) -> dict[str, Any]:
        if reg is None:
            return {"known": False}
        out: dict[str, Any] = {"known": True}
        for name, (fact, kind) in Package.REGISTRY.items():
            if fact in reg:
                value = reg[fact]
                out[name] = bool(value) if kind is BOOL else int(value) if kind is INT else value
        return out


__all__ = ["Package"]
