"""The knowledge tools: the rules (explained, or searched), how current the intel is, and this
server's own status."""

from __future__ import annotations

from typing import Any

from cordon_scanner.mcp.packages import (
    ECOSYSTEMS,
)
from cordon_scanner.mcp.runner import CancelToken, TimedOut
from cordon_scanner.mcp.tools.base import (
    SEVERITY_ENUM,
    Args,
    Outcome,
    Scans,
    Settings,
    ToolError,
)


class KnowledgeTools:
    @staticmethod
    def rules() -> tuple[list[Any], list[Any]]:
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.rules.loader import RuleLoader

        pack_rules = [compiled.rule for pack in RuleLoader.load_builtin() for compiled in pack]
        return pack_rules, list(
            RuleCatalogue.from_detectors(Registry(allow_third_party=False).detectors())
        )

    @staticmethod
    def entry(rule: Any, origin: str) -> dict[str, Any]:
        return {
            "id": rule.id,
            "title": rule.title,
            "severity": str(rule.severity),
            "confidence": str(rule.confidence),
            "category": str(rule.category),
            "origin": origin,
        }

    @staticmethod
    def explain_rule(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        rule_id = (Args.text(args, "rule_id", required=True, limit=200) or "").strip()
        pack_rules, declared = KnowledgeTools.rules()
        for rule in pack_rules:
            if rule.id == rule_id:
                entry = {
                    **KnowledgeTools.entry(rule, "pack"),
                    "message": rule.message,
                    "remediation": rule.remediation,
                    "references": list(rule.references),
                    "version": rule.version,
                    "rulepack": rule.rulepack,
                    "languages": list(rule.languages),
                    "enabled": rule.enabled,
                }
                return Scans.data(entry, f"{rule.id}: {rule.title}")
        for declared_rule in declared:
            if declared_rule.id == rule_id:
                entry = {
                    **KnowledgeTools.entry(declared_rule, f"detector:{declared_rule.detector}"),
                    "message": declared_rule.message,
                    "remediation": declared_rule.remediation,
                    "references": list(declared_rule.references),
                }
                return Scans.data(entry, f"{declared_rule.id}: {declared_rule.title}")
        raise ToolError(f"no rule {rule_id!r}; search_rules lists them")

    @staticmethod
    def search_rules(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        query = (Args.text(args, "query", limit=200) or "").lower()
        category = Args.text(args, "category", limit=60)
        minimum = args.get("min_severity")
        if minimum is not None and minimum not in SEVERITY_ENUM:
            raise ToolError(f"min_severity must be one of {', '.join(SEVERITY_ENUM)}")
        limit = args.get("limit", 50)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ToolError("limit must be an integer from 1 to 500")
        pack_rules, declared = KnowledgeTools.rules()
        entries = [KnowledgeTools.entry(r, "pack") for r in pack_rules]
        entries += [KnowledgeTools.entry(r, f"detector:{r.detector}") for r in declared]
        floor = SEVERITY_ENUM.index(minimum) if minimum else 0
        matched = sorted(
            (
                e
                for e in entries
                if (not query or query in e["id"].lower() or query in e["title"].lower())
                and (not category or e["category"] == category)
                and (
                    e["severity"] not in SEVERITY_ENUM
                    or SEVERITY_ENUM.index(e["severity"]) >= floor
                )
            ),
            key=lambda e: e["id"],
        )
        return Scans.data(
            {"total_rules": len(entries), "matched": len(matched), "rules": matched[:limit]},
            f"{len(matched)} rule(s) matched",
        )

    @staticmethod
    def intel_status(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        document, _ = Scans.run_json(settings, ["intel", "status", "--json"], token, ok=(0, 1))
        return Scans.data(Scans.document(document, "intel"), "Threat-intel source, serial and age")

    @staticmethod
    def server_status(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        # Imported here: the catalogue imports this module, to list these tools.
        from cordon_scanner.mcp.tools.catalogue import Catalogue

        try:
            run = settings.runner.run(["whoami"], timeout=30, token=token)
            # Signed in or not, never who: the identity would go to the model and its provider.
            cloud = "signed in" if run.exit_code == 0 else "not signed in"
        except TimedOut:
            cloud = "unknown (timed out)"
        structured = {
            "server": "cordon-scanner",
            "version": settings.version,
            "workspace_roots": settings.workspace.describe(),
            "online_allowed": settings.allow_online,
            "machine_reads_allowed": settings.allow_machine,
            "private_network_allowed": settings.allow_private_network,
            "scan_timeout_seconds": settings.timeout,
            "cordon_cloud": cloud,
            "ecosystems": list(ECOSYSTEMS),
            "tools": [t.name for t in Catalogue.available(settings)],
        }
        return Scans.data(structured, "Cordon MCP server status")
