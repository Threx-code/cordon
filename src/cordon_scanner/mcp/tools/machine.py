"""The machine tools: container images, and this machine's own packages and AI agents (which need
--allow-machine)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.mcp.runner import CancelToken
from cordon_scanner.mcp.tools.base import (
    Args,
    Outcome,
    Scans,
    Settings,
    ToolError,
)


class MachineTools:
    IMAGE: ClassVar[re.Pattern[str]] = re.compile(
        r"^[a-z0-9][a-z0-9._/-]{0,254}(?::[A-Za-z0-9_.-]{1,128})?(?:@sha256:[0-9a-f]{64})?$"
    )

    @staticmethod
    def image_purl(image: str) -> str:
        if image.startswith("pkg:"):
            return image
        if not MachineTools.IMAGE.match(image):
            raise ToolError(
                "image must be a reference such as nginx:1.27, ghcr.io/org/app:2 or name@sha256:<digest>"
            )
        name, _, digest = image.partition("@")
        last = name.rsplit("/", 1)[-1]
        repo, tag = (name.rsplit(":", 1)[0], name.rsplit(":", 1)[1]) if ":" in last else (name, "")
        return f"pkg:docker/{repo}@{digest or tag or 'latest'}"

    @staticmethod
    def scan_container_image(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        if not settings.allow_online:
            raise ToolError(
                "an image is pulled from its registry, and online checks are off for this server (--allow-online)"
            )
        image = (Args.text(args, "image", required=True, limit=400) or "").strip()
        return Scans.outcome(
            Scans.scan(
                settings,
                MachineTools.image_purl(image),
                token,
                online=True,
                severity=Args.severity(args),
                max_findings=Args.max_findings(settings, args),
                subject={"image": image},
                cache=False,
            )
        )

    @staticmethod
    def scan_machine(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        extra = ["--host"]
        if Args.flag(args, "include_home"):
            extra += ["--home", str(Path.home())]
        return Scans.outcome(
            Scans.scan(
                settings,
                "/",
                token,
                online=online,
                severity=Args.severity(args),
                extra=extra,
                max_findings=Args.max_findings(settings, args),
                subject={"machine": "this computer's installed packages"},
            )
        )

    @staticmethod
    def list_local_agents(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        document, _ = Scans.run_json(settings, ["agent", "inventory"], token, ok=(0, 1))
        found = Scans.document(document, "inventory")
        found.pop("device", None)
        return Scans.data(
            found,
            "AI agents, MCP servers and editor extensions configured on this machine (nothing was sent anywhere)",
        )
