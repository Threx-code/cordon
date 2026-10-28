"""Three campaigns' acts in JavaScript, each read whole-file from its own patterns.

`plants_agent_config`: an install script copying execution-capable agent configuration into the
project being installed into (`INIT_CWD`). `attribution_cloak`: a mobile attribution callback
beside a server-chosen WebView or a POST. `channel_follow`: a messaging library made to follow a
fixed channel. Moved beside `capability/detector.py` (0.7.0 layout: a long module only shrinks);
`CapabilityDetector` calls these and labels what they return.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.detector import CapabilityHit
from cordon_scanner.foundation.models import Capability

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.content import FileContent


class JsCampaigns:
    #: npm's name for the project that is installing the package, and a write or copy into it.
    _JS_INTO_PROJECT: ClassVar[re.Pattern[str]] = re.compile(r"\bINIT_CWD\b")
    _JS_COPY_OR_WRITE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:cpSync|cp|copyFileSync|copyFile|copySync|copy|writeFileSync|writeFile|outputFileSync"
        r"|outputFile|ensureFileSync|symlinkSync|renameSync)\s*\("
    )
    #: Agent configuration that makes the agent RUN something when it opens a project: the MCP
    #: servers it starts, the settings that hold its hooks and status-line commands. A template
    #: `CLAUDE.md` is text a person reads (a QA pack's postinstall copies one); a server list is
    #: a program the agent launches (review 98: the benign corpus held the first, the planting
    #: packages ship both).
    _AGENT_CONFIG_MEMBER: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|/)(?:\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|\.gemini/settings\.json"
        r"|\.claude/settings(?:\.local)?\.json|\.claude/hooks/.+)$"
    )

    @classmethod
    def plants_agent_config(
        cls, ctx: ScanContext, content: FileContent, language: str | None
    ) -> list[CapabilityHit]:
        """Code that copies or writes into the installing project (`INIT_CWD`) in a package that
        ships an AI agent's configuration: the package plants an MCP server, a system prompt or
        agent settings in the user's own repository, and the next agent session there loads them
        unasked.

        The `0x2ai-demo*` packages (npm, 2026): a postinstall `cpSync(payload, INIT_CWD)` drops
        `.mcp.json`, `CLAUDE.md` and `.claude/settings.json`, registering the publisher's MCP server
        with a persona prompt in every project that installs them (review 98, 17-PROOF-REVIEW). The
        composite takes it only where the file runs at install (`context: install_hook`): a
        scaffolder a person runs by name writes a CLAUDE.md because it was asked to."""
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        into = cls._JS_INTO_PROJECT.search(text)
        if into is None or cls._JS_COPY_OR_WRITE.search(text) is None:
            return []
        if not any(
            "node_modules/" not in path and cls._AGENT_CONFIG_MEMBER.search(path.rpartition("!")[2])
            for path in ctx.tree_paths
        ):
            return []
        line = text.count("\n", 0, into.start()) + 1
        start = len(text[: into.start()].encode("utf-8"))
        return [
            CapabilityHit(
                capability=Capability.FLOW,
                rule_id="CAP.JS.AGENT_CONFIG_PLANTED",
                byte_start=start,
                byte_end=start + 1,
                line=line,
            )
        ]

    #: A WebView whose page is a variable: `<WebView source={{ uri: link }} />`.
    _RN_WEBVIEW_VAR: ClassVar[re.Pattern[str]] = re.compile(
        r"<WebView\b[^>]{0,400}?source=\{\{\s*uri:\s*[A-Za-z_$]"
    )
    #: The mobile attribution SDKs' install/conversion callbacks: who installed the app, from
    #: which campaign.
    _RN_ATTRIBUTION: ClassVar[re.Pattern[str]] = re.compile(
        r"\bonInstallConversionData\b|\bonConversionDataSuccess\b|\bonAppOpenAttribution\b"
        r"|\bAdjust\w*\.\s*(?:getAttribution|setAttributionCallback)|\bbranch\.subscribe\s*\("
    )

    #: Data sent: a POST through axios or fetch.
    _RN_POST: ClassVar[re.Pattern[str]] = re.compile(
        r"\baxios\s*\.\s*post\s*\(|method:\s*['\"]POST['\"]"
    )

    @classmethod
    def attribution_cloak(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """A component that takes the app's install-attribution data and shows a page the server
        chooses in a WebView: the cloaking component of fake React Native packages.

        The `sproger` campaign (npm, 2026, 37 packages): on mount, `appsFlyer.onInstallConversionData`
        hands the attribution data to `axios.post` to the publisher, a remote config then names
        a URL, and a WebView hidden by `display: 'none'` shows it full-screen only when the server
        sends one -- App Store review sees a calculator, users see whatever the server picks
        (review 98, 17-PROOF-REVIEW: 18 of the study half's blind misses; on 92,999 benign npm
        units only a package of the same campaign). SDKs that render a link in a WebView (video
        rooms, polls, KYC) never read attribution callbacks."""
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        attribution = cls._RN_ATTRIBUTION.search(text)
        if attribution is None:
            return []
        # The page and the report can sit in separate files of the package (the campaign's
        # variants split them): either beside the attribution callback is the shape.
        view = cls._RN_WEBVIEW_VAR.search(text) or cls._RN_POST.search(text)
        if view is None:
            return []
        line = text.count("\n", 0, view.start()) + 1
        start = len(text[: view.start()].encode("utf-8"))
        return [
            CapabilityHit(
                capability=Capability.FLOW,
                rule_id="CAP.JS.ATTRIBUTION_CLOAK",
                byte_start=start,
                byte_end=start + 1,
                line=line,
            )
        ]

    #: A WhatsApp Channel's id written into code: `120363xxxxxxxxxx@newsletter`.
    _WA_CHANNEL: ClassVar[re.Pattern[str]] = re.compile(r"(?<![\w.])\d{10,22}@newsletter\b")
    #: Subscribing the signed-in account to a channel: the library's follow call, or the raw
    #: `w:mex` FOLLOW query it sends.
    _WA_FOLLOW: ClassVar[re.Pattern[str]] = re.compile(
        r"\bnewsletterFollow\s*\(|\bfollowNewsletter\s*\(|\bnewsletterWMexQuery\s*\([^)]{0,200}FOLLOW"
        r"|['\"]FOLLOW['\"]|\bQueryIds\.FOLLOW\b"
    )
    #: Where a WhatsApp Web library (Baileys and its forks) keeps its own code: the socket, its
    #: utilities and its defaults. The library defines a follow call and never names a channel.
    _WA_LIBRARY: ClassVar[re.Pattern[str]] = re.compile(r"(?:^|/)lib/(?:Socket|Utils|Defaults)/")

    @classmethod
    def channel_follow(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """A WhatsApp Channel id hard-coded where the library subscribes accounts: in a WhatsApp
        Web library's own socket, utility or default code, or beside a follow call.

        Over 100 near-identical forks of Baileys (npm, 2026) add a file to `lib/Socket/` or edit
        `newsletter.js` so that every account that connects through them follows the publisher's
        channels without being asked (review 98: 22 of 479 code-bearing misses of the bulk-2 study
        half; on all 92,999 benign npm units, only forks carrying the same added files). A bot
        that shows a channel id as an example in its settings has neither the library layout nor
        a follow call (two n8n nodes in the benign corpus)."""
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        found = cls._WA_CHANNEL.search(text)
        if found is None:
            return []
        member = content.path.rpartition("!")[2]
        if not (cls._WA_LIBRARY.search(member) or cls._WA_FOLLOW.search(text)):
            return []
        line = text.count("\n", 0, found.start()) + 1
        start = len(text[: found.start()].encode("utf-8"))
        return [
            CapabilityHit(
                capability=Capability.FLOW,
                rule_id="CAP.JS.WHATSAPP_CHANNEL_FOLLOW",
                byte_start=start,
                byte_end=start + 1,
                line=line,
            )
        ]


__all__ = ["JsCampaigns"]
