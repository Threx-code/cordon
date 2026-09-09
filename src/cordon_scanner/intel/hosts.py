"""Destinations that make an outbound request mean something specific.

Egress on its own is what every application does. What it is *for* is normally
invisible to a static pass -- a URL in a variable says nothing -- but a small
number of destinations are informative by themselves, because nothing in a
build, an install script or a library has a reason to talk to them.

Three groups, and the reasoning differs for each.

**Webhook endpoints** (Discord, Telegram, Slack incoming hooks). A webhook URL
is a write-only channel to somebody's private chat that requires no
authentication and no infrastructure. That is why it is the most common
exfiltration destination in published npm and PyPI incidents: it costs the
attacker nothing to set up and nothing to keep running. Legitimate software
does post to webhooks, which is why this is a co-signal rather than a finding on
its own -- but a package's install hook posting to one is not notification, it
is collection.

**Paste and file-drop services.** Same reasoning, with a second property: they
accept anonymous uploads and hand back a URL, which makes them a staging point
in both directions -- somewhere to send data, and somewhere to fetch a second
stage from.

**Tunnel and interaction services.** `ngrok`, `interact.sh`, `burpcollaborator`
and their kin exist to receive callbacks from somewhere that cannot be reached
directly. They are ordinary in a penetration test and in local development, and
they have no place in shipped code.

The lists are short and stay short. They are not an attempt at an exhaustive
blocklist -- that is unwinnable, and every extra entry is a string some
legitimate project might contain -- they are the destinations that carry enough
signal to change a finding's severity on their own.
"""

from __future__ import annotations

import re
from typing import Final

WEBHOOK_HOSTS: Final = frozenset(
    {
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "canary.discord.com/api/webhooks",
        "api.telegram.org/bot",
        "hooks.slack.com/services",
        "outlook.office.com/webhook",
        "office.com/webhookb2",
        "chat.googleapis.com/v1/spaces",
        "open.feishu.cn/open-apis/bot",
        "oapi.dingtalk.com/robot/send",
        "qyapi.weixin.qq.com/cgi-bin/webhook",
    }
)
"""Chat webhook endpoints.

Matched on the path as well as the host. `discord.com` is a website; the
`/api/webhooks` prefix is the write-only ingest that needs no credential, and
that difference is what separates a link in a README from a drop point."""

PASTE_HOSTS: Final = frozenset(
    {
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "hasteb.in",
        "ghostbin.co",
        "dpaste.com",
        "controlc.com",
        "rentry.co",
        "termbin.com",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "anonfiles.com",
        "gofile.io",
        "bashupload.com",
        "temp.sh",
        "oshi.at",
    }
)
"""Anonymous paste and file-drop services.

A staging point in both directions: somewhere to send data without an account,
and somewhere to fetch a second stage from without hosting it."""

TUNNEL_HOSTS: Final = frozenset(
    {
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "trycloudflare.com",
        "loca.lt",
        "serveo.net",
        "localtunnel.me",
        "interact.sh",
        "oast.fun",
        "oast.pro",
        "oast.live",
        "oast.site",
        "oastify.com",
        "burpcollaborator.net",
        "requestbin.net",
        "pipedream.net",
        "webhook.site",
        "dnslog.cn",
    }
)
"""Tunnels and out-of-band interaction services.

Built to receive a callback from somewhere that cannot be reached directly.
Ordinary during a penetration test or local development; in shipped code the
only thing they can be for is reaching back out."""

WEBHOOK_ONLY_HOSTS: Final = frozenset(
    {
        "hooks.slack.com",
        "oapi.dingtalk.com",
        "qyapi.weixin.qq.com",
        "open.feishu.cn",
    }
)
"""Hosts that serve nothing but webhook ingest, matched without a path.

The path-qualified entries above exist because `discord.com` is also a website.
These hosts are not: reaching them at all is reaching a webhook. Matching them
bare is what catches the shape a Node client actually produces, where the host
and the path are separate strings and the combined literal never appears --
`https.request({hostname: 'hooks.slack.com', path: '/services/...'})` was
invisible to a list that only held the joined form."""

ALL_HOSTS: Final = WEBHOOK_HOSTS | WEBHOOK_ONLY_HOSTS | PASTE_HOSTS | TUNNEL_HOSTS


def pattern() -> str:
    """A regex alternation over every host, for the egress pack.

    Generated rather than written into a pattern pack so the list has one
    home. A pack that duplicated it would drift, and a drifted blocklist is
    worse than a short one because it still looks maintained.
    """
    return "|".join(re.escape(host) for host in sorted(ALL_HOSTS))


_GENERIC_SEGMENTS = frozenset(
    {
        "com",
        "org",
        "net",
        "io",
        "co",
        "sh",
        "at",
        "st",
        "cn",
        "app",
        "fun",
        "pro",
        "live",
        "site",
        "me",
        "lt",
        "ee",
        "in",
        "api",
        "www",
        "open",
        "apis",
        "bot",
        "send",
        "robot",
        "spaces",
        "services",
        "webhook",
        "webhooks",
        "webhookb2",
        "cgi",
        "bin",
        "v1",
        "file",
        "temp",
        "paste",
        "chat",
        "hooks",
        "canary",
        "oapi",
        "qyapi",
        "outlook",
        "office",
    }
)
"""Segments too common to identify a host on their own.

`paste` and `webhook` appear in ordinary code constantly; using them as a
prefilter would mean the alternation runs anyway."""


def _prefilter() -> tuple[bytes, ...]:
    """Short literals, one of which must be present before the alternation runs.

    Derived from the host list rather than written beside it, so it cannot
    drift out of step with what it is filtering for.

    This is what makes the destination check affordable. Without it the
    eight-hundred-byte alternation ran against every file in every scan, at
    roughly five milliseconds each -- enough to put a fifty-thousand-file
    repository over its latency budget on its own. A substring test is a
    memmem, and it rejects effectively every file before any regex starts.
    """
    literals: set[str] = set()
    for host in ALL_HOSTS:
        for segment in re.split(r"[./-]", host):
            if len(segment) >= 5 and segment not in _GENERIC_SEGMENTS:
                literals.add(segment)
    return tuple(sorted(literal.encode("utf-8") for literal in literals))


PREFILTER: Final = _prefilter()


_PREFILTER_MATCHER: re.Pattern[bytes] | None = None


def could_match(raw: bytes) -> bool:
    """Whether any destination could appear in these bytes.

    One compiled alternation of literals rather than a loop of substring tests.
    The loop is the obvious way to write it and measures about a third slower
    across a large repository, because per-call overhead dominates on the small
    files that make up most of a tree.
    """
    global _PREFILTER_MATCHER
    if _PREFILTER_MATCHER is None:
        _PREFILTER_MATCHER = re.compile(b"|".join(re.escape(x) for x in PREFILTER))
    return _PREFILTER_MATCHER.search(raw) is not None


_MATCHER: re.Pattern[bytes] | None = None


def destination_matcher() -> re.Pattern[bytes]:
    """A compiled matcher over every host, built once and reused.

    Compiled lazily because most scans never reach a file that could match, and
    cached because the alternation is large enough that rebuilding it for every
    file would show up in a profile.
    """
    global _MATCHER
    if _MATCHER is None:
        _MATCHER = re.compile(pattern().encode("utf-8"), re.IGNORECASE)
    return _MATCHER


__all__ = [
    "ALL_HOSTS",
    "PASTE_HOSTS",
    "PREFILTER",
    "TUNNEL_HOSTS",
    "WEBHOOK_HOSTS",
    "WEBHOOK_ONLY_HOSTS",
    "could_match",
    "destination_matcher",
    "pattern",
]
