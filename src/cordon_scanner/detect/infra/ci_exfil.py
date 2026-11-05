"""What a CI step sends, and where: the shared reasoning behind the CI exfiltration rules.

`config_files` declares the rules (`MALWARE.CI.SECRET_TO_DROP_POINT.001`, `MALWARE.CI.SECRET_DUMP.001`,
`MALWARE.CI.CREDENTIAL_HARVEST.001`); this module holds the patterns they match and the checks that
decide a match is theft rather than publishing. GhostAction (2026) is the campaign that prompted
them; every check here was measured against 18,062 benign repositories' workflows.
"""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar, Final

ONE_COMMAND_BREAK: Final = re.compile(rb"(?<!\\)\r?\n")
"""A line break a shell does not continue: the end of one command."""

SECRET_IN_REQUEST: Final = re.compile(
    rb"(?m)^[^\n]{0,400}\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,400}?"
    rb"\b[A-Z][A-Z0-9_]{1,63}=\$\{\{[ \t]{0,8}secrets\.[A-Z][A-Z0-9_]{1,63}[ \t]{0,8}\}\}"
)
"""A request command whose body assigns a secret to a field: `-d 'NAME=${{ secrets.X }}'`."""

SECRET_FIELD: Final = re.compile(
    rb"\b([A-Z][A-Z0-9_]{1,63})=\$\{\{[ \t]{0,8}secrets\.([A-Z][A-Z0-9_]{1,63})[ \t]{0,8}\}\}"
)


class SecretInventory:
    @staticmethod
    def labels_a_secret_by_its_name(
        fields: re.Pattern[bytes], window: bytes, _whole: bytes
    ) -> bool:
        """A field named exactly as the secret it carries: `NPM_TOKEN=${{ secrets.NPM_TOKEN }}`.

        A pipeline hands a credential to the service it is for, under that service's parameter name;
        a list of secrets keyed by their own names is an inventory sent to whoever collects it.
        Case-sensitive on purpose: `token=${{ secrets.TOKEN }}` is a parameter that happens to agree.
        Compared here rather than by a backreference, which the pattern validator refuses."""
        return any(m.group(1) == m.group(2) for m in fields.finditer(window))


CREDENTIAL_FORMAT_SEARCH: Final = re.compile(
    rb"\b(?:e?grep|rg|git[ \t]+grep)\b[^\n]{0,400}?"
    rb"(?:AKIA\[0-9A-Z\]|ASIA\[0-9A-Z\]|sk-ant-|sk-proj-|ghp_|gh\[pousr\]_|glpat-|xox[abps]-|xox\[|AIza)"
)
"""A search of files or history for the FORMAT of a credential -- an AWS key id, an Anthropic or
OpenAI key, a GitHub, GitLab or Slack token: what a secret scanner does, and what a harvester does."""

SENDS_A_VARIABLE: Final = re.compile(
    rb"\b(?:curl|wget)\b[^\n]{0,400}?"
    rb"(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file)"
    rb"[ \t=]{1,4}[\"']?@?\$"
)
"""A request whose body is a shell variable's contents: what was gathered earlier in the step."""


class DropPoint:
    """Whether a command sends a secret to a destination no pipeline publishes to.

    Two shapes look like one and are not (measured on 18,062 benign repositories' workflows):

    * A private, loopback, link-local or carrier-grade-NAT address is the job's own infrastructure
      -- a runner-local service, a test server, an internal deploy target. Any other bare IP is a
      drop point.
    * A chat or webhook service receiving its OWN credential is a notification: a release bot
      posting with `secrets.TELEGRAM_BOT_TOKEN` to `api.telegram.org`. The same service receiving
      any other secret is the exfiltration channel it is in malware. The name that counts is the
      `secrets.NAME` the value comes from -- an env alias (`TELEGRAM_TOKEN: ${{ secrets.NPM_TOKEN
      }}`) is resolved back to it, so renaming a stolen secret does not excuse it; and an alias
      that resolves to no secret is not excused at all. A value in the service's credential slot
      (`/bot<token>/`) is its credential whatever it is called: three release bots in the 18,062
      named theirs `TOKEN` or `BOT_TOKEN`. And the chat a bot posts to (`secrets.CHAT_ID`) is the
      address the service needs, not anything's credential.
    """

    #: (host, the names its own credential goes by, the place in a request where only that
    #: credential can sit). A bot token is the path segment after `/bot` in every Bot API call: a
    #: value there is the bot's credential whatever the workflow calls it (`TOKEN`, `BOT_TOKEN`),
    #: and a stolen secret put there reaches Telegram, not whoever planted the step.
    SERVICES: ClassVar[tuple[tuple[bytes, re.Pattern[bytes], re.Pattern[bytes] | None], ...]] = (
        (
            b"api.telegram.org",
            re.compile(rb"TELEGRAM|(?:^|_)TG(?:_|$)|TGBOT", re.I),
            re.compile(
                rb"api\.telegram\.org/bot\$\{?\{?[ \t]{0,8}(?:secrets\.)?([A-Za-z_]\w{0,63})"
            ),
        ),
        (b"hooks.slack.com", re.compile(rb"SLACK", re.I), None),
        (b"discord.com/api/webhooks", re.compile(rb"DISCORD", re.I), None),
        (b"discordapp.com/api/webhooks", re.compile(rb"DISCORD", re.I), None),
    )
    _SECRET: ClassVar[re.Pattern[bytes]] = re.compile(rb"secrets\.(\w{1,64})")
    _VAR: ClassVar[re.Pattern[bytes]] = re.compile(rb"\$\{?([A-Za-z_][A-Za-z0-9_]{0,63})\}?")
    #: `NAME: ${{ secrets.X }}` in an `env:` mapping, or `NAME="${{ secrets.X }}"` in the script.
    _ALIAS: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,63})[ \t]*[:=][ \t]*['\"]?"
        rb"\$\{\{[ \t]*secrets\.(\w{1,64})"
    )
    _IP: ClassVar[re.Pattern[bytes]] = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")
    #: The job's own networks: a runner-local service, a VPC, a test container. Everything else,
    #: documentation ranges included, is somewhere outside the pipeline.
    OWN_NETWORKS: ClassVar[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = tuple(
        ipaddress.ip_network(n)
        for n in (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "0.0.0.0/8",
        )
    )
    _CREDENTIAL: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIAL|PRIVATE_KEY|WEBHOOK", re.I
    )
    _DESTINATION_ID: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?:^|_)(?:CHAT|CHANNEL|GROUP|THREAD|TOPIC)_?ID$", re.I
    )

    @classmethod
    def sends_to_one(cls, destinations: re.Pattern[bytes], window: bytes, whole: bytes) -> bool:
        for found in destinations.finditer(window):
            text = found.group(0)
            address = cls._IP.search(text)
            if address is not None:
                try:
                    ip = ipaddress.ip_address(address.group(0).decode())
                except ValueError:
                    return True
                if not any(ip in net for net in cls.OWN_NETWORKS):
                    return True
                continue
            service = next((s for s in cls.SERVICES if s[0] in text.lower()), None)
            if service is None or not cls._own_credential(service[1], service[2], window, whole):
                return True
        return False

    @classmethod
    def _own_credential(
        cls,
        names: re.Pattern[bytes],
        slot: re.Pattern[bytes] | None,
        window: bytes,
        whole: bytes,
    ) -> bool:
        """Every secret the command sends is the destination service's own."""
        aliases = {m.group(1): m.group(2) for m in cls._ALIAS.finditer(whole)}
        slotted = {m.group(1) for m in slot.finditer(window)} if slot is not None else set()
        owned = slotted | {aliases[n] for n in slotted if n in aliases}
        sent = [m.group(1) for m in cls._SECRET.finditer(window)]
        for var in cls._VAR.finditer(window):
            name = var.group(1)
            if name in aliases:
                sent.append(aliases[name])  # judged by the secret it really holds
            elif cls._CREDENTIAL.search(name):
                sent.append(name)  # a credential not mapped from `secrets`: judged by its own name
        # Which chat to post to is the address the service needs, not a credential of anything.
        sent = [name for name in sent if not cls._DESTINATION_ID.search(name)]
        return bool(sent) and all(name in owned or names.search(name) for name in sent)


_FETCH_RUN = rb"\b(?:curl|wget)\b[^\n|]{0,300}\|\s{0,4}(?:sudo\s{1,4})?(?:ba|z|da|k)?sh\b"
SCHEDULED_FETCH_RUN: Final = re.compile(
    rb"(?m)^[^\n]{0,600}?(?:"
    + _FETCH_RUN
    + rb"[^\n]{0,400}?\bcrontab\b|\bcrontab\b[^\n]{0,400}?"
    + _FETCH_RUN
    + rb")"
)
"""A crontab entry, written in one command, that downloads code and pipes it into a shell: code the
attacker can change at will, run every few minutes on whatever runner keeps the job. No pipeline
schedules that; GhostAction's later waves did (measured 0 of 81,662 benign workflow files)."""


__all__ = [
    "CREDENTIAL_FORMAT_SEARCH",
    "ONE_COMMAND_BREAK",
    "SCHEDULED_FETCH_RUN",
    "SECRET_FIELD",
    "SECRET_IN_REQUEST",
    "SENDS_A_VARIABLE",
    "DropPoint",
    "SecretInventory",
]
