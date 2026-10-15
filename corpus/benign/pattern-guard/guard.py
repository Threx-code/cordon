"""A request filter: refuses tool calls that touch startup files or keys.

The pattern lists the places it refuses. A pattern names what to look for; nothing here reads or
writes any of those paths. Arguments may arrive base64-encoded, so they are decoded before the check.
"""

import base64
import binascii
import re

REFUSED = re.compile(
    r"(?:^|[\s\"'=:(,])(?:/etc/(?:rc\.local|systemd/system|init\.d|profile\.d|cron\.d)"
    r"|(?:~|\$HOME)/\.(?:ssh|aws|bashrc|zshrc|profile|config/autostart))"
)


def decoded(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return value


def refused(argument: str) -> bool:
    return bool(REFUSED.search(argument) or REFUSED.search(decoded(argument)))
