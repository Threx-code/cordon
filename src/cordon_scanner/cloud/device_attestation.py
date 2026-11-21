"""`cordon agent inventory --signed`: a laptop signs what its sweep found, with a key made for that one statement.

The sweep (`device.DeviceInventory`) reports what is CONFIGURED, authenticated by the device's credential. This module
adds a statement the DEVICE signs, so the platform can tell a statement a device made from one a token holder invented,
and a customer can later show it existed and was not edited. It says what the sweep SAW: that a server was present at
the sweep, not that a running session loaded it (only a hook inside the agent can say that).

What the statement contains. A schema word, a time, a session id, and for each MCP server the sweep found that is
launched from a pinned package (`npx pkg@1.2.3`, `uvx pkg==1.2.3`) its package URL (`pkg:npm/%40scope/name@1.2.3`).
Everything the device cannot name that way (a remote URL, a local script, an unpinned package, an editor extension) is
COUNTED in `unnamed`, never listed and never silently left out: a statement that dropped them would read as complete.
No path, host, command, server name or user reaches it; the platform refuses any other field.

The key. One key per statement. It is made in memory, enrolled with a lifetime of minutes, used to sign once and let
go; it is never written to disk. That is what makes the in-house signer acceptable here: it is NOT constant-time (it
was written for the offline release ceremony, `intel/provenance/_ed25519_signer.py`), and a timing attack needs many
signatures under one key, which this never produces.

The credential. The enrolment uses the device's own machine credential (`CORDON_DEVICE_TOKEN`). Every laptop needs its
own (the device-code login, or an MDM integration that mints one per device); one token shared by a fleet is NOT
supported: the platform allows a credential only a few live keys at once, so a shared token is refused in effect.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from datetime import UTC, datetime
from typing import Any, ClassVar

from cordon_scanner.cloud import CloudEndpoint, CloudError
from cordon_scanner.cloud.transport import CloudTransport, Transport
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer


class DeviceAttestation:
    SCHEMA: ClassVar[str] = "cordon.runtime-inventory/v1"
    PAYLOAD_TYPE: ClassVar[str] = "application/vnd.cordon.runtime-inventory.v1+json"
    #: The key role a laptop's CLI enrols for. The platform signs nothing with it; it only checks.
    ROLE: ClassVar[str] = "decision.cli"
    #: Ten minutes. The platform's minimum is five.
    KEY_SECONDS: ClassVar[int] = 600
    #: The platform's limits on one statement.
    MAX_ENTRIES: ClassVar[int] = 500
    MAX_UNNAMED: ClassVar[int] = 5000
    MAX_NAME: ClassVar[int] = 214
    MAX_VERSION: ClassVar[int] = 64

    #: A purl name as the platform reads it: lower case, one optional `scope/` (an npm scope's `@` written `%40`).
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[a-z0-9._~%+-]+(?:/[a-z0-9._~%+-]+)?")
    VERSION: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9._+~-]+")
    PYPI_SPEC: ClassVar[re.Pattern[str]] = re.compile(
        r"([\w.\-]+)(?:\[[\w,.\-]*\])?(?:==|@)(\d[\w.\-+]*)"
    )

    #: How a pinned package is read, by ecosystem: a table keyed by it, so a third ecosystem is one more entry.
    SPLITTERS: ClassVar[dict[str, str]] = {"npm": "_split_npm", "pypi": "_split_pypi"}
    SEPARATORS: ClassVar[str] = "-_."

    # -- the statement -------------------------------------------------------------------------------------------

    @classmethod
    def statement(
        cls, payload: dict[str, Any], *, session: str | None = None, now: datetime | None = None
    ) -> dict[str, Any]:
        """The statement for what `DeviceInventory.collect()` found: packages named, everything else counted."""
        inventory = payload.get("inventory") or {}
        purls: set[str] = set()
        unnamed = 0
        for server in inventory.get("mcp_servers") or ():
            purl = cls._purl(server) if isinstance(server, dict) else None
            if purl is None:
                unnamed += 1
            else:
                purls.add(purl)
        unnamed += len(inventory.get("installed_extensions") or ())
        named = sorted(purls)
        unnamed += max(0, len(named) - cls.MAX_ENTRIES)
        moment = (now or datetime.now(UTC)).astimezone(UTC)
        return {
            "schema": cls.SCHEMA,
            "signed_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session": session or secrets.token_hex(16),
            "unnamed": min(unnamed, cls.MAX_UNNAMED),
            "loaded": [{"kind": "mcp", "purl": purl} for purl in named[: cls.MAX_ENTRIES]],
        }

    @classmethod
    def _purl(cls, server: dict[str, Any]) -> str | None:
        """The package URL of a server launched from a PINNED npm or PyPI package, else None (it is then counted)."""
        ecosystem, spec = server.get("ecosystem"), server.get("package")
        if (
            not isinstance(ecosystem, str)
            or ecosystem not in cls.SPLITTERS
            or server.get("pinned") is not True
            or not isinstance(spec, str)
        ):
            return None
        split = getattr(cls, cls.SPLITTERS[ecosystem])(spec)
        if split is None:
            return None
        name, version = split
        if not cls.NAME.fullmatch(name) or len(name) > cls.MAX_NAME:
            return None
        if not cls.VERSION.fullmatch(version) or len(version) > cls.MAX_VERSION:
            return None
        return f"pkg:{ecosystem}/{name}@{version}"

    @classmethod
    def _split_npm(cls, spec: str) -> tuple[str, str]:
        """`name@1.2.3` or `@scope/name@1.2.3`: the scope's `@` is written `%40` in a package URL."""
        scoped = spec.startswith("@")
        name, _, version = (spec[1:] if scoped else spec).partition("@")
        return (f"%40{name}" if scoped else name), version

    @classmethod
    def _split_pypi(cls, spec: str) -> tuple[str, str] | None:
        """`name==1.2.3` (extras allowed): the name in PEP 503 form, a run of `-`, `_` and `.` made one `-`."""
        match = cls.PYPI_SPEC.fullmatch(spec)
        if match is None:
            return None
        out: list[str] = []
        for char in match[1].lower():
            if char in cls.SEPARATORS:
                if not out or out[-1] != "-":
                    out.append("-")
            else:
                out.append(char)
        return "".join(out), match[2]

    # -- the envelope and the key --------------------------------------------------------------------------------

    @classmethod
    def envelope(cls, statement: dict[str, Any], signer: Ed25519Signer) -> dict[str, Any]:
        """A DSSE envelope: the statement as canonical JSON, signed over the payload type and the payload together, so
        an inventory cannot be passed off as a decision (the platform refuses each as the other)."""
        payload = ArtifactDigests.canonical_json(statement)
        kind = cls.PAYLOAD_TYPE.encode()
        signature = signer.sign(b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload))
        return {
            "payloadType": cls.PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {
                    "keyid": hashlib.sha256(signer.public).hexdigest(),
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    @classmethod
    def enrol(
        cls,
        signer: Ed25519Signer,
        *,
        url: str | None = None,
        token: str | None = None,
        transport: Transport | None = None,
    ) -> str:
        """Enrol the PUBLIC half of `signer` for minutes, with the device's own credential. Returns the key id."""
        device_token = token or os.environ.get("CORDON_DEVICE_TOKEN", "")
        if not device_token:
            raise CloudError("CORDON_DEVICE_TOKEN is not set; each device needs its own credential")
        response = CloudTransport.request(
            "POST",
            f"{CloudEndpoint.base_url(url)}/v1/keys/decision",
            json_body={
                "public_key": signer.public.hex(),
                "role": cls.ROLE,
                "ttl_seconds": cls.KEY_SECONDS,
            },
            token=device_token,
            transport=transport,
        )
        if response.status not in (200, 201):
            raise CloudError(f"the key was refused ({CloudTransport.error_text(response)})")
        data = response.body.get("data")
        keyid = data.get("keyid") if isinstance(data, dict) else None
        if keyid != hashlib.sha256(signer.public).hexdigest():
            raise CloudError("the cloud enrolled a different key than the one sent")
        return str(keyid)

    @classmethod
    def signed(
        cls,
        payload: dict[str, Any],
        *,
        url: str | None = None,
        token: str | None = None,
        transport: Transport | None = None,
        now: datetime | None = None,
        signer: Ed25519Signer | None = None,
    ) -> dict[str, Any]:
        """Make a key, enrol it, sign ONE statement of `payload` with it and return the envelope. The key lives in this
        call: it is not stored, returned or reused. (`signer` is for tests, which need a known key.)"""
        key = signer or Ed25519Signer.generate()
        cls.enrol(key, url=url, token=token, transport=transport)
        return cls.envelope(cls.statement(payload, now=now), key)


__all__ = ["DeviceAttestation"]
