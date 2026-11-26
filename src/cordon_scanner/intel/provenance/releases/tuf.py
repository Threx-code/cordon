"""The parts of The Update Framework a repository's signed metadata is checked with: canonical JSON, role keys and thresholds.

A TUF repository publishes small signed documents: `{"signed": {...}, "signatures": [{"keyid", "method", "sig"}]}`. A document is
the word of a role when at least `threshold` distinct keys that the (already trusted) root names for that role have signed the
canonical bytes of its `signed` part. Ed25519 only, as Hackage uses; a key of another type is not a key here."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
from typing import Any, ClassVar

from cordon_scanner.intel.provenance._ed25519 import Ed25519


class TufError(ValueError):
    """The metadata is not what a trusted root vouches for."""


class CanonicalJson:
    """The byte form TUF signs: sorted keys, no spaces, only `"` and `\\` and control characters escaped, no floats."""

    @classmethod
    def dumps(cls, value: Any) -> bytes:
        out: list[str] = []
        cls._write(value, out)
        return "".join(out).encode("utf-8")

    @classmethod
    def _write(cls, value: Any, out: list[str]) -> None:
        # One writer per exact type, by name: a bool is not an int here, and a new type is a new method.
        writer = getattr(cls, f"_write_{type(value).__name__}", None)
        if writer is None:
            raise TufError(f"a value canonical JSON does not carry: {type(value).__name__}")
        writer(value, out)

    @staticmethod
    def _write_NoneType(value: None, out: list[str]) -> None:
        out.append("null")

    @staticmethod
    def _write_bool(value: bool, out: list[str]) -> None:
        out.append("true" if value else "false")

    @staticmethod
    def _write_int(value: int, out: list[str]) -> None:
        out.append(str(value))

    @classmethod
    def _write_str(cls, value: str, out: list[str]) -> None:
        out.append(cls._string(value))

    @classmethod
    def _write_list(cls, value: list[Any], out: list[str]) -> None:
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            cls._write(item, out)
        out.append("]")

    @classmethod
    def _write_dict(cls, value: dict[str, Any], out: list[str]) -> None:
        out.append("{")
        for index, key in enumerate(sorted(value)):
            if index:
                out.append(",")
            out.append(cls._string(key) + ":")
            cls._write(value[key], out)
        out.append("}")

    @staticmethod
    def _string(text: str) -> str:
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return '"' + "".join(c if ord(c) >= 0x20 else f"\\u{ord(c):04x}" for c in escaped) + '"'


class Tuf:
    ED25519: ClassVar[str] = "ed25519"
    MAX_SIGNATURES: ClassVar[int] = 64

    @staticmethod
    def parse(raw: bytes) -> dict[str, Any]:
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=Tuf._unique)
        except TufError:
            raise
        except (ValueError, UnicodeDecodeError) as exc:
            raise TufError("metadata that is not JSON") from exc
        if (
            not isinstance(document, dict)
            or not isinstance(document.get("signed"), dict)
            or not isinstance(document.get("signatures"), list)
        ):
            raise TufError("metadata that is not a signed document")
        return document

    @staticmethod
    def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise TufError(f"a duplicate key in the metadata: {key}")
            out[key] = value
        return out

    @classmethod
    def keys(cls, root_signed: dict[str, Any]) -> dict[str, bytes]:
        """The root's keys by id, each id checked to be the SHA-256 of the key's canonical form (as Hackage's are)."""
        found: dict[str, bytes] = {}
        for keyid, key in root_signed.get("keys", {}).items():
            if (
                key.get("keytype") != cls.ED25519
                or hashlib.sha256(CanonicalJson.dumps(key)).hexdigest() != keyid
            ):
                raise TufError("a root key of a type not accepted, or whose id is not its digest")
            try:
                public = base64.b64decode(key["keyval"]["public"], validate=True)
            except (KeyError, binascii.Error, ValueError) as exc:
                raise TufError("a root key that does not decode") from exc
            if len(public) != 32:
                raise TufError("an Ed25519 key of the wrong length")
            found[keyid] = public
        return found

    @classmethod
    def signed_by(
        cls, document: dict[str, Any], keyids: list[str], threshold: int, keys: dict[str, bytes]
    ) -> bool:
        """At least `threshold` distinct keys of `keyids` have signed the document's `signed` part."""
        if threshold < 1 or len(document["signatures"]) > cls.MAX_SIGNATURES:
            return False
        message = CanonicalJson.dumps(document["signed"])
        valid: set[str] = set()
        for signature in document["signatures"]:
            keyid = signature.get("keyid") if isinstance(signature, dict) else None
            if (
                keyid not in keyids
                or keyid not in keys
                or keyid in valid
                or signature.get("method") != cls.ED25519
            ):
                continue
            try:
                raw = base64.b64decode(signature["sig"], validate=True)
            except (KeyError, binascii.Error, ValueError, TypeError):
                continue
            if len(raw) == 64 and Ed25519.verify(keys[keyid], message, raw):
                valid.add(keyid)
        return len(valid) >= threshold

    @classmethod
    def role(
        cls, document: dict[str, Any], root_signed: dict[str, Any], name: str
    ) -> dict[str, Any]:
        """The `signed` part of a document that `name`'s keys, per the root, sign in the threshold the root sets."""
        spec = root_signed.get("roles", {}).get(name)
        if not isinstance(spec, dict) or not isinstance(spec.get("threshold"), int):
            raise TufError(f"the root names no role {name}")
        if not cls.signed_by(
            document, list(spec.get("keyids", [])), spec["threshold"], cls.keys(root_signed)
        ):
            raise TufError(
                f"the {name} metadata is not signed by enough of the keys the root names"
            )
        return document["signed"]

    @staticmethod
    def expired(signed: dict[str, Any], now: dt.datetime) -> bool:
        """Whether the metadata has expired; one with no expiry is treated as expired (the roles checked here always have one)."""
        text = signed.get("expires")
        if not isinstance(text, str):
            return True
        try:
            return now >= dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return True
