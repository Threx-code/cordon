"""Census A (pypi-98): whether install-time code reaches a payload.

Extracted from `capability.py` so the install-composite gate can grow without that module. The gate
is the claim that a composite which says "code runs when the package is installed"
(`MALWARE.INSTALL.CONSUMER_CODE.001`) is the malicious finding only when a payload is reachable from
the install code -- egress, a fetch-and-run, a credential read, reconnaissance, a wallet/miner,
destruction, anti-analysis, or a decode-then-run -- or when it spawns a native binary the package
itself ships. A compiler SPAWN, or a spawn of a shipped *script* the scanner reads on its own, is
build/setup work, not malware. Persistence installed at install time is its own payload and is not
gated here; a dropper already requires a fetch-and-run, which is a payload.

`CapabilityDetector` holds the escalation and calls these static methods. `CapabilityHit` and
`FileContent` are imported only for typing, so this module imports no engine code and does not cycle
with `capability.py`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.models import Capability

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.detect.code.capability import CapabilityHit
    from cordon_scanner.foundation.content import FileContent


class InstallPayload:
    """The payload test the install-composite gate uses. Stateless; call the static methods."""

    #: Install composites escalated on a capability a build legitimately has (a compiler SPAWN), so
    #: the malicious finding only when a payload is reachable. INSTALL.PERSIST is not here --
    #: persistence installed at install time is itself the payload -- and DROPPER already requires a
    #: fetch-and-run, which is a payload.
    GATED: ClassVar[frozenset[str]] = frozenset({"MALWARE.INSTALL.CONSUMER_CODE.001"})

    #: Capabilities that make install-reachable code a payload on their own (cordon-f6, census A).
    _ALWAYS: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.EGRESS,
            Capability.FETCH_EXEC,
            Capability.CREDENTIAL,
            Capability.RECONNAISSANCE,
            Capability.WALLET,
            Capability.MINE,
            Capability.DESTROY,
            Capability.ANTI_ANALYSIS,
        }
    )

    @classmethod
    def gate(
        cls,
        rule_id: str,
        installing: bool,
        local_by_capability: dict[Capability, CapabilityHit],
        window: Iterable[CapabilityHit],
        unit: FileUnit,
        ctx: ScanContext,
    ) -> bool:
        """Whether to hold an install composite rather than let it escalate to the malicious install
        finding: it is a gated rule, it runs at install, and no payload is reachable -- neither a
        payload capability nor a spawn of a shipped native binary. The window already excludes what
        `install_deferred_lines` proves the hook never reaches, and unparsable code counts as
        reaching everything, so holding here can only hold a block, never add one (census A)."""
        return (
            rule_id in cls.GATED
            and installing
            and not cls.has_payload(set(local_by_capability))
            and not cls.spawns_shipped_file(
                unit.content, window, ctx.shipped_native_paths, unit.path
            )
        )

    @classmethod
    def has_payload(cls, caps: set[Capability]) -> bool:
        """Whether install-reachable capabilities include a payload. A decode/decompress counts only
        together with a way to run what it produced; SPAWN/PERSIST/DELAY/FLOW/AGENT/TARGETING do not
        count alone -- build tools spawn compilers and write caches."""
        if caps & cls._ALWAYS:
            return True
        return bool(
            caps & {Capability.DECODE, Capability.DECOMPRESS}
            and caps & {Capability.EXECUTE, Capability.DESERIALIZE, Capability.DYNAMIC_DISPATCH}
        )

    _UNPACKER_CALL: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"^(?:[^\n]{0,80}?\(\s{0,4}\[?\s{0,4}[`'\"]|\s{0,16})(?:sudo\s{1,4})?"
        rb"(?:tar|bsdtar|gtar|unzip|gunzip|bunzip2|unxz|xz|zstd|7z|7za)(?=[\s`'\",)\]])"
        rb"(?![^\n]{0,240}?(?:&&|\|\||;[ \t]{0,8}[^\s}]|\||\$\())"
    )
    """A spawn whose program is an archive tool, and which runs nothing after it on the line."""

    @classmethod
    def spawns_unpacker(cls, content: FileContent, hit: CapabilityHit) -> bool:
        """Whether a spawn hit only unpacks an archive: `execSync(`tar -xzf "${tgz}"`)`.

        A dropper runs what it fetched. Unpacking a downloaded release is how an npm package
        installs its platform binary, and it runs nothing: the binary runs later, by a spawn of
        its own that still counts. Measured in the long tail, `tar -xzf` beside the download was
        the dropper's third signal in most of the benign install scripts it blocked (review 98).
        """
        if hit.capability is not Capability.SPAWN:
            return False
        raw = content.raw
        start = raw.rfind(b"\n", 0, hit.byte_start) + 1
        end = raw.find(b"\n", hit.byte_start)
        line = raw[start : end if end != -1 else len(raw)]
        return bool(
            cls._UNPACKER_CALL.search(line[hit.byte_start - start :])
            or cls._UNPACKER_CALL.match(line)
        )

    #: A path-like token in a spawn's argument: `./dist/pip_security`, `rootkit/dist/pip_security`.
    _PATH_TOKEN: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9_./\\-]{2,}")

    @classmethod
    def spawns_shipped_file(
        cls,
        content: FileContent,
        window: Iterable[CapabilityHit],
        native_paths: frozenset[str],
        self_path: str,
    ) -> bool:
        """Whether a spawn in the install window runs a native binary the package itself ships.

        A build spawns a system tool by bare name -- `cc`, `make`, `protoc`; a dropper spawns the
        author's own compiled file by path -- `./dist/pip_security` -- which no reader of the install
        script can see. Keying on the spawn target resolving to a shipped ELF/PE/Mach-O
        (`ctx.shipped_native_paths`) keeps that dropper blocked while a compiler-spawn `setup.py`, and
        one spawning a shipped *script* the scanner reads on its own, both clear.
        """
        if not native_paths:
            return False
        basenames = {p.rsplit("/", 1)[-1] for p in native_paths if p != self_path and "/" in p}
        tails = tuple(p for p in native_paths if p != self_path)
        raw = content.raw
        for hit in window:
            if hit.capability is not Capability.SPAWN:
                continue
            span = raw[hit.byte_start : min(hit.byte_end + 160, len(raw))]
            for tok in cls._PATH_TOKEN.findall(span):
                t = tok.decode("utf-8", "replace").replace("\\", "/").strip("./")
                if not t:
                    continue
                base = t.rsplit("/", 1)[-1]
                if "/" in t and any(p.endswith(t) or p.endswith("/" + base) for p in tails):
                    return True
                if "/" not in t and base in basenames:
                    return True
        return False


__all__ = ["InstallPayload"]
