"""Census A (pypi-98): the decisions `InstallPayload.gate` makes for
`MALWARE.INSTALL.CONSUMER_CODE.001`.

A consumer-install override is the malicious install finding only when a payload is reachable from
the install code. These pin, with inert fixtures, that a compiler or a shipped *script* clears, a
shipped *native binary* or a real payload keeps, only CONSUMER_CODE is ever lowered, and a reachable
payload keeps it (the state that unparsable / unreachable install code fails closed into).
"""

from __future__ import annotations

import pathlib
import tempfile
from types import SimpleNamespace

from cordon_scanner import Scanner
from cordon_scanner.detect.code.install_payload import InstallPayload
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Capability

CONSUMER_CODE = "MALWARE.INSTALL.CONSUMER_CODE.001"

#: A setup.py that overrides the consumer-install command. `{imp}` is imported, `{body}` runs inside
#: the override. Nothing here executes on a scan -- the scanner reads it.
_SETUP = """from setuptools import setup
from setuptools.command.install import install
import {imp}


class Install(install):
    def run(self):
        {body}
        install.run(self)


setup(name="demo", version="1.0", cmdclass={{"install": Install}})
"""

#: ELF magic plus padding: `BinaryDetector.identify` reads it as a native executable. The bytes run
#: nothing; they are a header and zeros.
_ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56


class Fixture:
    """Builds an inert package tree and returns the rule ids a scan reports. Stateless."""

    @staticmethod
    def rules(root: str) -> list[str]:
        return [f.rule_id for f in Scanner().scan(root).findings]

    @staticmethod
    def unit(content: FileContent | None, path: str = "setup.py") -> SimpleNamespace:
        """A stand-in for the FileUnit `gate` reads: it uses only `.content` and `.path`."""
        return SimpleNamespace(content=content, path=path)

    @staticmethod
    def ctx(native: frozenset[str] = frozenset()) -> SimpleNamespace:
        """A stand-in for the ScanContext `gate` reads: it uses only `.shipped_native_paths`."""
        return SimpleNamespace(shipped_native_paths=native)

    @staticmethod
    def build(tmp: str, imp: str, body: str, extra: dict[str, bytes] | None = None) -> str:
        root = pathlib.Path(tmp)
        root.mkdir(parents=True, exist_ok=True)
        (root / "setup.py").write_text(_SETUP.format(imp=imp, body=body), encoding="utf-8")
        for rel, content in (extra or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return str(root)


class TestGateEndToEnd:
    """The whole chain: the engine computes `shipped_native_paths` and the install context, and the
    gate decides. Each case is one inert package."""

    def test_a_compiler_spawn_is_lowered(self) -> None:
        # (a) The install override spawns a system compiler by bare name: build work, not malware.
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(t, "subprocess", 'subprocess.call(["cc", "-c", "x.c"])')
            assert CONSUMER_CODE not in Fixture.rules(root)

    def test_b_spawn_of_a_shipped_native_binary_is_kept(self) -> None:
        # (b) It spawns an ELF the package itself ships -- the author's own code, which no reader of
        # setup.py can see. Kept.
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(
                t, "subprocess", 'subprocess.call(["./dist/helper"])', {"dist/helper": _ELF}
            )
            assert CONSUMER_CODE in Fixture.rules(root)

    def test_c_spawn_of_a_shipped_script_is_lowered(self) -> None:
        # (c) It spawns a shipped shell script, which the scanner reads on its own. Lowered.
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(
                t,
                "subprocess",
                'subprocess.call(["./postinstall.sh"])',
                {"postinstall.sh": b"#!/bin/sh\necho building\n"},
            )
            assert CONSUMER_CODE not in Fixture.rules(root)

    def test_d_reachable_egress_is_kept(self) -> None:
        # (d) The install override reaches the network: a payload. Kept.
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(
                t, "urllib.request", 'urllib.request.urlopen("http://example.com/x").read()'
            )
            assert CONSUMER_CODE in Fixture.rules(root)

    def test_f_a_payload_beside_a_compiler_spawn_is_kept(self) -> None:
        # (f) A compiler spawn alone would lower, but a payload anywhere in the install code keeps it.
        # CONSUMER_CODE is file-scoped, so a payload the install reaches -- the state that unparsable
        # or unprovable reachability fails closed into, counting the code as reached -- keeps it.
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(
                t,
                "subprocess",
                'subprocess.call(["cc", "-c", "x.c"])\n'
                "        import urllib.request\n"
                '        urllib.request.urlopen("http://example.com/x").read()',
            )
            assert CONSUMER_CODE in Fixture.rules(root)


class TestGateUnit:
    """The gate's own decisions, independent of the engine."""

    def test_e_a_non_gated_malicious_finding_is_never_lowered(self) -> None:
        # (e) Only CONSUMER_CODE is gated. Another malicious finding -- even one whose only install
        # capability is a spawn -- is never lowered. The rule-id check short-circuits before the
        # unit and context are read, so they are untouched here.
        assert not InstallPayload.gate(
            "MALWARE.EXFIL.INSTALL_CALLBACK.001",
            True,
            {Capability.SPAWN},
            [],
            Fixture.unit(None),
            Fixture.ctx(),
        )

    def test_a_reachable_payload_capability_keeps_the_finding(self) -> None:
        # A payload capability short-circuits before the unit is read, so it is untouched.
        assert not InstallPayload.gate(
            CONSUMER_CODE, True, {Capability.EGRESS}, [], Fixture.unit(None), Fixture.ctx()
        )

    def test_a_spawn_only_window_with_nothing_shipped_is_lowered(self) -> None:
        unit = Fixture.unit(FileContent(path="setup.py", raw=b"", size=0))
        assert InstallPayload.gate(CONSUMER_CODE, True, {Capability.SPAWN}, [], unit, Fixture.ctx())

    def test_has_payload_truth_table(self) -> None:
        # Always a payload on its own.
        assert InstallPayload.has_payload({Capability.EGRESS})
        assert InstallPayload.has_payload({Capability.FETCH_EXEC})
        assert InstallPayload.has_payload({Capability.CREDENTIAL})
        # Never a payload on their own: build tools spawn compilers and write caches.
        assert not InstallPayload.has_payload({Capability.SPAWN})
        assert not InstallPayload.has_payload({Capability.PERSIST})
        assert not InstallPayload.has_payload({Capability.DELAY, Capability.FLOW})
        # A decode counts only together with a way to run what it produced.
        assert not InstallPayload.has_payload({Capability.DECODE})
        assert InstallPayload.has_payload({Capability.DECODE, Capability.EXECUTE})
        assert InstallPayload.has_payload({Capability.DECOMPRESS, Capability.DESERIALIZE})
