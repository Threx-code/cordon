"""G15: `scan pkg:<purl>`, `deps`, `suppress list|add|prune` and `completion`.

No test here reaches a registry: archive downloads are substituted with fixed bytes and digests. The
suppression tests edit real files in a temporary directory, because what matters is the file left on
disk -- its comments, its layout, and that it still loads.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import tarfile
from datetime import date
from pathlib import Path

import pytest

from cordon_scanner.cli.completion import CommandTree, CompletionScript
from cordon_scanner.cli.deps import DependencyView
from cordon_scanner.cli.main import CommandLine
from cordon_scanner.cli.suppressions import SuppressCommand, SuppressionFile, SuppressionRules
from cordon_scanner.core.config import OrgConstraints
from cordon_scanner.core.errors import ConfigError, ExitCode
from cordon_scanner.core.models import Category, Suppression
from cordon_scanner.intel import more_registries, registry_client
from cordon_scanner.intel.more_registries import MoreRegistries
from cordon_scanner.intel.registry_client import (
    PackageArchive,
    PackageFacts,
    RegistryClient,
    RegistryError,
)
from cordon_scanner.sources.package import PackageTarget, PackageTargetError

TODAY = date(2026, 10, 3)
GOOD = "Downloads the pinned toolchain and verifies its sha256 before running it."


class PackageHelpers:
    @staticmethod
    def tgz(files: dict[str, str]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()


class TestParsingPackageUrls:
    @pytest.mark.parametrize(
        "purl, expected",
        [
            ("pkg:npm/left-pad@1.3.0", ("npm", "left-pad", "1.3.0")),
            ("pkg:npm/%40types/node@20.11.0", ("npm", "@types/node", "20.11.0")),
            ("pkg:npm/@types/node@20.11.0", ("npm", "@types/node", "20.11.0")),
            ("pkg:npm/types/node@20.11.0", ("npm", "@types/node", "20.11.0")),
            ("pkg:npm/left-pad", ("npm", "left-pad", None)),
            ("pkg:pypi/requests@2.31.0", ("pypi", "requests", "2.31.0")),
            ("pkg:cargo/serde@1.0.0", ("cargo", "serde", "1.0.0")),
            ("pkg:gem/rack@3.1.6", ("rubygems", "rack", "3.1.6")),
            ("pkg:nuget/Newtonsoft.Json@13.0.1", ("nuget", "Newtonsoft.Json", "13.0.1")),
            ("pkg:PyPI/six@1.16.0", ("pypi", "six", "1.16.0")),
        ],
    )
    def test_supported_forms(self, purl, expected) -> None:
        target = PackageTarget.parse(purl)
        assert (target.ecosystem, target.name, target.version) == expected

    @pytest.mark.parametrize(
        "purl, fragment",
        [
            ("pkg:npm/left-pad@1.3.0?repository_url=https://evil.example", "qualifiers"),
            ("pkg:npm/left-pad@1.3.0#lib/index.js", "qualifiers"),
            ("pkg:conan/zlib@1.3", "cannot fetch"),
            ("pkg:npm/", "not a valid"),
            ("pkg:pypi/a/b@1.0", "not a valid"),
            ("pkg:npm/../../etc/passwd@1", "not a valid"),
            ("pkg:npm/left-pad@1.0 ; rm", "not a valid version"),
            ("npm/left-pad@1.0", "not a package URL"),
            ("pkg:npm/" + "a" * 600, "not a package URL"),
        ],
    )
    def test_refused_forms_say_why(self, purl, fragment) -> None:
        with pytest.raises(PackageTargetError, match=fragment):
            PackageTarget.parse(purl)

    @pytest.mark.parametrize(
        "filename, ecosystem, expected",
        [
            ("left-pad-1.3.0.tgz", "npm", "left-pad-1.3.0.tgz"),
            ("../../etc/cron.d/x.tgz", "npm", "x.tgz"),
            ("..\\..\\evil.gem", "rubygems", "evil.gem"),
            ("serde-1.0.0", "cargo", "serde-1.0.0.crate"),
            ("weird name;$(x).zip", "pypi", "weird_name___x_.zip"),
            ("....", "npm", "package.tgz"),
        ],
    )
    def test_the_registrys_filename_is_never_trusted(self, filename, ecosystem, expected) -> None:
        assert PackageTarget.safe_filename(filename, ecosystem) == expected


class TestFetchingAndScanning:
    @pytest.fixture
    def archive(self, monkeypatch):
        def install(result: PackageArchive | Exception) -> None:
            def fake(ecosystem, name, version):
                if isinstance(result, Exception):
                    raise result
                return result

            monkeypatch.setattr(RegistryClient, "package_archive", staticmethod(fake))

        return install

    def test_the_archive_exists_only_for_the_block(self, archive) -> None:
        archive(PackageArchive("npm", "demo", "1.0.0", "demo-1.0.0.tgz", b"bytes"))
        with PackageTarget.parse("pkg:npm/demo@1.0.0").fetched() as path:
            assert path.read_bytes() == b"bytes"
            if (
                os.name != "nt"
            ):  # POSIX permission bits; Windows has ACLs instead and reports every file as 0o666.
                assert oct(path.stat().st_mode & 0o777) == "0o600"
                assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
            held = path
        assert not held.exists() and not held.parent.exists()

    def test_the_directory_is_removed_when_the_scan_fails(self, archive) -> None:
        archive(PackageArchive("npm", "demo", "1.0.0", "demo-1.0.0.tgz", b"bytes"))
        with (
            pytest.raises(RuntimeError),
            PackageTarget.parse("pkg:npm/demo@1.0.0").fetched() as path,
        ):
            held = path
            raise RuntimeError("scan crashed")
        assert not held.parent.exists()

    def test_a_registry_failure_is_a_target_error(self, archive) -> None:
        archive(RegistryError("does not match the integrity npm publishes"))
        with (
            pytest.raises(PackageTargetError, match="does not match"),
            PackageTarget.parse("pkg:npm/demo@1.0.0").fetched(),
        ):
            pass

    def test_scanning_a_package_url_needs_online(self, capsys) -> None:
        assert CommandLine.run(["scan", "pkg:npm/demo@1.0.0"]) == 3
        assert "--online" in capsys.readouterr().err

    def test_a_malformed_package_url_is_a_usage_error(self, capsys) -> None:
        assert CommandLine.run(["scan", "pkg:conan/zlib@1", "--online"]) == 3

    def test_a_package_that_cannot_be_fetched_is_never_clean(self, archive, capsys) -> None:
        archive(RegistryError("registry.npmjs.org has no package by that name"))
        assert CommandLine.run(["scan", "pkg:npm/nope@1.0.0", "--online"]) not in (0, 1)

    def test_the_fetched_archive_is_scanned(self, archive, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            RegistryClient,
            "facts",
            staticmethod(lambda *a: PackageFacts(name="demo", version="1.0.0")),
        )
        data = PackageHelpers.tgz(
            {
                "package/package.json": json.dumps(
                    {"name": "demo", "version": "1.0.0", "scripts": {"postinstall": "node i.js"}}
                ),
                "package/i.js": "eval(Buffer.from(process.argv[2], 'base64').toString());\n",
            }
        )
        archive(PackageArchive("npm", "demo", "1.0.0", "demo-1.0.0.tgz", data))
        code = CommandLine.run(
            ["scan", "pkg:npm/demo@1.0.0", "--online", "--format", "json", "--no-color"]
        )
        output = capsys.readouterr()
        report = json.loads(output.out)
        assert code == 1
        assert "digest verified" in output.err
        assert any(f["rule_id"].startswith(("MALWARE.", "SUSPECT.")) for f in report["findings"])


class TestVerifiedArchivesForMoreRegistries:
    @pytest.fixture
    def serve(self, monkeypatch):
        def install(facts: PackageFacts, body: bytes) -> list[str]:
            fetched: list[str] = []
            monkeypatch.setattr(MoreRegistries, "facts", staticmethod(lambda e, n, v: facts))

            def fetch(url, ecosystem):
                fetched.append(url)
                return body

            monkeypatch.setattr(registry_client.RegistryClient, "_fetch_bytes", staticmethod(fetch))
            return fetched

        return install

    def test_a_crate_matching_its_checksum(self, serve) -> None:
        body = b"crate-bytes"
        fetched = serve(
            PackageFacts(
                name="serde", version="1.0.0", digests=(hashlib.sha256(body).hexdigest(),)
            ),
            body,
        )
        archive = MoreRegistries.archive("cargo", "serde", "1.0.0")
        assert archive.filename == "serde-1.0.0.crate" and archive.data == body
        assert fetched == ["https://static.crates.io/crates/serde/serde-1.0.0.crate"]

    def test_a_gem_that_does_not_match_is_refused(self, serve) -> None:
        serve(PackageFacts(name="rack", version="3.1.6", digests=("ab" * 32,)), b"tampered")
        with pytest.raises(RegistryError, match="does not match"):
            MoreRegistries.archive("rubygems", "rack", "3.1.6")

    def test_a_nupkg_is_verified_against_the_catalog_sha512(self, serve) -> None:
        body = b"nupkg-bytes"
        digest = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
        fetched = serve(
            PackageFacts(name="Newtonsoft.Json", version="13.0.1", digests=(digest,)), body
        )
        archive = MoreRegistries.archive("nuget", "Newtonsoft.Json", "13.0.1")
        assert archive.filename == "newtonsoft.json.13.0.1.nupkg"
        assert fetched == [
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        ]

    def test_nothing_to_verify_against_is_a_refusal_not_a_pass(self, serve) -> None:
        fetched = serve(PackageFacts(name="serde", version="1.0.0"), b"x")
        with pytest.raises(RegistryError, match="nothing to verify against"):
            MoreRegistries.archive("cargo", "serde", "1.0.0")
        assert fetched == []

    def test_the_latest_is_resolved_when_no_version_is_named(self, serve) -> None:
        body = b"x"
        serve(
            PackageFacts(
                name="serde",
                version=None,
                latest="1.0.229",
                digests=(hashlib.sha256(body).hexdigest(),),
            ),
            body,
        )
        assert MoreRegistries.archive("cargo", "serde", None).version == "1.0.229"

    def test_archive_hosts_are_confined_per_registry(self) -> None:
        with pytest.raises(RegistryError, match="allowlist"):
            RegistryClient._fetch_bytes("https://evil.example/serde.crate", "cargo")
        with pytest.raises(RegistryError, match="allowlist"):
            RegistryClient._fetch_bytes("http://static.crates.io/serde.crate", "cargo")


class TestLargeRegistryDocuments:
    def test_a_gzip_body_is_expanded(self) -> None:
        import gzip

        assert RegistryClient._gunzip(gzip.compress(b'{"a": 1}'), "h") == b'{"a": 1}'

    def test_an_expansion_past_the_ceiling_is_refused(self, monkeypatch) -> None:
        import gzip

        monkeypatch.setattr(registry_client, "MAX_RESPONSE_BYTES", 100)
        with pytest.raises(RegistryError, match="expands past"):
            RegistryClient._gunzip(gzip.compress(b"0" * 10_000), "h")

    def test_a_corrupt_body_is_an_error(self) -> None:
        with pytest.raises(RegistryError, match="unreadable"):
            RegistryClient._gunzip(b"\x1f\x8bjunk", "h")

    def test_the_ceiling_fits_the_largest_real_packuments(self) -> None:
        # `next` is about 30 MB uncompressed; the old 4 MB ceiling refused it, and with it most of
        # the packages people install most.
        assert registry_client.MAX_RESPONSE_BYTES >= 40 << 20
        assert more_registries.base.MAX_RESPONSE_BYTES == registry_client.MAX_RESPONSE_BYTES

    def test_a_pinned_npm_archive_reads_only_the_version_document(self, monkeypatch) -> None:
        body = b"tarball"
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
        asked: list[str] = []

        def fetch(url, **kwargs):
            asked.append(url)
            return {
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                    "integrity": integrity,
                },
            }

        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(fetch))
        monkeypatch.setattr(RegistryClient, "_fetch_bytes", staticmethod(lambda url, eco: body))
        archive = RegistryClient._npm_archive("@scope/demo", "1.0.0")
        assert asked == ["https://registry.npmjs.org/@scope/demo/1.0.0"] and archive.data == body


class TestSuppressionFile:
    TEXT = (
        "version: 1\n"
        "# Why each exception exists is recorded here.\n"
        "suppressions:\n"
        "  # Kept for the record.\n"
        "  - rule: SUSPECT.SPAWN.001\n"
        "    path: scripts/old.mjs\n"
        f'    justification: "{GOOD}"\n'
        '    expires: "2020-01-01"\n'
        "  - rule: SUSPECT.DROPPER.001\n"
        "    path: scripts/fetch.sh\n"
        f'    justification: "{GOOD}"\n'
        '    expires: "2026-12-01"\n'
        "\n"
        "evidence: masked\n"
    )

    @staticmethod
    def rules(**constraints) -> SuppressionRules:
        categories = {
            "SUSPECT.SPAWN.001": Category.SUSPICIOUS,
            "SUSPECT.DROPPER.001": Category.SUSPICIOUS,
            "SUSPECT.PERSIST.001": Category.SUSPICIOUS,
            "MALWARE.INSTALL.FETCH_EXEC.001": Category.MALICIOUS,
        }
        return SuppressionRules(
            OrgConstraints(**constraints) if constraints else OrgConstraints.permissive(),
            categories,
        )

    @staticmethod
    def args(**fields) -> argparse.Namespace:
        defaults = {
            "rule": "SUSPECT.PERSIST.001",
            "path": "bin/setup.sh",
            "justification": GOOD,
            "expires": None,
            "days": None,
            "approved_by": None,
        }
        return argparse.Namespace(**{**defaults, **fields})

    def write(self, tmp_path: Path, text: str | None = None) -> SuppressionFile:
        path = tmp_path / "cordon.yaml"
        path.write_text(self.TEXT if text is None else text, encoding="utf-8")
        return SuppressionFile(path)

    def test_states_today(self, tmp_path) -> None:
        file = self.write(tmp_path)
        states = [self.rules().state(s, TODAY) for s in file.suppressions()]
        assert [s.state for s in states] == ["expired", "active"]
        assert states[1].detail == "expires in 59 day(s)"

    def test_a_suppression_naming_no_rule_is_refused_in_the_listing(self, tmp_path) -> None:
        file = self.write(tmp_path, self.TEXT.replace("SUSPECT.DROPPER.001", "SUSPECT.DROPER.001"))
        assert self.rules().state(file.suppressions()[1], TODAY).state == "refused"

    def test_add_writes_an_entry_the_scanner_reads_and_keeps_every_comment(self, tmp_path) -> None:
        file = self.write(tmp_path)
        SuppressCommand.add(file, self.rules(), TODAY, self.args(days=10))
        text = file.path.read_text(encoding="utf-8")
        assert (
            "# Kept for the record." in text
            and "# Why each exception" in text
            and "evidence: masked" in text
        )
        added = file.suppressions()[-1]
        assert (added.rule, added.path, added.expires) == (
            "SUSPECT.PERSIST.001",
            "bin/setup.sh",
            "2026-10-13",
        )

    def test_add_creates_the_config_when_there_is_none(self, tmp_path) -> None:
        file = SuppressionFile(tmp_path / "cordon.yaml")
        SuppressCommand.add(file, self.rules(), TODAY, self.args(expires="2026-11-01"))
        assert file.path.read_text(encoding="utf-8").startswith("version: 1\n")
        assert file.suppressions()[0].expires == "2026-11-01"

    def test_add_into_an_empty_inline_list(self, tmp_path) -> None:
        file = self.write(tmp_path, "version: 1\nsuppressions: []\n")
        SuppressCommand.add(file, self.rules(), TODAY, self.args())
        assert len(file.suppressions()) == 1

    def test_a_justification_with_quotes_colons_and_hashes_survives(self, tmp_path) -> None:
        file = self.write(tmp_path)
        text = 'Runs "make" once: the # in the path is literal, and é is not a problem here.'
        SuppressCommand.add(file, self.rules(), TODAY, self.args(justification=text))
        assert file.suppressions()[-1].justification == text

    @pytest.mark.parametrize(
        "fields, message",
        [
            ({"rule": "MALWARE.INSTALL.FETCH_EXEC.001"}, "forbids suppressing"),
            ({"rule": "NO.SUCH.RULE"}, "suppresses nothing"),
            ({"justification": "false positive"}, "at least 40"),
            ({"path": "**/setup.sh"}, "`\\*\\*`"),
            ({"path": "*"}, "wildcard"),
            ({"expires": "2026-10-03"}, "future"),
            ({"expires": "2027-12-01"}, "exceeding the maximum"),
            ({"expires": "next week"}, "ISO date"),
            ({"days": 0}, "at least 1"),
            ({"justification": GOOD + "\x1b[31m"}, "control characters"),
        ],
    )
    def test_add_refuses_what_the_scanner_would_refuse(self, tmp_path, fields, message) -> None:
        file = self.write(tmp_path)
        before = file.path.read_text(encoding="utf-8")
        with pytest.raises(ConfigError, match=message):
            SuppressCommand.add(file, self.rules(), TODAY, self.args(**fields))
        assert file.path.read_text(encoding="utf-8") == before

    def test_an_approver_is_demanded_when_policy_says_so(self, tmp_path) -> None:
        file = self.write(tmp_path)
        with pytest.raises(ConfigError, match="approver"):
            SuppressCommand.add(file, self.rules(require_approver=True), TODAY, self.args())
        SuppressCommand.add(
            file, self.rules(require_approver=True), TODAY, self.args(approved_by="security-team")
        )
        assert file.suppressions()[-1].approved_by == "security-team"

    def test_a_duplicate_is_refused(self, tmp_path) -> None:
        file = self.write(tmp_path)
        with pytest.raises(ConfigError, match="already suppresses"):
            SuppressCommand.add(
                file,
                self.rules(),
                TODAY,
                self.args(rule="SUSPECT.DROPPER.001", path="scripts/fetch.sh"),
            )

    def test_prune_removes_expired_entries_with_their_comments(self, tmp_path, capsys) -> None:
        file = self.write(tmp_path)
        SuppressCommand.prune(file, TODAY, dry_run=False)
        text = file.path.read_text(encoding="utf-8")
        assert "scripts/old.mjs" not in text and "# Kept for the record." not in text
        assert (
            "scripts/fetch.sh" in text
            and "evidence: masked" in text
            and "# Why each exception" in text
        )
        assert "removed: SUSPECT.SPAWN.001" in capsys.readouterr().out

    def test_a_dry_run_changes_nothing(self, tmp_path, capsys) -> None:
        file = self.write(tmp_path)
        SuppressCommand.prune(file, TODAY, dry_run=True)
        assert file.path.read_text(encoding="utf-8") == self.TEXT
        assert "would remove" in capsys.readouterr().out

    def test_pruning_everything_leaves_an_empty_list_that_loads(self, tmp_path) -> None:
        file = self.write(tmp_path)
        SuppressCommand.prune(file, date(2027, 6, 1), dry_run=False)
        assert (
            "suppressions: []" in file.path.read_text(encoding="utf-8")
            and file.suppressions() == ()
        )

    def test_a_write_that_would_not_read_back_is_refused_and_the_file_is_untouched(
        self, tmp_path
    ) -> None:
        file = self.write(tmp_path)
        before = file.path.read_text(encoding="utf-8")
        with pytest.raises(ConfigError, match="does not read back"):
            file.replace(before + "\n", (Suppression("X", "y", GOOD, "2027-01-01"),))
        assert file.path.read_text(encoding="utf-8") == before

    def test_the_files_mode_is_kept(self, tmp_path) -> None:
        file = self.write(tmp_path)
        file.path.chmod(0o640)
        SuppressCommand.add(file, self.rules(), TODAY, self.args())
        if (
            os.name != "nt"
        ):  # POSIX permission bits; Windows has ACLs instead and reports every file as 0o666.
            assert oct(file.path.stat().st_mode & 0o777) == "0o640"
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".cordon-")]

    def test_the_cli_lists_as_json(self, tmp_path, capsys) -> None:
        self.write(tmp_path)
        assert (
            CommandLine.run(["suppress", "list", "--root", str(tmp_path), "--format", "json"]) == 0
        )
        listed = json.loads(capsys.readouterr().out)["suppressions"]
        assert [s["state"] for s in listed] == ["expired", "active"]

    def test_the_cli_refuses_suppressing_malware(self, tmp_path, capsys) -> None:
        self.write(tmp_path)
        code = CommandLine.run(
            [
                "suppress",
                "add",
                "MALWARE.INSTALL.FETCH_EXEC.001",
                "x.sh",
                "--justification",
                GOOD,
                "--root",
                str(tmp_path),
            ]
        )
        assert code == 3 and "forbids suppressing" in capsys.readouterr().err


class TestDeps:
    def test_the_graph_nests_and_carries_findings(self, tmp_path, capsys) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "dependencies": {"express": "4.17.1"}}), encoding="utf-8"
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "demo",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "demo", "dependencies": {"express": "4.17.1"}},
                        "node_modules/express": {
                            "version": "4.17.1",
                            "dependencies": {"qs": "6.7.0"},
                        },
                        "node_modules/qs": {"version": "6.7.0"},
                    },
                }
            ),
            encoding="utf-8",
        )
        assert CommandLine.run(["deps", str(tmp_path)]) == 0
        lines = capsys.readouterr().out.splitlines()
        express = next(i for i, line in enumerate(lines) if line.startswith("npm:express@4.17.1"))
        assert lines[express + 1].startswith("  npm:qs@6.7.0")
        assert "VULNERABLE.DEPENDENCY.KNOWN.001" in lines[express + 1]

        assert CommandLine.run(["deps", str(tmp_path), "--format", "json", "--direct-only"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [d["name"] for d in payload["dependencies"]] == ["express"]

    def test_no_lockfile_says_so(self, tmp_path) -> None:
        from cordon_scanner.core.models import ScanResult

        assert (
            DependencyView(ScanResult())
            .render_text(direct_only=False)[0]
            .startswith("no dependencies found")
        )

    def test_an_incomplete_graph_exits_incomplete_not_as_a_scanner_error(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        # Found by running `deps --online` on axios: an advisory source that covers no package
        # of an ecosystem leaves the scan incomplete, and deps answered 2 -- "a bug in Cordon".
        import cordon_scanner
        from cordon_scanner.core.models import ScanResult

        monkeypatch.setattr(
            cordon_scanner.Scanner, "scan", lambda self, target: ScanResult(complete=False)
        )
        assert CommandLine.run(["deps", str(tmp_path)]) == int(ExitCode.INCOMPLETE)
        assert "incomplete" in capsys.readouterr().err

    def test_a_missing_target_is_an_error(self, tmp_path, capsys) -> None:
        assert CommandLine.run(["deps", str(tmp_path / "nope")]) != 0


class TestCompletion:
    @pytest.fixture
    def tree(self) -> CommandTree:
        return CommandTree.from_parser(CommandLine.build_parser())

    def test_every_command_is_completed(self, tree) -> None:
        assert {"scan", "deps", "suppress", "completion", "rules", "sbom"} <= set(
            tree.subcommands[""]
        )
        assert tree.subcommands["suppress"] == ["add", "list", "prune"]
        assert "--dry-run" in tree.options["suppress prune"]
        assert "--online" in tree.options["scan"]

    @pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
    def test_each_shell_renders(self, shell) -> None:
        script = CompletionScript(CommandLine.build_parser(), "cordon-scanner").render(shell)
        assert "cordon-scanner" in script and "suppress" in script

    def test_zsh_reuses_the_bash_script_through_bashcompinit(self) -> None:
        script = CompletionScript(CommandLine.build_parser(), "cordon-scanner").render("zsh")
        assert script.startswith("autoload -U +X bashcompinit && bashcompinit\n")

    def test_an_unknown_shell_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unsupported shell"):
            CompletionScript(CommandLine.build_parser(), "cordon-scanner").render("powershell")

    def test_the_cli_prints_it(self, capsys) -> None:
        assert CommandLine.run(["completion", "bash"]) == 0
        assert "complete -F _cordon_scanner cordon-scanner" in capsys.readouterr().out
