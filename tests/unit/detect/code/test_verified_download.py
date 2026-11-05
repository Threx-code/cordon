"""A checksum-verified release download is reported, not blocked (review 98, FP-2).

`@ohos-ports/larksuite-cli`'s postinstall downloads its release archive from a release host,
compares its sha256 with the line in the `checksums.txt` it ships, and only then extracts and
`chmod`s it. Blocked as `MALWARE.DROPPER.001` at CRITICAL. The exemption may only lower the
dropper-by-pattern finding, to `SUSPECT.DROPPER.001` at MEDIUM -- never clear the file -- and
each condition failing keeps the block.

Every fixture here is inert text written into a tarball and scanned; none is executed. Hosts are
`example.invalid`, documentation addresses, or repositories that do not exist.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.code.verified_download import VerifiedDownload
from cordon_scanner.foundation.models import Severity

RELEASE = "https://registry.npmmirror.com/-/binary/example-tool/v${VERSION}/example-tool.tar.gz"
GITHUB = "https://github.com/example-owner/example-tool/releases/download/v${VERSION}/tool.tar.gz"

CHECK = """function verify(file) {
  const lines = fs.readFileSync(path.join(__dirname, "checksums.txt"), "utf8").split("\\n");
  const expected = lines[0].split("  ")[0];
  const actual = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  if (actual !== expected) {
    throw new Error("checksum mismatch");
  }
}
"""


class VerifiedKit:
    """Builds an npm tarball around an install script, and scans it."""

    @staticmethod
    def script(
        url: str = RELEASE,
        *,
        check: str = CHECK,
        verify_first: bool = True,
        extra: str = "",
        prelude: str = "",
    ) -> str:
        install_steps = (
            ["download(DOWNLOAD_URL, archive);", "verify(archive);", "unpack(archive);"]
            if verify_first
            else ["download(DOWNLOAD_URL, archive);", "unpack(archive);", "verify(archive);"]
        )
        return (
            'const fs = require("fs");\n'
            'const os = require("os");\n'
            'const path = require("path");\n'
            'const crypto = require("crypto");\n'
            'const { execFileSync } = require("child_process");\n'
            'const VERSION = "1.2.3";\n'
            f"{prelude}"
            f"const DOWNLOAD_URL = `{url}`;\n"
            "function download(url, dest) {\n"
            '  execFileSync("curl", ["--fail", "--location", "--output", dest, url]);\n'
            "}\n"
            f"{check}"
            # The shape larksuite's script has: extract (PowerShell on Windows), copy the binary
            # into place, make it executable.
            "function unpack(archive) {\n"
            '  if (process.platform === "win32") {\n'
            '    execFileSync("powershell.exe", ["-NoProfile", "-Command", "Expand-Archive x"]);\n'
            "  } else {\n"
            '    execFileSync("tar", ["-xzf", archive, "-C", os.tmpdir()]);\n'
            "  }\n"
            '  const dest = path.join(__dirname, "tool");\n'
            '  fs.copyFileSync(path.join(os.tmpdir(), "tool"), dest);\n'
            "  fs.chmodSync(dest, 0o755);\n"
            "}\n"
            "function install() {\n"
            '  const archive = path.join(os.tmpdir(), "tool.tar.gz");\n'
            + "".join(f"  {step}\n" for step in install_steps)
            + f"{extra}"
            "}\n"
            "install();\n"
        )

    @staticmethod
    def scan(
        tmp_path: Path,
        script: str,
        *,
        checksums: bool = True,
        repository: str | None = "github:example-owner/example-tool",
    ) -> list[tuple[str, Severity]]:
        manifest = {
            "name": "example-tool",
            "version": "1.2.3",
            "scripts": {"postinstall": "node install.js"},
        }
        if repository is not None:
            manifest["repository"] = repository
        members = {
            "package/package.json": json.dumps(manifest).encode(),
            "package/install.js": script.encode(),
        }
        if checksums:
            members["package/checksums.txt"] = (b"0" * 64) + b"  example-tool.tar.gz\n"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "example-tool-1.2.3.tgz"
        target.write_bytes(buffer.getvalue())
        return [
            (f.rule_id, f.severity)
            for f in Scanner().scan(target).findings
            if f.rule_id in ("MALWARE.DROPPER.001", "SUSPECT.DROPPER.001")
        ]

    @staticmethod
    def blocked(found: list[tuple[str, Severity]]) -> bool:
        return any(rule == "MALWARE.DROPPER.001" for rule, _ in found)


class TestTheVerifiedShape:
    def test_is_lowered_and_still_reported(self, tmp_path: Path) -> None:
        found = VerifiedKit.scan(tmp_path, VerifiedKit.script())
        assert not VerifiedKit.blocked(found)
        # Never clean: the same span stays reported, below the gate.
        assert found
        assert all(rule == "SUSPECT.DROPPER.001" for rule, _ in found)
        assert all(severity <= Severity.MEDIUM for _, severity in found)

    def test_the_same_script_without_its_check_is_still_a_dropper(self, tmp_path: Path) -> None:
        # The control: the fixture is a dropper by pattern before the exemption is applied.
        script = VerifiedKit.script(check="function verify(file) {}\n")
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))


class TestConditionA:
    def test_a_host_that_is_not_a_release_host(self, tmp_path: Path) -> None:
        script = VerifiedKit.script("https://downloads.example.invalid/tool-${VERSION}.tar.gz")
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    def test_a_host_computed_at_runtime(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(
            "https://${HOST}/-/binary/example-tool/v${VERSION}/example-tool.tar.gz",
            prelude="const HOST = os.platform() + '.example.invalid';\n",
        )
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    def test_a_url_assembled_by_decoding(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(
            "${Buffer.from(PARTS, 'base64').toString()}",
            prelude="const PARTS = 'aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvdA==';\n",
        )
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    def test_a_paste_site(self, tmp_path: Path) -> None:
        assert VerifiedKit.blocked(
            VerifiedKit.scan(tmp_path, VerifiedKit.script("https://pastebin.com/raw/x"))
        )

    def test_a_raw_address(self, tmp_path: Path) -> None:
        script = VerifiedKit.script("https://203.0.113.9/tool-${VERSION}.tar.gz")
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))


class TestConditionB:
    def test_no_digest_compared(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(
            check=(
                "function verify(file) {\n"
                '  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");\n'
                "}\n"
            )
        )
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    def test_a_digest_downloaded_beside_the_asset(self, tmp_path: Path) -> None:
        # `pumperly-mcp` and `restflow-cli` fetch `checksums.txt` from the release they check.
        check = CHECK.replace(
            "function verify(file) {\n",
            "function verify(file) {\n"
            '  download(`${DOWNLOAD_URL}/../checksums.txt`, path.join(__dirname, "checksums.txt"));\n',
        )
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, VerifiedKit.script(check=check)))

    def test_a_digest_file_the_package_does_not_ship(self, tmp_path: Path) -> None:
        assert VerifiedKit.blocked(
            VerifiedKit.scan(tmp_path, VerifiedKit.script(), checksums=False)
        )

    def test_checked_after_it_has_run(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(verify_first=False)
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))


class TestConditionC:
    """The release on github.com has to be the package's own repository."""

    def test_unknown_repository_is_not_assumed(self, tmp_path: Path) -> None:
        # A manifest with no `repository`: the release cannot be shown to be the package's own,
        # so a github.com download keeps the finding.
        script = VerifiedKit.script(GITHUB)
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script, repository=None))

    def test_the_package_own_release_is_lowered_end_to_end(self, tmp_path: Path) -> None:
        assert not VerifiedKit.blocked(VerifiedKit.scan(tmp_path, VerifiedKit.script(GITHUB)))

    def test_someone_else_release_is_not_lowered_end_to_end(self, tmp_path: Path) -> None:
        found = VerifiedKit.scan(
            tmp_path, VerifiedKit.script(GITHUB), repository="github:someone-else/example-tool"
        )
        assert VerifiedKit.blocked(found)

    def test_the_package_own_repository(self) -> None:
        text = VerifiedKit.script(GITHUB)
        tree = frozenset({"p.tgz!package/checksums.txt", "p.tgz!package/install.js"})
        args = (text, "javascript", "p.tgz!package/install.js", [], tree)
        assert VerifiedDownload.verified(
            *args, "git+https://github.com/example-owner/example-tool.git"
        )
        assert VerifiedDownload.verified(*args, "github:Example-Owner/example-tool")

    def test_another_repository(self) -> None:
        text = VerifiedKit.script(GITHUB)
        tree = frozenset({"p.tgz!package/checksums.txt"})
        args = (text, "javascript", "p.tgz!package/install.js", [], tree)
        assert not VerifiedDownload.verified(*args, "https://github.com/someone-else/example-tool")
        assert not VerifiedDownload.verified(*args, None)

    def test_latest_is_not_a_pinned_release(self) -> None:
        text = VerifiedKit.script(
            "https://github.com/example-owner/example-tool/releases/latest/download/tool.tar.gz"
        )
        tree = frozenset({"p.tgz!package/checksums.txt"})
        assert not VerifiedDownload.verified(
            text, "javascript", "p.tgz!package/install.js", [], tree, "example-owner/example-tool"
        )


class TestTheRestOfTheFile:
    def test_a_credential_read_keeps_the_dropper(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(
            # Assembled here, so this test file does not itself read as a credential read.
            extra="  const rc = fs.readFileSync(path.join(os.homedir(), "
            + '"'
            + "."
            + "npmrc"
            + '"'
            + '), "utf8");\n'
        )
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    def test_a_body_sent_anywhere_keeps_the_dropper(self) -> None:
        text = VerifiedKit.script(
            extra='  execFileSync("curl", ["-d", "x", "https://registry.npmmirror.com/"]);\n'
        )
        tree = frozenset({"p.tgz!package/checksums.txt"})
        assert not VerifiedDownload.verified(
            text, "javascript", "p.tgz!package/install.js", [], tree, None
        )


class TestPython:
    SETUP = (
        "import hashlib, os, subprocess, urllib.request\n"
        'VERSION = "1.2.3"\n'
        'EXPECTED = "' + "a" * 64 + '"\n'
        "def fetch():\n"
        '    dest = "tool.tar.gz"\n'
        '    urllib.request.urlretrieve(f"https://nodejs.org/dist/v{VERSION}/tool.tar.gz", dest)\n'
        '    with open(dest, "rb") as handle:\n'
        "        if hashlib.sha256(handle.read()).hexdigest() != EXPECTED:\n"
        '            raise SystemExit("checksum mismatch")\n'
        '    subprocess.run(["tar", "-xzf", dest], check=True)\n'
        '    os.chmod("tool", 0o755)\n'
        "fetch()\n"
    )

    def test_hashlib_against_a_constant(self) -> None:
        assert VerifiedDownload.verified(self.SETUP, "python", "setup.py", [], frozenset(), None)

    def test_md5_is_not_a_verification(self) -> None:
        text = self.SETUP.replace("hashlib.sha256", "hashlib.md5")
        assert not VerifiedDownload.verified(text, "python", "setup.py", [], frozenset(), None)


#: esbuild's `install.js`, reduced: the platform package's tarball from the registry, the binary read
#: out of it, written beside the script, run once for its version (review 98 P2). Inert text.
REGISTRY_INSTALL = """const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const https = require("https");
const child_process = require("child_process");
const VERSION = "1.2.3";
const pkg = "@example/linux-x64";
function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location)
        return fetch(res.headers.location).then(resolve, reject);
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
    }).on("error", reject);
  });
}
function extract(buffer) {
  buffer = zlib.unzipSync(buffer);
  return buffer.subarray(512);
}
async function install() {
  const url = `https://registry.npmjs.org/${pkg}/-/${pkg.replace("@example/", "")}-${VERSION}.tgz`;
  const bin = path.join(__dirname, "tool");
  fs.writeFileSync(bin, extract(await fetch(url)), { mode: 0o755 });
  child_process.execFileSync(bin, ["--version"]);
}
install();
"""


class TestRegistryInstall:
    """A file whose every request is a registry tarball of a package the manifest declares installs
    that package as npm would: lowered like a verified release, never cleared."""

    @staticmethod
    def scan(tmp_path: Path, script: str, declared: dict[str, str]) -> list[tuple[str, Severity]]:
        manifest = {
            "name": "example-tool",
            "version": "1.2.3",
            "scripts": {"postinstall": "node install.js"},
            "optionalDependencies": declared,
        }
        members = {
            "package/package.json": json.dumps(manifest).encode(),
            "package/install.js": script.encode(),
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "example-tool-1.2.3.tgz"
        target.write_bytes(buffer.getvalue())
        return [
            (f.rule_id, f.severity)
            for f in Scanner().scan(target).findings
            if f.rule_id in ("MALWARE.DROPPER.001", "SUSPECT.DROPPER.001")
        ]

    @staticmethod
    def blocked(found: list[tuple[str, Severity]]) -> bool:
        return any(rule == "MALWARE.DROPPER.001" or sev >= Severity.HIGH for rule, sev in found)

    def test_a_declared_platform_package_is_lowered_and_still_reported(
        self, tmp_path: Path
    ) -> None:
        found = self.scan(tmp_path, REGISTRY_INSTALL, {"@example/linux-x64": "1.2.3"})
        assert found
        assert not self.blocked(found)

    def test_a_tarball_the_manifest_does_not_declare_keeps_the_block(self, tmp_path: Path) -> None:
        # The registry used as a CDN: any published package's tarball, fetched and run.
        found = self.scan(tmp_path, REGISTRY_INSTALL, {"@other/linux-x64": "1.2.3"})
        assert self.blocked(found)

    def test_one_request_elsewhere_keeps_the_block(self, tmp_path: Path) -> None:
        script = REGISTRY_INSTALL.replace(
            "install();\n", 'https.get("https://example.invalid/x");\ninstall();\n'
        )
        found = self.scan(tmp_path, script, {"@example/linux-x64": "1.2.3"})
        assert self.blocked(found)

    def test_matched_by_name_or_by_the_scope_the_template_names(self) -> None:
        declared = frozenset({"@example/linux-x64"})
        assert VerifiedDownload.registry_install(REGISTRY_INSTALL, "javascript", [], declared)
        assert not VerifiedDownload.registry_install(
            REGISTRY_INSTALL, "javascript", [], frozenset()
        )
        assert not VerifiedDownload.registry_install(
            REGISTRY_INSTALL, "javascript", [], frozenset({"example-unrelated"})
        )

    def test_the_url_pieces_never_match_a_declared_name(self) -> None:
        # The template's literal parts include '', '-', '.tgz', '/-/' and the host: none is a
        # package name or a scope, so a declared dependency the URL does not name stays blocked.
        unscoped = REGISTRY_INSTALL.replace('"@example/linux-x64"', '"tool-linux-x64"').replace(
            'pkg.replace("@example/", "")', "pkg"
        )
        assert not VerifiedDownload.registry_install(
            unscoped, "javascript", [], frozenset({"left-pad"})
        )
        # And a name that reaches the URL only through a variable is no literal part of it: the
        # match fails closed, and the block stays.
        assert not VerifiedDownload.registry_install(
            unscoped, "javascript", [], frozenset({"tool-linux-x64"})
        )


#: positron-stata's uv download, reduced: the asset URL chosen from literals for the platform and
#: returned in an object, fetched, written beside the extension and run (review 98 #28). Inert text.
OFFICIAL_INSTALL = """const fs = require("fs");
const path = require("path");
const child_process = require("child_process");
function asset(platform, arch) {
  const cpu = arch === "x64" ? "x86_64" : arch === "arm64" ? "aarch64" : void 0;
  if (!cpu) return void 0;
  const target = platform === "darwin" ? `${cpu}-apple-darwin` : `${cpu}-unknown-linux-gnu`;
  const ext = platform === "win32" ? "zip" : "tar.gz";
  return { target, ext, url: `https://github.com/astral-sh/uv/releases/latest/download/uv-${target}.${ext}` };
}
async function download(dir) {
  const found = asset(process.platform, process.arch);
  if (!found) throw new Error("no prebuilt uv");
  const response = await fetch(found.url);
  const archive = path.join(dir, `uv.${found.ext}`);
  fs.writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
  child_process.execFileSync(archive, ["--version"]);
}
exports.activate = (context) => download(context.globalStorageUri.fsPath);
"""


class TestOfficialInstall:
    """A file whose every request is a listed tool's own release binary, every string of the URL
    decided by literals in the file: lowered like a verified release, never cleared."""

    REMOTE_CODE = ("MALWARE.INSTALL.REMOTE_CODE.001", "SUSPECT.DROPPER.REMOTE_CODE.001")

    @classmethod
    def scan(cls, tmp_path: Path, script: str) -> list[tuple[str, Severity]]:
        import zipfile

        manifest = {
            "name": "tool",
            "publisher": "example",
            "version": "1.0.0",
            "engines": {"vscode": "^1.90.0"},
            "main": "./dist/extension.js",
        }
        target = tmp_path / "example.tool-1.0.0.vsix"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("extension.vsixmanifest", "<PackageManifest/>")
            archive.writestr("extension/package.json", json.dumps(manifest))
            archive.writestr("extension/dist/extension.js", script)
        return [
            (f.rule_id, f.severity)
            for f in Scanner().scan(target).findings
            if f.rule_id in cls.REMOTE_CODE
        ]

    @staticmethod
    def blocked(found: list[tuple[str, Severity]]) -> bool:
        return any(rule.startswith("MALWARE.") or sev >= Severity.HIGH for rule, sev in found)

    def test_a_pinned_uv_release_is_lowered_and_still_reported(self, tmp_path: Path) -> None:
        found = self.scan(tmp_path, OFFICIAL_INSTALL)
        assert found == [("SUSPECT.DROPPER.REMOTE_CODE.001", Severity.MEDIUM)]

    def test_another_owner_on_the_same_host_keeps_the_block(self, tmp_path: Path) -> None:
        script = OFFICIAL_INSTALL.replace("astral-sh/uv", "someone/uv")
        assert self.blocked(self.scan(tmp_path, script))

    def test_a_base_url_from_the_environment_keeps_the_block(self, tmp_path: Path) -> None:
        script = OFFICIAL_INSTALL.replace(
            "`https://github.com/astral-sh/uv/releases/latest/download/uv-",
            '(process.env.UV_MIRROR || "https://github.com/astral-sh/uv/releases/latest/download")'
            " + `/uv-",
        )
        assert self.blocked(self.scan(tmp_path, script))

    def test_a_segment_that_climbs_out_keeps_the_block(self, tmp_path: Path) -> None:
        script = OFFICIAL_INSTALL.replace(
            "uv-${target}", "${target}/../../../../o/r/releases/download/v1/x"
        )
        assert self.blocked(self.scan(tmp_path, script))

    def test_one_request_elsewhere_keeps_the_block(self, tmp_path: Path) -> None:
        script = OFFICIAL_INSTALL.replace(
            "exports.activate", 'fetch("https://example.invalid/beacon");\nexports.activate'
        )
        assert self.blocked(self.scan(tmp_path, script))

    def test_the_url_must_be_decided_in_the_file(self) -> None:
        # The asset's target handed in by a caller the file does not show: no value set, no
        # official request, the dropper keeps its grade.
        script = OFFICIAL_INSTALL.replace(
            "const found = asset(process.platform, process.arch);",
            "const found = { ext: 'zip', url: `https://github.com/astral-sh/uv/releases/download/${dir}` };",
        )
        assert not VerifiedDownload.official_install(script, "javascript", [])
        assert VerifiedDownload.official_install(OFFICIAL_INSTALL, "javascript", [])


class TestPinnedDownload:
    def test_a_listed_release_path(self) -> None:
        from cordon_scanner.intel.registries.installers import OfficialInstallers

        assert OfficialInstallers.pinned_download(
            "https://github.com/astral-sh/uv/releases/download/0.9.0/uv-x86_64-apple-darwin.tar.gz"
        )

    def test_what_is_not_pinned(self) -> None:
        from cordon_scanner.intel.registries.installers import OfficialInstallers

        for url in (
            "http://github.com/astral-sh/uv/releases/download/0.9.0/uv.tar.gz",  # not https
            "https://github.com/someone/uv/releases/download/0.9.0/uv.tar.gz",  # another owner
            "https://github.com/astral-sh/uv/releases/download/../../../o/r/x",  # climbs out
            "https://github.com/astral-sh/uv/releases/download/%2e%2e/x",  # escaped
            "https://github.com/astral-sh/uv/releases/download/x\\..\\y",  # backslash
            "https://github.com:443@evil.example/astral-sh/uv/releases/download/x",  # user part
            "https://deno.land/x/anyone/mod.ts",  # a listed host with no path pinned
            "https://astral.sh/uv/install.sh",  # a script installer, not a release binary
        ):
            assert not OfficialInstallers.pinned_download(url), url
