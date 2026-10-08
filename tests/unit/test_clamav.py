"""The ClamAV hand-off, against an in-process clamd that speaks the INSTREAM protocol."""

from __future__ import annotations

import socket
import struct
import tempfile
import threading
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.detect import clamav

MARKER = b"cordon-clamav-test-marker"


class FakeClamd:
    """Answers VERSION and INSTREAM like clamd. Reports a signature when the marker is present."""

    def __init__(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="clamd-")
        self.path = str(Path(self.directory) / "clamd.sock")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen(16)
        self.streams: list[bytes] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            with connection:
                command = b""
                while not command.endswith(b"\x00"):
                    command += connection.recv(1)
                if command == b"zVERSION\x00":
                    connection.sendall(b"ClamAV 1.4.1/27400/Tue Sep 30 08:00:00 2026\x00")
                    continue
                data = b""
                while True:
                    header = b""
                    while len(header) < 4:
                        header += connection.recv(4 - len(header))
                    (length,) = struct.unpack(">I", header)
                    if length == 0:
                        break
                    piece = b""
                    while len(piece) < length:
                        piece += connection.recv(length - len(piece))
                    data += piece
                self.streams.append(data)
                answer = (
                    b"stream: Cordon.Test.Marker FOUND\x00" if MARKER in data else b"stream: OK\x00"
                )
                connection.sendall(answer)

    def close(self) -> None:
        self.server.close()


class ClamavFixtures:
    """Fixtures for the tests in test_clamav.py; every test class here inherits them."""

    @pytest.fixture
    def clamd(self):
        if not hasattr(socket, "AF_UNIX"):
            pytest.skip(
                "the fake daemon listens on a Unix socket, which this platform does not have"
            )
        fake = FakeClamd()
        yield fake
        fake.close()


class ClamavHelpers:
    """Helpers for test_clamav.py."""

    @staticmethod
    def _scan(tmp_path, socket_path):
        return Scanner(Config.default().with_overrides(use_cache=False, clamav=socket_path)).scan(
            tmp_path
        )


class TestTheProtocol(ClamavFixtures):
    def test_version_and_a_clean_stream(self, clamd) -> None:
        assert clamav.Clamd.version(clamd.path).startswith("ClamAV 1.4.1")
        assert clamav.Clamd.scan_bytes(clamd.path, b"x" * (clamav.CHUNK * 2 + 7)) is None
        assert len(clamd.streams[-1]) == clamav.CHUNK * 2 + 7, "every byte arrived, across chunks"

    def test_a_signature_is_named(self, clamd) -> None:
        assert clamav.Clamd.scan_bytes(clamd.path, b"prefix " + MARKER) == "Cordon.Test.Marker"

    def test_only_a_loopback_tcp_address_is_contacted(self) -> None:
        with pytest.raises(clamav.ClamdError, match="loopback"):
            clamav.Clamd.connect("tcp://10.0.0.5:3310")


class TestInAScan(ClamavFixtures):
    def test_off_by_default(self, tmp_path, clamd) -> None:
        (tmp_path / "a.txt").write_bytes(MARKER)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not [f for f in result.findings if f.detector == "clamav"]
        assert clamd.streams == []

    def test_it_reports_that_it_ran_and_what_it_found(self, tmp_path, clamd) -> None:
        (tmp_path / "a.txt").write_bytes(b"hello " + MARKER)
        (tmp_path / "b.txt").write_bytes(b"ordinary\n")
        result = ClamavHelpers._scan(tmp_path, clamd.path)
        rules = {f.rule_id: f for f in result.findings if f.detector == "clamav"}
        assert "ClamAV 1.4.1" in rules["OPERATIONAL.CLAMAV.STATUS"].message
        hit = rules["MALWARE.CLAMAV.SIGNATURE.001"]
        assert hit.location.path == "a.txt" and "Cordon.Test.Marker" in hit.message
        assert result.complete

    def test_an_unreachable_daemon_makes_the_scan_incomplete(self, tmp_path) -> None:
        (tmp_path / "a.txt").write_bytes(b"x")
        result = ClamavHelpers._scan(tmp_path, str(tmp_path / "no-such.sock"))
        assert "OPERATIONAL.CLAMAV.UNAVAILABLE" in {f.rule_id for f in result.findings}
        assert not result.complete

    def test_a_repository_config_cannot_turn_it_on(self, tmp_path, clamd) -> None:
        from cordon_scanner.core.config import ConfigResolver

        (tmp_path / ".cordon.yml").write_text(
            f"version: 1\nscan:\n  clamav: {clamd.path}\n", encoding="utf-8"
        )
        with pytest.raises(Exception):  # noqa: B017 - unknown key, refused by the strict parser
            ConfigResolver.resolve(root=tmp_path)


class TestWithWorkerProcesses(ClamavFixtures):
    """Worker processes rebuild their configuration from `to_dict()`, the repository schema, which
    leaves `clamav` out on purpose. So every worker ran the detector with no daemon address. Once
    a repository was big enough for two workers (about 520 files), ClamAV received nothing, the
    scan came back "clamd at  could not be reached", and a payload in it was not checked."""

    def test_workers_reach_the_daemon_and_find_the_marker(self, tmp_path, clamd) -> None:
        from cordon_scanner.core.parallel import ParallelScanner

        count = 1100
        assert ParallelScanner.worker_count(4, count) > 1, "the test must start real workers"
        for n in range(count):
            (tmp_path / f"f{n:04d}.txt").write_text(f"ordinary {n}\n", encoding="utf-8")
        (tmp_path / "zz-payload.txt").write_bytes(b"hello " + MARKER)
        config = Config.default().with_overrides(use_cache=False, clamav=clamd.path)
        config = config.with_overrides(limits=config.limits.merged(max_workers=4))
        result = Scanner(config).scan(tmp_path)
        rules = [f.rule_id for f in result.findings if f.detector == "clamav"]
        assert "OPERATIONAL.CLAMAV.UNAVAILABLE" not in rules
        assert "MALWARE.CLAMAV.SIGNATURE.001" in rules
        assert result.complete
