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


@pytest.fixture
def clamd():
    fake = FakeClamd()
    yield fake
    fake.close()


def _scan(tmp_path, socket_path):
    return Scanner(Config.default().with_overrides(use_cache=False, clamav=socket_path)).scan(
        tmp_path
    )


class TestTheProtocol:
    def test_version_and_a_clean_stream(self, clamd) -> None:
        assert clamav.version(clamd.path).startswith("ClamAV 1.4.1")
        assert clamav.scan_bytes(clamd.path, b"x" * (clamav.CHUNK * 2 + 7)) is None
        assert len(clamd.streams[-1]) == clamav.CHUNK * 2 + 7, "every byte arrived, across chunks"

    def test_a_signature_is_named(self, clamd) -> None:
        assert clamav.scan_bytes(clamd.path, b"prefix " + MARKER) == "Cordon.Test.Marker"

    def test_only_a_loopback_tcp_address_is_contacted(self) -> None:
        with pytest.raises(clamav.ClamdError, match="loopback"):
            clamav.connect("tcp://10.0.0.5:3310")


class TestInAScan:
    def test_off_by_default(self, tmp_path, clamd) -> None:
        (tmp_path / "a.txt").write_bytes(MARKER)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not [f for f in result.findings if f.detector == "clamav"]
        assert clamd.streams == []

    def test_it_reports_that_it_ran_and_what_it_found(self, tmp_path, clamd) -> None:
        (tmp_path / "a.txt").write_bytes(b"hello " + MARKER)
        (tmp_path / "b.txt").write_bytes(b"ordinary\n")
        result = _scan(tmp_path, clamd.path)
        rules = {f.rule_id: f for f in result.findings if f.detector == "clamav"}
        assert "ClamAV 1.4.1" in rules["OPERATIONAL.CLAMAV.STATUS"].message
        hit = rules["MALWARE.CLAMAV.SIGNATURE.001"]
        assert hit.location.path == "a.txt" and "Cordon.Test.Marker" in hit.message
        assert result.complete

    def test_an_unreachable_daemon_makes_the_scan_incomplete(self, tmp_path) -> None:
        (tmp_path / "a.txt").write_bytes(b"x")
        result = _scan(tmp_path, str(tmp_path / "no-such.sock"))
        assert "OPERATIONAL.CLAMAV.UNAVAILABLE" in {f.rule_id for f in result.findings}
        assert not result.complete

    def test_a_repository_config_cannot_turn_it_on(self, tmp_path, clamd) -> None:
        from cordon_scanner.core.config import ConfigResolver

        (tmp_path / ".cordon.yml").write_text(
            f"version: 1\nscan:\n  clamav: {clamd.path}\n", encoding="utf-8"
        )
        with pytest.raises(Exception):  # noqa: B017 - unknown key, refused by the strict parser
            ConfigResolver.resolve(root=tmp_path)
