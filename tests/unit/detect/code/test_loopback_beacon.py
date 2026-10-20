"""A daemon's health check on loopback is not a beacon (review 98, FP-3)."""

from __future__ import annotations

from cordon_scanner.detect.code.capability import CapabilityDetector


class TestLoopbackOnly:
    def test_a_health_check_on_its_own_port(self) -> None:
        region = b"http.get({ hostname: '127.0.0.1', port: DEFAULT_PORT, path: '/api/health' })"
        assert CapabilityDetector._loopback_only(region)

    def test_a_url_on_localhost(self) -> None:
        assert CapabilityDetector._loopback_only(b"fetch('http://localhost:7070/status')")

    def test_loopback_beside_another_host_is_not(self) -> None:
        region = b"http.get('http://127.0.0.1:1/x'); https.request('https://collect.example.io/k')"
        assert not CapabilityDetector._loopback_only(region)

    def test_a_raw_address_is_not(self) -> None:
        assert not CapabilityDetector._loopback_only(
            b"net.connect(4444, '203.0.113.9'); host='localhost'"
        )

    def test_no_destination_is_not(self) -> None:
        assert not CapabilityDetector._loopback_only(b"os.hostname(); request(opts)")
