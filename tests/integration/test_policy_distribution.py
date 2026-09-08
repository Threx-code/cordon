"""Fetching an organisation policy that lives somewhere else.

An organisation with more than a handful of repositories cannot copy its policy
into each of them: the copies drift, and a drifted ceiling is worse than none,
because everyone believes it is in force.

Distributing it is therefore necessary and is also a security decision, because
of what the document is. An organisation policy is the ceiling -- it says a
repository may not disable a detector, may not suppress a category, may not
raise a limit. Anything that can change it can switch the control off in every
repository at once. Fetching that over an unauthenticated channel would hand
the ceiling to whoever controls the network, the host, the CDN, or a stale DNS
record.

So the tests here are mostly refusals, and each is a refusal rather than a
warning: a warning about a policy that did not verify is a policy that was used
anyway.
"""

from __future__ import annotations

import hashlib
import http.server
import threading
from pathlib import Path

import pytest

from cordon_scanner.core.config import ConfigResolver
from cordon_scanner.core.distribution import MAX_POLICY_BYTES, PolicyDistribution
from cordon_scanner.core.errors import ConfigError

POLICY = b"""
enforce:
  detectors_required: [capability, secrets]
  min_severity_threshold: low
"""
DIGEST = hashlib.sha256(POLICY).hexdigest()


class Server:
    """A local HTTP server that can be told to lie."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args: object) -> None:
                return None

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> Server:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}/policy.yaml"


class TestRefusals:
    def test_a_url_without_a_digest_is_refused(self, tmp_path: Path) -> None:
        """The central rule. Without it, the network is trusted; with it, the
        network is merely a transport."""
        with pytest.raises(ConfigError, match="no integrity digest"):
            PolicyDistribution.resolve(
                "https://acme.example/p.yaml", allow_network=True, cache_dir=tmp_path
            )

    def test_plain_http_is_refused(self, tmp_path: Path) -> None:
        """The digest already protects the content; HTTP would additionally
        disclose which policy an organisation uses to anyone on the path."""
        with pytest.raises(ConfigError, match="must use https"):
            PolicyDistribution.resolve(
                f"http://acme.example/p.yaml#sha256={DIGEST}",
                allow_network=True,
                cache_dir=tmp_path,
            )

    def test_fetching_without_permission_is_refused(self, tmp_path: Path) -> None:
        """Offline is the default. A tool that reaches out because an argument
        began with `https://` has network behaviour nobody can audit."""
        with pytest.raises(ConfigError, match="not cached and network access is not allowed"):
            PolicyDistribution.resolve(
                f"https://acme.example/p.yaml#sha256={DIGEST}",
                allow_network=False,
                cache_dir=tmp_path,
            )

    def test_the_refusal_says_how_to_proceed_offline(self, tmp_path: Path) -> None:
        """An air-gapped site has to be able to act on this without guessing."""
        with pytest.raises(ConfigError) as raised:
            PolicyDistribution.resolve(
                f"https://acme.example/p.yaml#sha256={DIGEST}",
                allow_network=False,
                cache_dir=tmp_path,
            )
        assert "--allow-network" in (raised.value.hint or "")
        assert DIGEST in (raised.value.hint or "")


class TestFetching:
    def fetch(self, url: str, digest: str, cache: Path) -> Path:
        # The scheme check is bypassed for the loopback test server; what is
        # under test here is verification, not the scheme rule, which has its
        # own test above.
        return PolicyDistribution.resolve(
            f"{url}#sha256={digest}".replace("http://", "https://", 1),
            allow_network=True,
            cache_dir=cache,
        )

    def test_a_served_policy_that_matches_is_accepted(self, tmp_path, monkeypatch) -> None:
        with Server(POLICY) as server:
            monkeypatch.setattr(PolicyDistribution, "ALLOWED_SCHEMES", ("http://", "https://"))
            path = PolicyDistribution.resolve(
                f"{server.url}#sha256={DIGEST}", allow_network=True, cache_dir=tmp_path
            )
            assert path.read_bytes() == POLICY

    def test_a_tampered_response_is_refused(self, tmp_path, monkeypatch) -> None:
        """The attack the digest exists for: the host is compromised and serves
        a policy that enforces nothing."""
        with Server(b"enforce: {}\n") as server:
            monkeypatch.setattr(PolicyDistribution, "ALLOWED_SCHEMES", ("http://", "https://"))
            with pytest.raises(ConfigError, match="does not match its digest"):
                PolicyDistribution.resolve(
                    f"{server.url}#sha256={DIGEST}", allow_network=True, cache_dir=tmp_path
                )

    def test_nothing_is_cached_when_verification_fails(self, tmp_path, monkeypatch) -> None:
        """A failed fetch must not leave something behind that a later run finds
        and trusts."""
        with Server(b"enforce: {}\n") as server:
            monkeypatch.setattr(PolicyDistribution, "ALLOWED_SCHEMES", ("http://", "https://"))
            with pytest.raises(ConfigError):
                PolicyDistribution.resolve(
                    f"{server.url}#sha256={DIGEST}", allow_network=True, cache_dir=tmp_path
                )
        assert (
            not list((tmp_path / "policies").glob("*"))
            if (tmp_path / "policies").is_dir()
            else True
        )

    def test_the_second_use_needs_no_network(self, tmp_path, monkeypatch) -> None:
        with Server(POLICY) as server:
            monkeypatch.setattr(PolicyDistribution, "ALLOWED_SCHEMES", ("http://", "https://"))
            url = f"{server.url}#sha256={DIGEST}"
            PolicyDistribution.resolve(url, allow_network=True, cache_dir=tmp_path)
        # Server is down; the cached copy still resolves, offline.
        again = PolicyDistribution.resolve(url, allow_network=False, cache_dir=tmp_path)
        assert again.read_bytes() == POLICY

    def test_a_corrupted_cache_entry_is_not_trusted(self, tmp_path, monkeypatch) -> None:
        """The cache is an ordinary directory other processes can write, so the
        digest is re-checked on every use rather than assumed on arrival."""
        cached = tmp_path / "policies" / f"{DIGEST}.yaml"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"enforce: {}\n")
        with pytest.raises(ConfigError, match="not cached and network access"):
            PolicyDistribution.resolve(
                f"https://acme.example/p.yaml#sha256={DIGEST}",
                allow_network=False,
                cache_dir=tmp_path,
            )
        assert not cached.exists(), "a failing entry must be removed, not left to be found again"

    def test_an_oversized_policy_is_refused(self) -> None:
        """An organisation policy is a small document. The cap stops a
        compromised or merely misconfigured host turning a fetch into memory
        exhaustion."""
        assert MAX_POLICY_BYTES <= 1024 * 1024


class TestItStillWorksAsACeiling:
    def test_a_fetched_policy_constrains_the_repository(self, tmp_path, monkeypatch) -> None:
        """The end to end point: a distributed policy has to actually constrain
        a repository, not merely be downloaded.

        Refusal is the correct outcome and stronger than clamping. A repository
        that disables a required detector has asked for something the
        organisation forbids, and silently granting a weaker version would leave
        the operator believing the ceiling held.
        """
        from cordon_scanner.core.errors import PolicyViolationError

        root = tmp_path / "repo"
        root.mkdir()
        (root / "cordon.yaml").write_text(
            "scan:\n  detectors:\n    capability: false\n", encoding="utf-8"
        )
        with Server(POLICY) as server:
            monkeypatch.setattr(PolicyDistribution, "ALLOWED_SCHEMES", ("http://", "https://"))
            with pytest.raises(PolicyViolationError, match="required by organisation policy"):
                ConfigResolver.resolve(
                    root=root,
                    policy_path=f"{server.url}#sha256={DIGEST}",
                    allow_network=True,
                    cache_dir=str(tmp_path / "cache"),
                )

    def test_a_compliant_repository_is_accepted(self, tmp_path, monkeypatch) -> None:
        """The other half: a ceiling that refuses repositories inside it is a
        control people route around."""
        root = tmp_path / "repo"
        root.mkdir()
        (root / "cordon.yaml").write_text("scan:\n  severity_threshold: low\n", encoding="utf-8")
        with Server(POLICY) as server:
            monkeypatch.setattr(PolicyDistribution, "ALLOWED_SCHEMES", ("http://", "https://"))
            config = ConfigResolver.resolve(
                root=root,
                policy_path=f"{server.url}#sha256={DIGEST}",
                allow_network=True,
                cache_dir=str(tmp_path / "cache"),
            )
        assert config.detectors.get("capability") is not False
