"""What keeps a private registry's credential on the path it was named for: no traversal out of the registry's base, no
fail-open when a reader moves to another thread, the checksum database on its own path, a file address taken from a
document checked against the file hosts, and the scheme of the credential stated by the operator."""

from __future__ import annotations

import contextlib
import io
import threading
import urllib.error
from email.message import Message
from typing import Any

import pytest

from cordon_scanner.intel.registries.private_registries import PrivateRegistries, PrivateRegistry
from cordon_scanner.intel.registries.private_route import PrivateRoute, Route
from cordon_scanner.intel.registries.registry_client import PackageNotFound, RegistryError

TOKEN = "s3cr3t-registry-token-value"
REGISTRY = PrivateRegistry("https://registry.acme.example/artifacts", "ACME_TOKEN")


class Routes:
    @staticmethod
    def make(**origins: str) -> Route:
        return Route(
            REGISTRY.base,
            REGISTRY.host,
            f"Bearer {TOKEN}",
            {
                "https://registry.npmjs.org": "",
                **{k.replace("_", "."): v for k, v in origins.items()},
            },
            "ACME_TOKEN",
        )


class TestTheRewrittenPathStaysUnderTheBase:
    @pytest.mark.parametrize(
        "rest",
        [
            "/../../../admin",
            "/a/../../admin",
            "/%2e%2e/x",
            "/%2E%2E/x",
            "/%2E%2E/",
            "/./x",
            "//x",
            "/a//x",
            "/a\\x",
            "/a%5cx",
            "/a%0ax",
            "/a\x00x",
            "/%2e%2e%2fx",
            "/a/..;x/b",
            "/..;/",
            "/%2e%2e;/x",
            "/;x/y",
            "/%252e%252e/x",
            "/a%2525b",
        ],
    )
    def test_a_name_that_climbs_out_is_refused(self, rest: str) -> None:
        with PrivateRoute.use(Routes.make()), pytest.raises(RegistryError):
            PrivateRoute.apply(f"https://registry.npmjs.org{rest}")

    @pytest.mark.parametrize("rest", ["/../x", "/%2e%2e/x", "//x", "/a\\x"])
    def test_an_address_already_under_the_base_is_held_to_the_same(self, rest: str) -> None:
        with PrivateRoute.use(Routes.make()), pytest.raises(RegistryError):
            PrivateRoute.apply(f"{REGISTRY.base}{rest}")

    @pytest.mark.parametrize(
        "rest",
        [
            "/left-pad",
            "/@acme%2fwidget",
            "/simple/requests/",
            "/api/v1/crates/serde/1.0.0",
            "/x?y=1&z=a/../b",
            "",
        ],
    )
    def test_an_ordinary_name_is_rewritten_under_the_base(self, rest: str) -> None:
        with PrivateRoute.use(Routes.make()):
            url, headers = PrivateRoute.apply(f"https://registry.npmjs.org{rest}")
        assert url == REGISTRY.base + rest and url.startswith(REGISTRY.base)
        assert headers == {"Authorization": f"Bearer {TOKEN}"}


class TestARouteDoesNotLeakAcrossThreads:
    def test_the_route_is_restored_after_an_exception(self) -> None:
        with pytest.raises(RuntimeError), PrivateRoute.use(Routes.make()):
            raise RuntimeError("boom")
        assert PrivateRoute.current() is None

    def test_a_nested_route_is_restored_to_the_outer_one(self) -> None:
        outer, inner = Routes.make(), Routes.make()
        with PrivateRoute.use(outer):
            with PrivateRoute.use(inner):
                assert PrivateRoute.current() is inner
            assert PrivateRoute.current() is outer
        assert PrivateRoute.current() is None

    @pytest.mark.parametrize("ecosystem", sorted(PrivateRegistries.supported()))
    def test_no_reader_starts_a_thread_while_a_route_is_set(self, ecosystem, monkeypatch) -> None:
        """A reader that handed work to another thread would ask the public registry, with no route, about a private
        package name. Starting a thread inside a private question is a failure, whatever the reader is."""
        started: list[str] = []

        def refuse(self, *args, **kwargs):
            started.append(self.name)
            raise AssertionError("a thread was started while a private route was set")

        monkeypatch.setattr(threading.Thread, "start", refuse)
        monkeypatch.setenv("ACME_TOKEN", TOKEN)
        monkeypatch.setattr("urllib.request.build_opener", _Silent.opener)
        name = {"image": f"{REGISTRY.host}/acme/widget"}.get(ecosystem, "widget")
        with contextlib.suppress(PackageNotFound, RegistryError, ValueError):
            PrivateRegistries.facts(REGISTRY, ecosystem, name, "1.0.0", source=REGISTRY.base)
        assert started == []


class _Silent:
    @staticmethod
    def opener(*handlers: Any):
        class Opener:
            def open(self, request, timeout: float = 0):
                raise urllib.error.HTTPError(request.full_url, 404, "x", Message(), io.BytesIO(b""))

        return Opener()


class TestTheChecksumDatabaseHasItsOwnPath:
    def test_a_go_route_sends_the_sumdb_to_its_own_path_under_the_base(self) -> None:
        built = PrivateRegistries.route(REGISTRY, "gomod", TOKEN)
        with PrivateRoute.use(built):
            module, _ = PrivateRoute.apply("https://proxy.golang.org/github.com/x/y/@v/list")
            sumdb, _ = PrivateRoute.apply("https://sum.golang.org/lookup/github.com/x/y@v1.0.0")
        assert module == f"{REGISTRY.base}/github.com/x/y/@v/list"
        assert sumdb == f"{REGISTRY.base}/sumdb/sum.golang.org/lookup/github.com/x/y@v1.0.0"


class TestAnAddressInADocumentIsCheckedAgainstTheFileHosts:
    def test_a_checksum_address_on_another_host_is_not_fetched(self, monkeypatch) -> None:
        from cordon_scanner.intel.registries.readers.open_vsx import ExtensionRegistries

        asked: list[str] = []

        class Opener:
            def open(self, request, timeout: float = 0):
                asked.append(request.full_url)
                body = {
                    "https://open-vsx.org/api/acme/theme": b'{"allVersions": {"1.0.0": "u"}}',
                    "https://open-vsx.org/api/acme/theme/1.0.0": b'{"files": {"sha256": "https://evil.example/x"}}',
                }.get(request.full_url)
                if body is None:
                    raise urllib.error.HTTPError(
                        request.full_url, 404, "x", Message(), io.BytesIO(b"")
                    )
                response = io.BytesIO(body)
                response.headers = Message()  # type: ignore[attr-defined]
                response.__enter__ = lambda: response  # type: ignore[method-assign,assignment]
                response.__exit__ = lambda *exc: None  # type: ignore[method-assign,assignment]
                return response

        monkeypatch.setattr("urllib.request.build_opener", lambda *h: Opener())
        with pytest.raises(RegistryError):
            ExtensionRegistries.vscode("acme.theme", "1.0.0")
        assert not any("evil" in url for url in asked)


class TestTheSchemeOfTheCredentialIsTheOperators:
    def test_a_scheme_may_be_stated_before_the_variable(self) -> None:
        parsed = PrivateRegistries.parse(
            ["https://a.example=bearer:A_TOKEN, https://b.example=basic:B_TOKEN"]
        )
        assert [(r.variable, r.scheme) for r in parsed] == [
            ("A_TOKEN", "bearer"),
            ("B_TOKEN", "basic"),
        ]

    def test_a_bearer_token_with_a_colon_is_sent_as_bearer_when_the_operator_says_so(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", "ghp:abc")
        stated = PrivateRegistry(REGISTRY.base, "ACME_TOKEN", "bearer")
        assert PrivateRegistries.route(stated, "cargo", "ghp:abc").authorization == "Bearer ghp:abc"

    def test_basic_is_sent_as_basic_and_an_unstated_scheme_keeps_the_colon_rule(self) -> None:
        stated = PrivateRegistry(REGISTRY.base, "ACME_TOKEN", "basic")
        assert PrivateRegistries.route(stated, "cargo", "u:p").authorization.startswith("Basic ")
        assert PrivateRegistries.route(REGISTRY, "cargo", "u:p").authorization.startswith("Basic ")
        assert PrivateRegistries.route(REGISTRY, "cargo", "plain").authorization == "Bearer plain"

    @pytest.mark.parametrize(
        "value",
        ["https://a.example=digest:A_TOKEN", "https://a.example=basic:", "https://a.example=:A"],
    )
    def test_any_other_scheme_is_refused_without_repeating_the_value(self, value: str) -> None:
        with pytest.raises(ValueError):
            PrivateRegistries.parse([value])


class TestAWorkerPoolStartedUnderARouteIsCaught:
    def test_a_thread_pool_submit_starts_a_thread_and_the_guard_sees_it(self, monkeypatch) -> None:
        """`ThreadPoolExecutor` makes its workers through `Thread.start`, so the guard the per-reader test uses covers a pool: the
        submit below fails the way a reader that handed its question to a pool would."""
        from concurrent.futures import ThreadPoolExecutor

        def refuse(self, *args, **kwargs):
            raise AssertionError("a thread was started while a private route was set")

        monkeypatch.setattr(threading.Thread, "start", refuse)
        with (
            PrivateRoute.use(Routes.make()),
            ThreadPoolExecutor(max_workers=1) as pool,
            pytest.raises(AssertionError),
        ):
            pool.submit(PrivateRoute.apply, "https://registry.npmjs.org/left-pad")

    def test_a_thread_that_does_run_has_no_route_and_so_cannot_be_given_the_credential(
        self,
    ) -> None:
        seen: list[tuple[str, dict[str, str]]] = []
        with PrivateRoute.use(Routes.make()):
            worker = threading.Thread(
                target=lambda: seen.append(PrivateRoute.apply("https://registry.npmjs.org/x"))
            )
            worker.start()
            worker.join()
        assert seen == [("https://registry.npmjs.org/x", {})], (
            "no credential reaches a thread the route was not set in"
        )
