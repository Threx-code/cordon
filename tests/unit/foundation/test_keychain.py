"""The sign-in credential kept by the operating system's store: the secret reaches a tool only on its standard input,
a file from an older sign-in moves into the keychain, signing out clears both, and with no keychain the file stays."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cordon_scanner.cloud import auth
from cordon_scanner.foundation.secrets.keychain import (
    MacKeychain,
    SecretService,
    SystemKeychain,
    WindowsCredentials,
)


class FakeTool:
    """A credential tool that keeps what it is given, and records every call it gets."""

    def __init__(self, base64_secrets: bool) -> None:
        self.calls: list[tuple[list[str], bytes]] = []
        self.kept: dict[tuple[str, str], str] = {}
        self.base64 = base64_secrets

    def mac(self, argv, stdin: bytes) -> tuple[int, bytes]:
        self.calls.append((list(argv), stdin))
        if argv[1] == "-i":
            words = stdin.decode().split('"')
            self.kept[(words[1], words[3])] = base64.b64decode(words[5]).decode()
            return 0, b""
        key = (argv[argv.index("-s") + 1], argv[argv.index("-a") + 1])
        if argv[1] == "find-generic-password":
            found = self.kept.get(key)
            return (0, base64.b64encode(found.encode()) + b"\n") if found else (44, b"")
        return (0, b"") if self.kept.pop(key, None) is not None else (44, b"")

    def linux(self, argv, stdin: bytes) -> tuple[int, bytes]:
        self.calls.append((list(argv), stdin))
        key = (argv[argv.index("service") + 1], argv[argv.index("account") + 1])
        if argv[1] == "store":
            self.kept[key] = stdin.decode()
            return 0, b""
        if argv[1] == "lookup":
            found = self.kept.get(key)
            return (0, found.encode()) if found else (1, b"")
        return (0, b"") if self.kept.pop(key, None) is not None else (1, b"")


SECRET = '{"access_token": "at-1", "note": "quotes \\" and \\n newlines"}'


class TestTheSecretNeverOnACommandLine:
    @pytest.mark.parametrize("kind", ["mac", "linux"])
    def test_a_written_secret_reads_back_and_no_argument_holds_it(self, kind: str) -> None:
        tool = FakeTool(base64_secrets=kind == "mac")
        store = MacKeychain(tool.mac) if kind == "mac" else SecretService(tool.linux, environ={})
        assert store.write("cordon-scanner", "/home/a/.config/cordon", SECRET)
        assert store.read("cordon-scanner", "/home/a/.config/cordon") == SECRET
        for argv, _ in tool.calls:
            assert all("at-1" not in arg for arg in argv), argv
        assert store.delete("cordon-scanner", "/home/a/.config/cordon")
        assert store.read("cordon-scanner", "/home/a/.config/cordon") is None
        assert not store.delete("cordon-scanner", "/home/a/.config/cordon")

    def test_a_keychain_answer_that_is_not_base64_is_no_secret(self) -> None:
        store = MacKeychain(lambda argv, stdin: (0, b"not base64 !!"))
        assert store.read("s", "a") is None

    def test_a_tool_that_fails_writes_nothing(self) -> None:
        assert not MacKeychain(lambda argv, stdin: (1, b"")).write("s", "a", "x")
        assert not SecretService(lambda argv, stdin: (1, b""), environ={}).write("s", "a", "x")


class TestWhichStoreIsThere:
    def test_the_secret_service_needs_a_session_bus(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        assert not SecretService(environ={}).available()
        assert SecretService(environ={"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/bus"}).available()

    def test_each_store_answers_only_on_its_own_system(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("sys.platform", "darwin")
        assert MacKeychain().available() and not WindowsCredentials().available()
        monkeypatch.setattr("sys.platform", "win32")
        assert WindowsCredentials().available() and not MacKeychain().available()

    def test_none_is_found_where_none_is_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "sunos5")
        assert SystemKeychain.found() is None


class TestSigningInWithAKeychain:
    @pytest.fixture
    def keychain(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeTool:
        tool = FakeTool(base64_secrets=False)
        monkeypatch.setenv("CORDON_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.delenv("CORDON_CREDENTIAL_STORE", raising=False)
        monkeypatch.setattr(
            auth.CloudAuth, "keychain", staticmethod(lambda: SecretService(tool.linux, environ={}))
        )
        return tool

    @staticmethod
    def credentials() -> auth.Credentials:
        return auth.Credentials(
            url="https://api.example", org="acme", access_token="at-1", expires_at=9e9
        )

    def test_a_sign_in_is_kept_in_the_keychain_and_not_on_disk(self, keychain: FakeTool) -> None:
        assert auth.CloudAuth.save(self.credentials()) == "the system keychain"
        assert not (auth.CloudAuth.config_dir() / auth.CREDENTIALS_NAME).exists()
        assert auth.CloudAuth.load().access_token == "at-1"

    def test_an_older_file_moves_into_the_keychain(self, keychain: FakeTool) -> None:
        path = auth.CloudAuth.config_dir() / auth.CREDENTIALS_NAME
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({**self.credentials().__dict__}), encoding="utf-8")
        assert auth.CloudAuth.load().access_token == "at-1"
        assert not path.exists() and keychain.kept

    def test_signing_out_clears_the_keychain(self, keychain: FakeTool) -> None:
        auth.CloudAuth.save(self.credentials())
        assert auth.CloudAuth.forget() and auth.CloudAuth.load() is None
        assert not auth.CloudAuth.forget()

    def test_the_file_is_kept_when_asked_for(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("CORDON_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setenv("CORDON_CREDENTIAL_STORE", "file")
        assert auth.CloudAuth.keychain() is None
        assert auth.CloudAuth.save(self.credentials()).endswith("(mode 0600)")

    def test_a_keychain_that_refuses_the_write_leaves_the_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("CORDON_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setattr(
            auth.CloudAuth,
            "keychain",
            staticmethod(lambda: SecretService(lambda argv, stdin: (1, b""), environ={})),
        )
        assert auth.CloudAuth.save(self.credentials()).endswith("(mode 0600)")
        assert auth.CloudAuth.load().access_token == "at-1"
