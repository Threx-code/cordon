"""One secret in the operating system's credential store: the macOS Keychain, the freedesktop Secret Service
(GNOME Keyring, KWallet) on Linux, the Windows Credential Manager.

A file with mode 0600 keeps other users out, but every program the same user runs can read it, and it travels into
backups, disk images and synced home folders. The system store is locked with the user's session and kept out of all
of those. Nothing here adds a dependency: macOS's `security` and Linux's `secret-tool` are the systems' own tools, and
Windows is reached through `ctypes`. The secret never appears on a command line, where any process may read it: it
is written to the tool's standard input.

Each store answers `available()` first; where none is (a server with no session bus, a container, CI), the caller
keeps its file, so signing in never fails for want of a keychain.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from typing import Any, ClassVar, Protocol

#: Runs a tool: (argv, standard input) -> (exit code, standard output). Swapped in tests.
Run = Callable[[Sequence[str], bytes], tuple[int, bytes]]


class SecretStore(Protocol):
    def available(self) -> bool: ...
    def read(self, service: str, account: str) -> str | None: ...
    def write(self, service: str, account: str, secret: str) -> bool: ...
    def delete(self, service: str, account: str) -> bool: ...


class Tools:
    TIMEOUT: ClassVar[float] = 20.0

    @staticmethod
    def run(argv: Sequence[str], stdin: bytes) -> tuple[int, bytes]:
        try:
            done = subprocess.run(  # noqa: S603 - a fixed system tool, arguments never from input
                list(argv), input=stdin, capture_output=True, timeout=Tools.TIMEOUT, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return 1, b""
        return done.returncode, done.stdout


class MacKeychain:
    """The login keychain through `security`. A write goes through `security -i`, which reads its command from
    standard input, so the secret (base64, so no quoting can break the line) is never an argument."""

    TOOL: ClassVar[str] = "/usr/bin/security"

    def __init__(self, run: Run = Tools.run) -> None:
        self._run = run

    def available(self) -> bool:
        return sys.platform == "darwin" and shutil.which(self.TOOL) is not None

    def read(self, service: str, account: str) -> str | None:
        code, out = self._run(
            [self.TOOL, "find-generic-password", "-s", service, "-a", account, "-w"], b""
        )
        if code != 0:
            return None
        try:
            return base64.b64decode(out.strip(), validate=True).decode("utf-8")
        except ValueError:
            return None

    def write(self, service: str, account: str, secret: str) -> bool:
        encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        line = f'add-generic-password -U -s "{service}" -a "{account}" -w "{encoded}"\n'
        code, _ = self._run([self.TOOL, "-i"], line.encode("ascii"))
        return code == 0 and self.read(service, account) == secret

    def delete(self, service: str, account: str) -> bool:
        code, _ = self._run(
            [self.TOOL, "delete-generic-password", "-s", service, "-a", account], b""
        )
        return code == 0


class SecretService:
    """The freedesktop Secret Service through `secret-tool`, which reads the secret to store from standard input.
    Available only with a session bus to reach it."""

    TOOL: ClassVar[str] = "secret-tool"

    def __init__(self, run: Run = Tools.run, environ: dict[str, str] | None = None) -> None:
        import os

        self._run = run
        self._environ = os.environ if environ is None else environ

    def available(self) -> bool:
        return (
            sys.platform.startswith("linux")
            and bool(self._environ.get("DBUS_SESSION_BUS_ADDRESS"))
            and shutil.which(self.TOOL) is not None
        )

    def read(self, service: str, account: str) -> str | None:
        code, out = self._run([self.TOOL, "lookup", "service", service, "account", account], b"")
        return out.decode("utf-8") if code == 0 and out else None

    def write(self, service: str, account: str, secret: str) -> bool:
        argv = [self.TOOL, "store", f"--label={service}", "service", service, "account", account]
        code, _ = self._run(argv, secret.encode("utf-8"))
        return code == 0 and self.read(service, account) == secret

    def delete(self, service: str, account: str) -> bool:
        code, _ = self._run([self.TOOL, "clear", "service", service, "account", account], b"")
        return code == 0


class WindowsCredentials:
    """The Windows Credential Manager through `advapi32`'s CredRead/CredWrite/CredDelete, a generic credential
    named `service/account`."""

    GENERIC: ClassVar[int] = 1
    LOCAL_MACHINE: ClassVar[int] = 2

    def available(self) -> bool:
        return sys.platform == "win32"

    def read(
        self, service: str, account: str
    ) -> str | None:  # pragma: no cover - only Windows runs this
        import ctypes

        api = WindowsCredentials._api()
        pointer = ctypes.c_void_p()
        if not api.CredReadW(f"{service}/{account}", self.GENERIC, 0, ctypes.byref(pointer)):
            return None
        try:
            cred = ctypes.cast(pointer, ctypes.POINTER(WindowsCredentials._struct())).contents
            raw = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
            return raw.decode("utf-8")
        finally:
            api.CredFree(pointer)

    def write(
        self, service: str, account: str, secret: str
    ) -> bool:  # pragma: no cover - only Windows runs this
        import ctypes

        blob = secret.encode("utf-8")
        buffer = ctypes.create_string_buffer(blob, len(blob))
        cred = WindowsCredentials._struct()()
        cred.Type = self.GENERIC
        cred.TargetName = f"{service}/{account}"
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ctypes.cast(buffer, ctypes.c_void_p)
        cred.Persist = self.LOCAL_MACHINE
        cred.UserName = account
        ok = bool(WindowsCredentials._api().CredWriteW(ctypes.byref(cred), 0))
        return ok and self.read(service, account) == secret

    def delete(
        self, service: str, account: str
    ) -> bool:  # pragma: no cover - only Windows runs this
        return bool(WindowsCredentials._api().CredDeleteW(f"{service}/{account}", self.GENERIC, 0))

    @staticmethod
    def _api() -> Any:  # pragma: no cover - only Windows runs this
        import ctypes

        return ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]

    @staticmethod
    def _struct() -> Any:  # pragma: no cover - only Windows runs this
        import ctypes
        from ctypes import wintypes

        class Credential(ctypes.Structure):
            _fields_: ClassVar = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.c_void_p),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        return Credential


class SystemKeychain:
    """The store this system has, or None: the first of them that is available here."""

    STORES: ClassVar[tuple[Callable[[], SecretStore], ...]] = (
        MacKeychain,
        SecretService,
        WindowsCredentials,
    )

    @staticmethod
    def found() -> SecretStore | None:
        for make in SystemKeychain.STORES:
            store = make()
            if store.available():
                return store
        return None


__all__ = [
    "MacKeychain",
    "SecretService",
    "SecretStore",
    "SystemKeychain",
    "Tools",
    "WindowsCredentials",
]
