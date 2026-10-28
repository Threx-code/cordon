"""The rules the binary detector declares: what each reports, at what severity, and what to do.

The detector id they carry is named here, once: the detector reads it from here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)

if TYPE_CHECKING:
    pass

#: The id every binary finding carries.
DETECTOR: Final = "binary"

DECLARED_RULES: tuple[DeclaredRule, ...] = (
    DeclaredRule(
        id="POLICY.BINARY.COMMITTED.001",
        title="Executable committed to a source repository",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        # Policy, not suspicion, and deliberately quiet. Vendored native
        # libraries, prebuilt test fixtures and checked-in tools are
        # ordinary in a great many repositories, and calling each of
        # them suspicious is how a reader learns to skip this detector's
        # output entirely. What is worth saying is that the artefact is
        # here and its contents are not derivable from anything in the
        # tree -- which is a visibility statement, not an accusation.
        category=Category.POLICY,
        detector=DETECTOR,
        message=(
            "An executable is committed where source belongs. Nobody reviews a binary "
            "in a diff, so whatever it does entered the repository unread and stays "
            "unread on every clone."
        ),
        references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
        remediation=(
            "Build the artefact rather than committing it, so what it "
            "contains is derivable from source that can be reviewed."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.EXECUTABLE_PATH.001",
        title="Executable committed where a lifecycle step will run it",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "A committed executable sits on a path a build or install step reaches, so "
            "it is not merely present -- something runs it. That is the difference "
            "between a binary nobody reads and a binary nobody reads that executes."
        ),
        references=(
            references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
            references.UNTRUSTED_SEARCH_PATH,
        ),
        remediation=(
            "Remove it. A binary in a scripts or hook directory runs without ever being read."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.PACKED.001",
        title="Committed binary is packed",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "A committed binary carries a packer signature. Packing compresses or "
            "encrypts the real program so that it exists only once the outer one has "
            "run, which defeats both a reviewer and static inspection of the file."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation=(
            "Confirm this project ships a packed artefact. Packing is "
            "ordinary for installers and is also how a payload avoids "
            "having readable strings."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.STRINGS.001",
        title="Committed binary contains a URL, command or credential path",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "Readable strings inside a committed binary name a network destination, a "
            "shell command or a path to a credential store. The strings are what the "
            "binary was built with, and they say something about what it reaches for."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation=(
            "Read what the binary reaches for. A committed artefact that "
            "names a host and a shell is doing something at runtime that "
            "no source in this repository describes."
        ),
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.PROCESS_INJECTION.001",
        title="Committed binary imports process-injection calls",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "It imports the calls that write code into another process and start it there (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, ptrace and their kin). Debuggers do this; almost nothing committed to a source repository should."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation="Find out what this binary is and why it injects into other processes. If nobody can say, remove it.",
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.CREDENTIAL_THEFT.001",
        title="Committed binary imports credential-store and network calls",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "It imports the calls that decrypt saved credentials or read the keychain (CryptUnprotectData, CredEnumerate, SecKeychainFind*) and the calls that reach the network. Together that is the shape of a password stealer."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation="Remove it, and treat credentials on machines that ran it as disclosed.",
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.KEYLOGGER.001",
        title="Committed binary imports keyboard-capture and network calls",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "It imports calls that observe keystrokes system-wide (SetWindowsHookEx, GetAsyncKeyState, CGEventTapCreate) and calls that reach the network."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation="Confirm what it is. Input capture beside networking is what a keylogger needs.",
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.IMPLANT.001",
        title="Committed binary imports download-and-run calls",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "It imports calls that download a file and run it (URLDownloadToFile with ShellExecute or CreateProcess), or networking and process creation alongside anti-debugging checks. That is a dropper's import table."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation="Remove it and find out how it entered the repository.",
    ),
    DeclaredRule(
        id="SUSPECT.BINARY.HIDDEN_IMPORTS.001",
        title="Committed binary resolves its imports at run time",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "It imports almost nothing except the loader's own lookup (dlopen/dlsym, LoadLibrary/GetProcAddress), so what it calls is decided at run time and named nowhere a reader can see."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation="Confirm what it loads. Hiding the import table is how a payload keeps its intentions out of static inspection.",
    ),
    DeclaredRule(
        id="SUSPECT.POLYGLOT.MISMATCH.001",
        title="File contents do not match its extension",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        detector=DETECTOR,
        message=(
            "The bytes at the start of this file identify a different format from the "
            "one its name claims. A file that is read by one tool according to its "
            "extension and by another according to its content is two different files."
        ),
        references=(references.OBSCURED_SECURITY_DATA,),
        remediation=(
            "Rename the file to match what it is, or remove it. A file "
            "whose name and content disagree is arranged so that the thing "
            "inspecting it and the thing opening it reach different "
            "conclusions."
        ),
    ),
)

__all__ = ["DECLARED_RULES", "DETECTOR"]
