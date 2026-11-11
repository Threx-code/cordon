"""A worker's memory and CPU bounds where the kernel offers no rlimit for them (S8,
reviews/release-080/SECURITY-HARDENING.md).

Linux bounds a worker with RLIMIT_AS and RLIMIT_CPU (`supervisor.Limits`). macOS ignores RLIMIT_AS,
and Windows has no rlimits at all, so on both a file built to exhaust memory grew one worker until
the user's machine swapped or the scan was killed, and on Windows a unit's CPU was bounded only by
the wall backstop.

- **macOS, memory:** the parent reads each busy worker's physical footprint (`proc_pid_rusage`,
  the figure macOS itself acts on under memory pressure) between its waits, and ends a worker past
  its budget. That is the same outcome as RLIMIT_AS on Linux: the unit is run once more alone,
  then reported as `Reason.MEMORY`. The check is the parent's, not a thread in the worker: one
  allocation is a single C call holding the worker's interpreter lock, so a thread there would
  only run once the memory was already taken.
- **Windows, memory and CPU:** the worker puts itself in a Job Object whose per-process limits the
  kernel enforces. An allocation past the memory limit fails (MemoryError, the existing
  MEMORY_EXIT path), and a unit past its user-CPU budget is ended by the system with
  ERROR_NOT_ENOUGH_QUOTA, which the parent reads as `Reason.CPU`.

Standard library only (ctypes), as everything in the scanner is.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import sys
from typing import Any, ClassVar


class Footprint:
    """macOS: a process's physical footprint in bytes, or None where it cannot be read."""

    #: `RUSAGE_INFO_V2`: the first flavor whose struct carries `ri_phys_footprint`, at the offset
    #: read below. V0 has it too, but V2 is what every supported macOS release documents.
    FLAVOR: ClassVar[int] = 2
    #: How often the parent reads busy workers' footprints, in seconds.
    POLL: ClassVar[float] = 0.05

    class _RusageInfoV2(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [
            ("ri_uuid", ctypes.c_uint8 * 16),
            ("ri_user_time", ctypes.c_uint64),
            ("ri_system_time", ctypes.c_uint64),
            ("ri_pkg_idle_wkups", ctypes.c_uint64),
            ("ri_interrupt_wkups", ctypes.c_uint64),
            ("ri_pageins", ctypes.c_uint64),
            ("ri_wired_size", ctypes.c_uint64),
            ("ri_resident_size", ctypes.c_uint64),
            ("ri_phys_footprint", ctypes.c_uint64),
            ("ri_proc_start_abstime", ctypes.c_uint64),
            ("ri_proc_exit_abstime", ctypes.c_uint64),
            ("ri_child_user_time", ctypes.c_uint64),
            ("ri_child_system_time", ctypes.c_uint64),
            ("ri_child_pkg_idle_wkups", ctypes.c_uint64),
            ("ri_child_interrupt_wkups", ctypes.c_uint64),
            ("ri_child_pageins", ctypes.c_uint64),
            ("ri_child_elapsed_abstime", ctypes.c_uint64),
            ("ri_diskio_bytesread", ctypes.c_uint64),
            ("ri_diskio_byteswritten", ctypes.c_uint64),
        ]

    _libproc: ClassVar[Any] = None

    @staticmethod
    def available() -> bool:
        return sys.platform == "darwin" and Footprint._library() is not None

    @staticmethod
    def _library() -> Any:
        if Footprint._libproc is None and sys.platform == "darwin":
            with contextlib.suppress(OSError):
                Footprint._libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        return Footprint._libproc

    @staticmethod
    def of(pid: int) -> int | None:
        library = Footprint._library()
        if library is None:
            return None
        info = Footprint._RusageInfoV2()
        try:
            status = library.proc_pid_rusage(pid, Footprint.FLAVOR, ctypes.byref(info))
        except (OSError, AttributeError):
            return None
        return int(info.ri_phys_footprint) if status == 0 else None


class JobLimits:
    """Windows: this process placed in a Job Object with per-process memory and CPU limits."""

    JOB_OBJECT_LIMIT_PROCESS_TIME: ClassVar[int] = 0x00000002
    JOB_OBJECT_LIMIT_PROCESS_MEMORY: ClassVar[int] = 0x00000100
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: ClassVar[int] = 9
    #: The exit code the system gives a process it ended at the job's per-process time limit.
    ERROR_NOT_ENOUGH_QUOTA: ClassVar[int] = 1816

    class _Basic(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class _Io(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    _job: ClassVar[Any] = None
    _info: ClassVar[Any] = None

    _dlls: ClassVar[dict[str, Any]] = {}

    @classmethod
    def _kernel32(cls) -> Any:
        """kernel32 with every function this class calls declared. Undeclared, ctypes passes and
        returns a HANDLE as a 32-bit int: GetCurrentProcess's pseudo-handle (-1) comes back
        truncated, AssignProcessToJobObject then names no process, fails, and the worker runs
        with no limit at all (S8's Windows CI, 2026-11-10: a 2 GB allocation went through)."""
        if "kernel32" not in cls._dlls:
            dll = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            handle, dword, address = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p
            dll.GetCurrentProcess.restype, dll.GetCurrentProcess.argtypes = handle, []
            dll.CreateJobObjectW.restype = handle
            dll.CreateJobObjectW.argtypes = [address, ctypes.c_wchar_p]
            dll.SetInformationJobObject.restype = ctypes.c_int
            dll.SetInformationJobObject.argtypes = [handle, ctypes.c_int, address, dword]
            dll.AssignProcessToJobObject.restype = ctypes.c_int
            dll.AssignProcessToJobObject.argtypes = [handle, handle]
            dll.GetProcessTimes.restype = ctypes.c_int
            dll.GetProcessTimes.argtypes = [handle, address, address, address, address]
            cls._dlls["kernel32"] = dll
        return cls._dlls["kernel32"]

    @classmethod
    def _psapi(cls) -> Any:
        if "psapi" not in cls._dlls:
            dll = ctypes.WinDLL("psapi", use_last_error=True)  # type: ignore[attr-defined]
            dll.GetProcessMemoryInfo.restype = ctypes.c_int
            dll.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
            cls._dlls["psapi"] = dll
        return cls._dlls["psapi"]

    @classmethod
    def apply(cls, memory_bytes: int) -> bool:
        """This process into a fresh job, its committed memory capped at what it has now plus
        `memory_bytes`. True when the kernel holds the limit."""
        if os.name != "nt":  # os.name, not sys.platform: type-checked on every platform
            return False
        try:
            kernel32 = cls._kernel32()
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                return False
            info = ExtendedLimits()
            flags = 0
            if memory_bytes > 0:
                info.ProcessMemoryLimit = cls._committed() + memory_bytes
                flags |= cls.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.BasicLimitInformation.LimitFlags = flags
            if not kernel32.SetInformationJobObject(
                job,
                cls.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.addressof(info),
                ctypes.sizeof(info),
            ):
                return False
            if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
                return False
        except (OSError, AttributeError, ValueError):
            return False
        cls._job, cls._info = job, info
        return memory_bytes > 0

    @classmethod
    def held(cls) -> bool:
        """Whether this process is in the job this class made."""
        return cls._job is not None

    @classmethod
    def cpu_for_next(cls, budget: float) -> bool:
        """The job's per-process user-time limit set to the user time used so far plus `budget`."""
        if cls._job is None or cls._info is None:
            return False
        try:
            used = cls._user_time_100ns()
            cls._info.BasicLimitInformation.PerProcessUserTimeLimit = (
                used + int(budget * 10_000_000) + 10_000_000
            )
            cls._info.BasicLimitInformation.LimitFlags |= cls.JOB_OBJECT_LIMIT_PROCESS_TIME
            return bool(cls._set())
        except (OSError, AttributeError, ValueError):
            return False

    @classmethod
    def cpu_release(cls) -> None:
        """No CPU limit between units: an idle worker is never ended for the unit before."""
        if cls._job is None or cls._info is None:
            return
        with contextlib.suppress(OSError, AttributeError, ValueError):
            cls._info.BasicLimitInformation.LimitFlags &= ~cls.JOB_OBJECT_LIMIT_PROCESS_TIME
            cls._set()

    @classmethod
    def _set(cls) -> int:
        kernel32 = cls._kernel32()
        return int(
            kernel32.SetInformationJobObject(
                cls._job,
                cls.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.addressof(cls._info),
                ctypes.sizeof(cls._info),
            )
        )

    @classmethod
    def _user_time_100ns(cls) -> int:
        kernel32 = cls._kernel32()
        created, ended, kernel, user = (
            ctypes.c_uint64(),
            ctypes.c_uint64(),
            ctypes.c_uint64(),
            ctypes.c_uint64(),
        )
        kernel32.GetProcessTimes(
            kernel32.GetCurrentProcess(),
            ctypes.addressof(created),
            ctypes.addressof(ended),
            ctypes.addressof(kernel),
            ctypes.addressof(user),
        )
        return int(user.value)

    @staticmethod
    def _committed() -> int:
        """This process's committed (pagefile-backed) memory now, or 0 where unknown."""

        class Counters(ctypes.Structure):
            _fields_: ClassVar[list[tuple[str, Any]]] = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        try:
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            psapi = JobLimits._psapi()
            kernel32 = JobLimits._kernel32()
            if psapi.GetProcessMemoryInfo(
                kernel32.GetCurrentProcess(), ctypes.addressof(counters), counters.cb
            ):
                return int(counters.PagefileUsage)
        except (OSError, AttributeError):
            pass
        return 0


class ExtendedLimits(ctypes.Structure):
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""

    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("BasicLimitInformation", JobLimits._Basic),
        ("IoInfo", JobLimits._Io),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


__all__ = ["ExtendedLimits", "Footprint", "JobLimits"]
