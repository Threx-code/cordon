"""Incremental scan cache.

The cache exists so a second scan of a mostly-unchanged repository is fast
enough to run on every commit. Speed is a security property here: a guard that
costs noticeably more than a second gets bypassed, and a bypassed guard protects
nothing.

The key covers everything that could change a finding: the file's content, the
rule pack, the configuration, the detector versions, and the file's *context* --
its path, its language, and whether it executes at install time.

Any rule change, configuration change or engine upgrade invalidates every entry.
That is the only safe behaviour, and it is worth being explicit about why: a
stale cached "clean" is a false negative, and a false negative is the one error
class this project treats as unacceptable. Being over-eager to invalidate costs
a slower scan; being under-eager costs a missed payload.

Context belongs in the key for the same reason. Identical code is suspicious in
an application module and malicious in an install hook, so a content-only key
returns findings computed for a different file. That is not a stale result, it
is a wrong one, and it can move in either direction.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import hmac
import inspect
import json
import os
import secrets
import sys
import sysconfig
import tempfile
import threading
import time
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cordon_scanner.engine.pipeline.constants import INCOMPLETE_WHEN_REPORTED
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import Finding
from cordon_scanner.foundation.paths import StatePaths
from cordon_scanner.version import SCHEMA_VERSION

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.config.settings import Config

CACHE_VERSION = 4
"""Bumped when the on-disk format changes.

Version 2 added the MAC. Entries written by version 1 carry no `mac` field and
are rejected by verification, which is the correct outcome: they are exactly as
trustworthy as an entry an attacker wrote.

Version 3 is about the findings rather than the envelope. Every finding now carries
the hash of the file it came from, which is what `ResultFolding.repeats` groups on,
and an entry written by version 2 has no such field -- so a warm cache would have
produced a report where some findings collapsed and some did not, according to which
files happened to be cached. A detector version cannot express that: the change is in
the engine, after the detectors have spoken.
"""

NOT_A_RESULT = INCOMPLETE_WHEN_REPORTED | {
    "OPERATIONAL.DETECTOR.FAILED",
    "OPERATIONAL.FILE.TIMEOUT",
    "OPERATIONAL.FILE.UNREADABLE",
}
"""Findings that say a file's checks did not all run, so its result is not one to keep. A worker
returns a detector's failure as a finding, cached before anything marks the scan incomplete."""

KEY_NAME = ".cordon-cache-key"
"""Per-machine HMAC key, created 0600 on first use.

Not a secret worth much on its own. Its job is to make a cache entry unforgeable
by anyone who cannot already write the user's files -- and anybody who can do
that can edit the source being scanned, at which point the cache is not the weak
link."""
DEFAULT_CACHE_DIRNAME = ".cordon-cache"

MAX_ENTRY_BYTES = 1 * 1024 * 1024
"""Cap on a single cached result.

A file producing megabytes of findings is pathological, and caching it would
turn one hostile input into a permanent disk-space problem. Such a result is
simply not cached; the scan still works, it is only not accelerated.
"""

MAX_ENTRY_AGE_DAYS = 30
"""How long an entry stays useful.

A file not scanned in a month is one whose content has almost certainly changed,
so the entry would miss anyway. Without eviction the cache grew without bound,
which on a shared CI volume is a slow disk-space failure nobody attributes to
the scanner."""


class Watch:
    """What inspecting one file reached past its own bytes, seen by an audit hook.

    A file's cached findings are only right while everything they came from is in the key. Some
    detectors read more than the file: an agent instruction file's chained file, an MCP server's
    installed copy, the repository's history through `git`, a registry over the network. None of
    that is in a key, and none of it can be -- so a file whose inspection reached any of it is
    not cached. Seen by `sys.addaudithook` rather than declared by each reader, so a reader added
    later is covered without anyone remembering to say so.

    Reached: a socket, a request or a resolver call; a process started; a file opened or a
    directory listed anywhere but the file itself, this package's own files (keyed by the package
    hash), the synced intelligence (keyed by its state) and the standard library. A file in the
    scanned tree is always reached, even where the tree lies inside one of those places.
    Unaudited (a `stat`) is not seen: what the tree holds is keyed by `tree_paths`.
    """

    NETWORK = frozenset(
        {
            "socket.connect",
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyaddr",
            "socket.sendto",
            "urllib.Request",
            "http.client.connect",
            "ftplib.connect",
            "smtplib.connect",
        }
    )
    PROCESS = frozenset(
        {
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.posix_spawn",
            "os.spawn",
            "os.fork",
            "os.forkpty",
            "os.startfile",
            "pty.spawn",
        }
    )
    LISTING = frozenset({"os.listdir", "os.scandir", "glob.glob"})

    current = threading.local()
    _installed = False
    _lock = threading.Lock()
    _allowed: tuple[str, ...] = ()

    def __init__(self, root: str | None, own: str) -> None:
        self.root = Watch.absolute(root) + os.sep if root else ""
        self.own = Watch.absolute(Path(root) / own) if root else ""
        self.reached = ""

    @staticmethod
    def absolute(path: Any) -> str:
        """`path` absolute and with `..` folded, lexically: `/package/../home` is not the package."""
        return os.path.normpath(Path(os.fsdecode(path)).absolute())

    @classmethod
    def install(cls) -> None:
        """Add the hook, once per process. An audit hook cannot be removed, so it does nothing
        while no file is being inspected on its thread."""
        with cls._lock:
            if cls._installed:
                return
            from cordon_scanner.foundation.paths import PackagePaths

            places = {str(PackagePaths.root()), str(StatePaths.synced_intel_dir())}
            for name in ("stdlib", "platstdlib"):
                with contextlib.suppress(KeyError):
                    places.add(sysconfig.get_paths()[name])
            cls._allowed = tuple(Watch.absolute(place) + os.sep for place in sorted(places))
            # The per-machine evidence key, loaded once per process on first use -- which was
            # inside the first file inspected, keeping that file out of the cache for a read
            # that is not about it. Loaded here instead, before anything is watched.
            from cordon_scanner.foundation.evidence_key import EvidenceKey

            EvidenceKey.key()
            sys.addaudithook(cls._audit)
            cls._installed = True

    @staticmethod
    def _audit(event: str, args: tuple[Any, ...]) -> None:
        watch: Watch | None = getattr(Watch.current, "watch", None)
        if watch is None or watch.reached:
            return
        # A hook that raises breaks the call it audits -- the open a detector made, inside a
        # scan. Nothing here may: what cannot be judged is counted as reached.
        try:
            Watch._judge(watch, event, args)
        except Exception:  # noqa: BLE001
            watch.reached = event

    @staticmethod
    def _judge(watch: Watch, event: str, args: tuple[Any, ...]) -> None:
        if event in Watch.NETWORK or event in Watch.PROCESS:
            watch.reached = event
        elif event == "open" or event in Watch.LISTING:
            target = args[0] if args else None
            if target is None or isinstance(target, int):
                return
            watch.place(event, target, args[1] if event == "open" and len(args) > 1 else None)

    def place(self, event: str, target: Any, mode: Any) -> None:
        """Whether opening or listing `target` is a read past the file."""
        path = Watch.absolute(target)
        if path == self.own and (mode is None or not any(c in str(mode) for c in "wax+")):
            return
        if self.root and (path + os.sep).startswith(self.root):
            self.reached = f"{event} in the tree"
            return
        writing = isinstance(mode, str) and any(c in mode for c in "wax+")
        if not writing and any((path + os.sep).startswith(place) for place in Watch._allowed):
            return
        self.reached = f"{event} outside the package"


@dataclass(frozen=True, slots=True)
class CacheKey:
    """Everything that determines a file's findings.

    Content alone is not enough, and getting that wrong is the sharpest failure
    this cache can have. A finding depends on its *context* as well as its
    bytes: identical code is suspicious in an application module and malicious
    in an install hook, and a finding records the path it was found at. Keying
    on content alone therefore returns findings computed for a different file,
    which can promote an ordinary module to a malware finding or, worse, demote
    a real one.

    So the key includes the path, the install-time context and the language.
    That costs a cache miss on a rename, which is the correct trade: a rename
    changes every finding's location anyway, so the cached result would have
    been wrong to reuse.
    """

    content_hash: str
    rulepack_hash: str
    config_hash: str
    detector_signature: str
    path: str = ""
    in_install_hook: bool = False
    language: str = ""

    def digest(self) -> str:
        payload = "\x00".join(
            (
                str(CACHE_VERSION),
                str(SCHEMA_VERSION),
                self.content_hash,
                self.rulepack_hash,
                self.config_hash,
                self.detector_signature,
                self.path,
                "hook" if self.in_install_hook else "plain",
                self.language,
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CacheSignature:
    """What a cached result depends on, so that a change to any of it misses the cache: the
    detectors and their source, the installed package, the scan's context, the intelligence
    state and the rule file. Pure functions of those; the store that keys by them is
    `ScanCache`."""

    @staticmethod
    def detector_signature(detectors: Sequence[Any]) -> str:
        """Identity of the detector set, so changing one invalidates the cache.

        Sorted, because the set is what matters and not the order it was discovered
        in. Without this, upgrading a detector would silently reuse results produced
        by the previous version of it.

        Each detector contributes its declared `version` AND a hash of the module
        it is defined in. The declared version alone was the whole identity, and
        that made cache correctness depend on a person remembering to edit a
        string in the same commit as the behaviour change. 0.1.1 came one line
        from shipping a false-positive fix that would have reached nobody who had
        ever run a scan: content, rule pack and configuration were all unchanged,
        so every affected entry would have been served from the cache.

        A declared version is still worth having -- it is what a report, a
        release note and a rule pack's `requires` clause can name, and a code
        hash is not a thing anyone can reason about. It is just no longer the
        thing correctness rests on.

        The cost is deliberate and is the right way round. Editing a docstring in
        a detector module now invalidates that detector's entries, and a
        needless re-scan costs seconds; reusing a result the current code would
        not have produced is a wrong answer, and in this tool a wrong answer is
        usually a missed payload.
        """
        parts = sorted(CacheSignature._detector_identity(d) for d in detectors)
        # The package's own code as well: a detector's module is a small part of what decides its
        # findings, and the analysis it calls (the JavaScript and Python flow, the rule engine, the
        # decoders) lives elsewhere. Keyed on its own module alone, a release that fixed detection
        # there kept serving every warm cache the old findings, and the cache is on by default.
        parts.append(f"package@{CacheSignature._package_hash()}")
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    @functools.cache
    def _package_hash() -> str:
        """The identity of every file of the running package -- its code and the data it ships
        (catalogues, the verdict model, the rule packs) -- once per process.

        An installed wheel's: its `RECORD`, which holds every installed file's SHA-256, so the same
        release gives the same identity on every machine and a CI cache restored onto a fresh
        runner still hits. Used only when that `RECORD` lists this package's own modules and its
        files are the ones running: a source tree on `PYTHONPATH` in front of an installed copy
        must not borrow the copy's identity, and an editable install's `RECORD` lists only its
        loader. Anywhere else -- a source tree, an editable install, a snapshot -- each file's path,
        size and modification time: an edit moves it. Reading every byte instead cost 0.37 s of
        CPU per process (757 files, 35 MB), paid by every scan a measurement run starts."""
        from cordon_scanner.foundation.paths import PackagePaths
        from cordon_scanner.version import __version__

        root = PackagePaths.root()
        record = CacheSignature._wheel_record(root)
        if record is not None:
            return "wheel-" + hashlib.sha256(record).hexdigest()[:16]
        entries: list[str] = []
        pending = [(str(root), "")]
        while pending:
            directory, prefix = pending.pop()
            with contextlib.suppress(OSError), os.scandir(directory) as listing:
                for entry in listing:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name != "__pycache__":
                            pending.append((entry.path, f"{prefix}{entry.name}/"))
                    elif entry.is_file() and not entry.name.endswith(".pyc"):
                        stat = entry.stat()
                        entries.append(f"{prefix}{entry.name}:{stat.st_size}:{stat.st_mtime_ns};")
        if not entries:
            return f"nosource-{__version__}"
        return "tree-" + hashlib.sha256("".join(sorted(entries)).encode()).hexdigest()[:16]

    @staticmethod
    def _wheel_record(root: Path) -> bytes | None:
        """The installed wheel's `RECORD`, when it describes the package running from `root`."""
        from importlib import metadata

        try:
            distribution = metadata.distribution("cordon-scanner")
            record = distribution.read_text("RECORD")
            located = Path(str(distribution.locate_file("cordon_scanner/__init__.py")))
        except (metadata.PackageNotFoundError, OSError, ValueError):
            return None
        if not record or "cordon_scanner/engine/cache.py," not in record:
            return None
        if Watch.absolute(located) != Watch.absolute(root / "__init__.py"):
            return None
        return record.encode("utf-8")

    @staticmethod
    def scan_signature(detectors: Sequence[Any], ctx: ScanContext, config: Config) -> str:
        """Everything a file's cached findings depend on besides its own bytes, its path, its
        language, the rule pack and the configuration (the other parts of the key).

        The detector signature alone was this part of the key, and a file's findings depend on
        more than the code that produced them. On the scan context: whether the file is a
        published package's entry point, in its library closure, a skill's script, a consumer's
        install path -- unchanged bytes whose role changed were served the findings of the old
        role. On the synced intelligence: a feed refresh that condemned a release left every
        warm cache clearing its files. On the Python that parsed it, and on the contents of an
        operator's `--rule-file`, of which the configuration holds only whether one is set.

        Reads past the file itself are not here because they cannot be: a detector that reads
        another file of the tree, a socket or a subprocess makes its result depend on something
        no key names, and `watch` keeps such a result out of the cache instead.
        """
        digest = hashlib.sha256()
        for part in (
            CacheSignature.detector_signature(detectors),
            CacheSignature.context_digest(ctx),
            CacheSignature._intel_state(),
            CacheSignature._rule_file_digest(config),
            sys.version,
        ):
            digest.update(part.encode("utf-8") + b"\0")
        return digest.hexdigest()[:16]

    @staticmethod
    def context_digest(ctx: ScanContext) -> str:
        """A stable hash of the context's facts (`ScanContext.facts`). The repository's root is
        left out: it is where this run unpacked or found the tree, a temporary directory for an
        archive, and what is under it is the files' own business."""
        facts = ctx.facts()
        repository = facts.get("repository")
        if repository is not None and is_dataclass(repository):
            facts["repository"] = replace(cast("Any", repository), root="")
        digest = hashlib.sha256()
        CacheSignature._feed(digest, facts)
        return digest.hexdigest()[:16]

    @staticmethod
    def _feed(digest: Any, value: Any) -> None:
        """Feed `value` into `digest` canonically: sets sorted, dataclasses by field.

        Iterative, not recursive: a context carries parsed manifests, and their nesting is the
        scanned package's to choose. A value of a type this does not know is fed by its type and
        `repr`, which can only make two equal contexts hash apart -- a cache miss, never a
        wrong hit."""
        stack: list[Any] = [value]
        while stack:
            item = stack.pop()
            if item is None or isinstance(item, (bool, int, float, str, bytes)):
                digest.update(f"{type(item).__name__}:{item!r};".encode())
            elif isinstance(item, Enum):
                digest.update(f"enum:{type(item).__name__}.{item.name};".encode())
            elif isinstance(item, Path):
                digest.update(f"path:{item.as_posix()};".encode())
            elif isinstance(item, (frozenset, set)):
                members = sorted(CacheSignature._canonical(member) for member in item)
                digest.update(f"set:{len(members)}:".encode())
                for member in members:
                    digest.update(member.encode("utf-8") + b"\0")
            elif isinstance(item, (list, tuple)):
                digest.update(f"seq:{len(item)}:".encode())
                stack.extend(reversed(item))
            elif isinstance(item, dict):
                ordered = sorted(item.items(), key=lambda pair: CacheSignature._canonical(pair[0]))
                digest.update(f"map:{len(ordered)}:".encode())
                for key, member in reversed(ordered):
                    stack.append(member)
                    stack.append(key)
            elif is_dataclass(item) and not isinstance(item, type):
                names = [f.name for f in fields(item)]
                digest.update(f"obj:{type(item).__qualname__}:{len(names)}:".encode())
                for name in reversed(names):
                    stack.append(getattr(item, name))
                    stack.append(name)
            else:
                digest.update(f"other:{type(item).__qualname__}:{item!r};".encode())

    @staticmethod
    def _canonical(value: Any) -> str:
        """One set member or mapping key as a string to sort and hash by."""
        if isinstance(value, (str, int, float, bool, bytes)) or value is None:
            return f"{type(value).__name__}:{value!r}"
        digest = hashlib.sha256()
        CacheSignature._feed(digest, value)
        return digest.hexdigest()

    @staticmethod
    def _intel_state() -> str:
        """The synced intelligence as it stands on disk -- the advisory database, the feed's
        overlays and rules, the OS databases (`StatePaths.synced_intel_dir`) -- by each file's
        path, size and modification time. Every writer there replaces files whole, so a refresh
        moves this."""
        root = StatePaths.synced_intel_dir()
        digest = hashlib.sha256()
        with contextlib.suppress(OSError):
            for directory, dirnames, filenames in os.walk(root):
                dirnames.sort()
                for name in sorted(filenames):
                    path = Path(directory) / name
                    with contextlib.suppress(OSError):
                        stat = path.stat()
                        relative = path.relative_to(root).as_posix()
                        digest.update(f"{relative}:{stat.st_size}:{stat.st_mtime_ns};".encode())
        return digest.hexdigest()[:16]

    @staticmethod
    def _rule_file_digest(config: Config) -> str:
        """The contents of the operator's rule file, when one is set."""
        if not config.rule_file:
            return ""
        try:
            return hashlib.sha256(Path(config.rule_file).read_bytes()).hexdigest()[:16]
        except OSError:
            return "unreadable"

    @staticmethod
    def _detector_identity(detector: Any) -> str:
        """One detector's contribution to the signature: `id@version@code`."""
        version = getattr(detector, "version", "0")
        return f"{detector.id}@{version}@{CacheSignature._module_hash(type(detector).__module__)}"

    @staticmethod
    @functools.cache
    def _module_hash(module_name: str) -> str:
        """A hash of a module's source, or `"nosource"` when there is none.

        Cached per module name because the detector set is walked once per scan
        and several detectors may share a module; the source cannot change inside
        a process.

        Line endings are normalised before hashing. Without that, the same
        release produces two different signatures depending on whether the
        checkout used LF or CRLF, which costs a full cold scan every time a CI
        cache is restored onto a runner whose checkout differs from the one that
        saved it -- not wrong, but a cache that never hits is a cache nobody
        keeps paying for.

        Falling back rather than failing: a frozen or zipped build has no source
        to read, and refusing to scan would be a worse answer than reverting to
        the declared version, which is what shipped before this and is what the
        `id@version` half of the identity still provides. It is named in the
        signature rather than substituted silently, so two builds of the same
        release do not collide on one key.
        """
        module = sys.modules.get(module_name)
        source: str | None = None
        with contextlib.suppress(OSError, TypeError):
            if module is not None:
                source = inspect.getsource(module)
        if source is None:
            return "nosource"
        normalised = source.replace("\r\n", "\n").replace("\r", "\n")
        return hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]


class ScanCache:
    """A content-addressed store of per-file findings.

    Deliberately a plain directory of JSON files rather than a database. There
    is no schema to migrate, no lock to contend on, corruption is confined to a
    single entry, and the whole thing can be deleted with `rm -rf` by anyone
    debugging it. A cache that is hard to inspect is a cache people stop
    trusting, and an untrusted cache gets disabled.
    """

    @staticmethod
    def default_cache_dir() -> Path:
        """Where cache entries live (`StatePaths.default_cache_dir`)."""
        return StatePaths.default_cache_dir()

    @staticmethod
    def key_dir() -> Path:
        """Where the authentication key lives, which no variable moves (`StatePaths.key_dir`)."""
        return StatePaths.key_dir()

    @staticmethod
    def _home() -> Path:
        """The running user's home directory, from the account store (`StatePaths._home`)."""
        return StatePaths._home()

    @staticmethod
    @contextlib.contextmanager
    def watch(root: str | None, own: str) -> Iterator[Watch]:
        """Note anything inspecting one file reaches past its own bytes (`Watch`)."""
        Watch.install()
        watch = Watch(root, own)
        previous = getattr(Watch.current, "watch", None)
        Watch.current.watch = watch
        try:
            yield watch
        finally:
            Watch.current.watch = previous

    @staticmethod
    def finding_from_dict(data: dict[str, Any]) -> Finding:
        """Rebuild a finding from its serialised form.

        Reconstructed through the domain types rather than restored as a bare
        mapping, so a cached finding is indistinguishable from a freshly produced
        one everywhere downstream. That is what makes the equivalence test between a
        cold scan and a warm one meaningful.
        """
        from cordon_scanner.foundation.capabilities import Capability
        from cordon_scanner.foundation.models import (
            Category,
            Confidence,
            Evidence,
            EvidenceKind,
            Explanation,
            Location,
            RedactionMode,
            RiskFactor,
            RiskScore,
            Severity,
            Suppression,
        )

        location = Location(**data["location"])

        evidence_data = dict(data["evidence"])
        metadata = evidence_data.pop("metadata", {})
        span = evidence_data.pop("span", None)
        evidence = Evidence(
            kind=EvidenceKind(evidence_data["kind"]),
            match_hash=evidence_data["match_hash"],
            redaction=RedactionMode(evidence_data["redaction"]),
            snippet=evidence_data.get("snippet"),
            span=tuple(span) if span else None,
            metadata=tuple(sorted((str(k), str(v)) for k, v in metadata.items())),
        )

        risk_data = data["risk"]
        risk = RiskScore(
            value=risk_data["value"],
            base=risk_data["base"],
            confidence_multiplier=risk_data["confidence_multiplier"],
            factors=tuple(
                RiskFactor(f["name"], f["points"], f["reason"])
                for f in risk_data.get("factors", ())
            ),
        )

        explanation_data = data["explanation"]
        explanation = Explanation(
            summary=explanation_data["summary"],
            matched_rule=explanation_data["matched_rule"],
            contributing=tuple(explanation_data.get("contributing", ())),
            escalations=tuple(explanation_data.get("escalations", ())),
        )

        suppression = None
        if "suppressed" in data:
            suppression = Suppression(**data["suppressed"])

        return Finding(
            rule_id=data["rule_id"],
            category=Category(data["category"]),
            severity=Severity.parse(data["severity"]),
            confidence=Confidence.parse(data["confidence"]),
            message=data["message"],
            location=location,
            evidence=evidence,
            remediation=data["remediation"],
            explanation=explanation,
            risk=risk,
            detector=data["detector"],
            rule_version=data.get("rule_version", "0.0.0"),
            rulepack=data.get("rulepack", "cordon-builtin"),
            references=tuple(data.get("references", ())),
            related=tuple(data.get("related", ())),
            occurrences=data.get("occurrences", 1),
            suppressed=suppression,
            capabilities=tuple(Capability(c) for c in data.get("capabilities", ())),
            always_report=bool(data.get("always_report", False)),
            fingerprint=data.get("fingerprint", ""),
        )

    def __init__(self, directory: Path | str | None = None, *, enabled: bool = True) -> None:
        self.directory = Path(directory) if directory else self.default_cache_dir()
        self.enabled = enabled
        self.hits = 0
        self.misses = 0
        self._writable: bool | None = None
        self._key_material: bytes | None = None
        self.max_entry_age_days = MAX_ENTRY_AGE_DAYS

    # -- Lookup ----------------------------------------------------------

    def get(self, key: CacheKey) -> tuple[Finding, ...] | None:
        """Return cached findings, or None.

        Any problem reading an entry is a miss rather than an error. A corrupt
        cache must degrade to a slower scan, never to a failed one: the cache is
        an optimisation and must not be able to break the thing it accelerates.

        An entry whose MAC does not verify is treated the same way. Every input
        to the cache key is public or attacker-computable -- the content hash is
        of the attacker's own file, the rulepack hash and detector signature are
        fixed per release, and the config hash is derivable from published
        defaults -- so anyone who can write to the cache directory can compute
        the exact path for a file they are about to commit and leave
        `{"findings": []}` there. Without authentication that is a permanent,
        silent, total bypass for chosen files.
        """
        if not self.enabled:
            return None

        path = self._path(key)
        try:
            info = path.stat()
            # Bounded before reading. MAX_ENTRY_BYTES was enforced on write
            # only, so a planted multi-gigabyte entry was pulled entirely into
            # memory before anything verified it.
            if info.st_size > MAX_ENTRY_BYTES:
                self.misses += 1
                return None
            # Age checked on read, not only by the manual `prune` command. An
            # entry was otherwise valid indefinitely, which widens the window
            # for every attack against the cache: a forged or stale entry
            # planted once stayed authoritative until somebody happened to run
            # `prune`. The key already covers content, rules, config and
            # detectors, so expiry is a second bound rather than the first one.
            if (
                self.max_entry_age_days > 0
                and time.time() - info.st_mtime > self.max_entry_age_days * 86400
            ):
                self.misses += 1
                return None
            raw = path.read_bytes()
        except (OSError, ValueError):
            self.misses += 1
            return None

        try:
            payload = ScannedJson.loads(raw)
            if not self._verify(payload, key):
                # Not deleted. An unverified entry may belong to another user
                # sharing the directory, and removing it would turn a read
                # into a destructive act on somebody else's data.
                self.misses += 1
                return None
            findings = tuple(ScanCache.finding_from_dict(f) for f in payload["findings"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, RecursionError):
            # A corrupt entry is removed rather than left to fail repeatedly.
            path.unlink(missing_ok=True)
            self.misses += 1
            return None

        self.hits += 1
        return findings

    # -- Authentication --------------------------------------------------

    def _secret(self) -> bytes | None:
        """The per-machine key entries are authenticated with.

        Generated on first use, stored `0600` beside the cache. Its only job is
        to make an entry unforgeable by anyone who cannot already read the
        user's files -- at which point they can edit the source being scanned
        and the cache is not the weak link.

        Returns None when the key can neither be read nor created, and callers
        then treat every entry as a miss. Failing to a slower scan is correct;
        failing to an unauthenticated one is not.
        """
        if self._key_material is not None:
            return self._key_material or None

        path = self.key_dir() / KEY_NAME
        try:
            material = path.read_bytes()
            if len(material) >= 32 and self._key_is_private(path):
                self._key_material = material
                return material
            if len(material) >= 32:
                # Readable by somebody else, so it is not a secret. Replaced
                # rather than used: an attacker who can read the key can forge
                # an entry for a file they are about to commit, and every input
                # to the cache path is public, so they can compute exactly where
                # to put it. A restored CI cache artefact or a shared volume is
                # how a directory arrives with loose permissions.
                with contextlib.suppress(OSError):
                    path.unlink()
        except OSError:
            pass

        try:
            key_directory = self.key_dir()
            key_directory.mkdir(parents=True, exist_ok=True)
            # 0700 on the directory, so another user cannot read the key or
            # plant entries even if they can reach the path.
            with contextlib.suppress(OSError):
                key_directory.chmod(0o700)
            self.directory.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                self.directory.chmod(0o700)
            material = secrets.token_bytes(32)
            handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(handle, material)
            finally:
                os.close(handle)
            self._key_material = material
            return material
        except FileExistsError:
            # Another process created it between the read and the write.
            try:
                self._key_material = path.read_bytes()
                return self._key_material or None
            except OSError:
                self._key_material = b""
                return None
        except OSError:
            self._key_material = b""
            return None

    @staticmethod
    def _key_is_private(path: Path) -> bool:
        """Whether the key file is owned by this user and readable only by them.

        The MAC design was right and the read path did not check either, so a
        cache directory that already existed with looser permissions handed the
        key to anyone who could read it. `chmod(0o700)` ran only on the creation
        branch, which is exactly the branch that does not execute when the
        directory is already there.
        """
        if os.name == "nt":  # pragma: no cover - POSIX permissions only
            return True
        try:
            info = path.stat()
        except OSError:
            return False
        return info.st_uid == os.getuid() and not info.st_mode & 0o077

    def _mac(self, body: bytes, key: CacheKey) -> str | None:
        """MAC over the payload, the key it is filed under, and who owns it.

        Binding the cache key in stops an entry being valid at a different path:
        a genuine `{"findings": []}` for a benign file could otherwise be copied
        onto the cache path of a malicious one.

        Binding the identity in narrows what a stolen or planted key is worth. A
        key is only meaningful for the uid and the key path it was created for,
        so a key file copied out of one home directory does not authenticate
        entries read under another, and a shared cache volume restored into a
        different account does not silently accept the previous account's
        entries. `key_dir` is what stops the key being moved at all on POSIX;
        this is what limits the damage where that lookup is unavailable.
        """
        secret = self._secret()
        if secret is None:
            return None
        bound = b"|".join(
            (
                key.digest().encode("ascii"),
                str(self._identity()).encode("utf-8"),
                str(self.key_dir()).encode("utf-8"),
                body,
            )
        )
        return hmac.new(secret, bound, "sha256").hexdigest()

    @staticmethod
    def _identity() -> int:
        """The uid the cache belongs to, or -1 where there is no such concept."""
        getuid = getattr(os, "getuid", None)
        return int(getuid()) if getuid is not None else -1

    def _verify(self, payload: Any, key: CacheKey) -> bool:
        if not isinstance(payload, dict):
            return False
        recorded = payload.get("mac")
        body = payload.get("findings")
        if not isinstance(recorded, str) or body is None:
            return False
        expected = self._mac(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"), key
        )
        if expected is None:
            return False
        return hmac.compare_digest(expected, recorded)

    def put(self, key: CacheKey, findings: Sequence[Finding]) -> None:
        """Store findings for a key.

        Written atomically through a temporary file and a rename, so a
        concurrent reader never observes a half-written entry. Two scans running
        at once is normal -- a hook and an editor integration, or several CI
        jobs sharing a cache volume.
        """
        if not self.enabled or not self._ensure_writable():
            return
        # A result that says it is incomplete -- a detector failed, the file could not be read --
        # is not a fact about the file. Cached, a failure from one bad moment (memory, load) was
        # served for that content until the code changed.
        if any(f.rule_id in NOT_A_RESULT or f.degrades_coverage for f in findings):
            return

        body = [f.to_dict() for f in findings]
        mac = self._mac(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"), key
        )
        if mac is None:
            # No key material means entries cannot be authenticated, and an
            # unauthenticated entry is worse than none at all.
            return

        payload = json.dumps(
            {"version": CACHE_VERSION, "findings": body, "mac": mac},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        if len(payload) > MAX_ENTRY_BYTES:
            return

        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(handle, "wb") as out:
                    out.write(payload)
                Path(temporary).replace(path)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
        except OSError:
            # A read-only or full cache directory must not fail a scan.
            self._writable = False

    # -- Maintenance -----------------------------------------------------

    def prune(self, *, max_age_days: int = MAX_ENTRY_AGE_DAYS) -> int:
        """Remove entries older than `max_age_days`. Returns the count removed.

        The cache had `clear` and `size` and no eviction at all, so a long-lived
        CI cache volume accumulated up to a megabyte per unique
        (content, config, rulepack) tuple, indefinitely. Age rather than a size
        cap, because the useful entries are the recent ones: a file that has not
        been scanned in a month is one whose content has almost certainly
        changed.
        """
        if not self.directory.is_dir():
            return 0
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        for entry in self._entry_files():
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                # A cache that cannot be pruned is not a scan failure.
                continue
        return removed

    def _entry_files(self) -> Iterator[Path]:
        """Every cache entry, without following symlinked directories.

        `Path.rglob` descends into them on Python before 3.13, and both callers
        then `unlink()` what they find -- so a symlink planted in the cache
        directory turned maintenance into arbitrary deletion of `*.json`
        anywhere the user can write.
        """
        for parent, dirnames, filenames in os.walk(self.directory, followlinks=False):
            dirnames[:] = [d for d in dirnames if not Path(parent, d).is_symlink()]
            for name in filenames:
                candidate = Path(parent, name)
                if name.endswith(".json") and not candidate.is_symlink():
                    yield candidate

    def clear(self) -> int:
        removed = 0
        if not self.directory.is_dir():
            return 0
        for entry in self._entry_files():
            try:
                entry.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def size(self) -> tuple[int, int]:
        """Entry count and total bytes."""
        if not self.directory.is_dir():
            return 0, 0
        count = 0
        total = 0
        for entry in self.directory.rglob("*.json"):
            try:
                total += entry.stat().st_size
                count += 1
            except OSError:
                continue
        return count, total

    # -- Internals -------------------------------------------------------

    def _path(self, key: CacheKey) -> Path:
        digest = key.digest()
        # Two levels of fan-out. A single directory with a hundred thousand
        # entries is slow to enumerate on most filesystems and unpleasant to
        # inspect by hand.
        return self.directory / digest[:2] / digest[2:4] / f"{digest}.json"

    def _ensure_writable(self) -> bool:
        if self._writable is not None:
            return self._writable
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            probe = self.directory / ".write-probe"
            probe.write_bytes(b"")
            probe.unlink()
            self._writable = True
        except OSError:
            self._writable = False
        return self._writable


__all__ = [
    "CACHE_VERSION",
    "CacheKey",
    "ScanCache",
]
