"""Cordon's PEP 517 / PEP 660 build backend: the wheel, the sdist and the editable install, from
`pyproject.toml`, with the standard library alone.

Why not setuptools: a release is built from whatever the build backend runs, and a backend is
code from outside the project executing with the release's privileges. Cordon ships no third-party
code; this keeps it from building with any either. It does exactly what this project needs and no
more: Python packages under `src/`, package data by glob, the project's own C extensions compiled
with the platform compiler (`Native`), and the sdist by `MANIFEST.in`.

Reproducible: entries sorted, timestamps from `SOURCE_DATE_EPOCH` (else 1980-01-01), permissions
normalised, so the same tree builds the same bytes.
"""

from __future__ import annotations

import ast
import base64
import csv
import fnmatch
import gzip
import hashlib
import io
import os
import tarfile
import time
import tomllib
import zipfile
from pathlib import Path
from typing import Any, ClassVar


class Project:
    """What `pyproject.toml` says, and the files it makes up."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path.cwd()
        self.config = tomllib.loads((self.root / "pyproject.toml").read_text(encoding="utf-8"))
        self.project: dict[str, Any] = self.config["project"]
        self.build: dict[str, Any] = self.config.get("tool", {}).get("cordon-build", {})
        self.name = self.project["name"]
        self.dist = self.name.replace("-", "_")
        self.version = self._version()

    def _version(self) -> str:
        source = self.root / self.build["version-file"]
        for node in ast.parse(source.read_text(encoding="utf-8")).body:
            if (
                isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
                and isinstance(node.value, ast.Constant)
            ):
                return str(node.value.value)
        raise ValueError(f"no __version__ in {source}")

    # -- the wheel's files ----------------------------------------------------

    def packages(self) -> list[str]:
        """Every directory under each top-level package, `__init__.py` or not: namespace packages
        count, as they do for setuptools' `packages.find` in `pyproject.toml`."""
        src = self.root / self.build.get("source", "src")
        out = []
        for top in self.build["packages"]:
            stack = [src / top]
            while stack:
                here = stack.pop()
                out.append(here.relative_to(src).as_posix().replace("/", "."))
                stack.extend(
                    sorted(p for p in here.iterdir() if p.is_dir() and p.name != "__pycache__")
                )
        return sorted(out)

    def wheel_files(self) -> dict[str, Path]:
        """Archive name -> source file: every module, then package data and the files
        `MANIFEST.in` brings into a package (setuptools' `include-package-data`)."""
        src = self.root / self.build.get("source", "src")
        out: dict[str, Path] = {}
        packages = self.packages()
        for package in packages:
            folder = src / package.replace(".", "/")
            for path in folder.iterdir():
                if path.is_file() and path.suffix == ".py":
                    out[path.relative_to(src).as_posix()] = path
        for package, patterns in self.build.get("package-data", {}).items():
            folder = src / package.replace(".", "/")
            for pattern in patterns:
                for path in folder.glob(pattern):
                    if path.is_file() and not Manifest.excluded(path.name):
                        out[path.relative_to(src).as_posix()] = path
        package_dirs = {src / p.replace(".", "/") for p in packages}
        for rel in Manifest(self.root).files():
            path = self.root / rel
            if path.parent in package_dirs and not Manifest.excluded(path.name):
                out.setdefault(path.relative_to(src).as_posix(), path)
        excluded = tuple(e.rstrip("/") + "/" for e in self.build.get("exclude", []))
        return dict(sorted((k, v) for k, v in out.items() if not k.startswith(excluded)))

    # -- metadata -----------------------------------------------------------

    def metadata(self) -> str:
        """Core metadata 2.4 (PEP 639 licence fields), with the readme as the description."""
        p = self.project
        lines = ["Metadata-Version: 2.4", f"Name: {self.name}", f"Version: {self.version}"]
        if "description" in p:
            lines.append(f"Summary: {p['description']}")
        for field, key in (("Author-email", "authors"), ("Maintainer-email", "maintainers")):
            people = [f"{x['name']} <{x['email']}>" for x in p.get(key, []) if "email" in x]
            if people:
                lines.append(f"{field}: {', '.join(people)}")
        if isinstance(p.get("license"), str):
            lines.append(f"License-Expression: {p['license']}")
        for label, url in p.get("urls", {}).items():
            lines.append(f"Project-URL: {label}, {url}")
        if p.get("keywords"):
            lines.append(f"Keywords: {','.join(p['keywords'])}")
        lines += [f"Classifier: {c}" for c in p.get("classifiers", [])]
        if "requires-python" in p:
            lines.append(f"Requires-Python: {p['requires-python']}")
        lines += [f"Requires-Dist: {d}" for d in p.get("dependencies", [])]
        readme = p.get("readme")
        body = ""
        if isinstance(readme, str):
            kind = (
                "text/markdown"
                if readme.endswith(".md")
                else "text/x-rst"
                if readme.endswith(".rst")
                else "text/plain"
            )
            lines.append(f"Description-Content-Type: {kind}")
            body = (self.root / readme).read_text(encoding="utf-8")
        lines += [f"License-File: {f}" for f in self.license_files()]
        return "\n".join(lines) + "\n\n" + body

    def license_files(self) -> list[str]:
        out: list[str] = []
        for pattern in self.project.get("license-files", []):
            out += sorted(
                p.relative_to(self.root).as_posix() for p in self.root.glob(pattern) if p.is_file()
            )
        return out

    def entry_points(self) -> str:
        groups: dict[str, dict[str, str]] = {}
        if self.project.get("scripts"):
            groups["console_scripts"] = self.project["scripts"]
        if self.project.get("gui-scripts"):
            groups["gui_scripts"] = self.project["gui-scripts"]
        groups.update(self.project.get("entry-points", {}))
        out = []
        for group, items in groups.items():
            out.append(f"[{group}]")
            out += [f"{k} = {v}" for k, v in sorted(items.items())]
            out.append("")
        return "\n".join(out)


class Manifest:
    """The `MANIFEST.in` commands this project uses: include, recursive-include, global-exclude,
    prune -- as setuptools reads them, over the files under the project root."""

    ALWAYS_EXCLUDED: ClassVar[tuple[str, ...]] = ("__pycache__", "*.py[cod]", ".DS_Store")

    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def excluded(name: str) -> bool:
        return any(fnmatch.fnmatchcase(name, p) for p in Manifest.ALWAYS_EXCLUDED)

    def _all(self) -> list[str]:
        out = []
        for here, dirs, files in os.walk(self.root):
            rel_dir = Path(here).relative_to(self.root).as_posix()
            skip = {".git", "__pycache__"} | (
                {".venv", "build", "dist"} if rel_dir == "." else set()
            )
            dirs[:] = sorted(d for d in dirs if d not in skip)
            out += [f if rel_dir == "." else f"{rel_dir}/{f}" for f in files]
        return out

    def files(self) -> list[str]:
        everything = self._all()
        chosen: set[str] = set()
        path = self.root / "MANIFEST.in"
        lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
        for raw in lines:
            words = raw.split("#", 1)[0].split()
            if not words:
                continue
            command, args = words[0], words[1:]
            if command == "include":
                chosen |= {f for f in everything if any(fnmatch.fnmatchcase(f, a) for a in args)}
            elif command == "recursive-include":
                folder, patterns = args[0].rstrip("/"), args[1:]
                chosen |= {
                    f for f in everything
                    if f.startswith(folder + "/") and any(fnmatch.fnmatchcase(f.rsplit("/", 1)[-1], p) for p in patterns)
                }  # fmt: skip
            elif command == "global-exclude":
                chosen = {
                    f
                    for f in chosen
                    if not any(fnmatch.fnmatchcase(f.rsplit("/", 1)[-1], a) for a in args)
                }
            elif command == "prune":
                chosen = {
                    f
                    for f in chosen
                    if not any(f == a or f.startswith(a.rstrip("/") + "/") for a in args)
                }
            else:
                raise ValueError(f"MANIFEST.in: {command} is not supported by cordon_build")
        return sorted(f for f in chosen if not any(self.excluded(part) for part in f.split("/")))


class Archive:
    """Reproducible zip and tar writing."""

    @staticmethod
    def epoch() -> int:
        return int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))

    @staticmethod
    def record_line(name: str, data: bytes) -> list[str]:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        return [name, f"sha256={digest}", str(len(data))]

    @staticmethod
    def wheel(path: Path, entries: list[tuple[str, bytes]], record_name: str) -> None:
        stamp = time.gmtime(max(Archive.epoch(), 315532800))[:6]
        rows = [Archive.record_line(n, d) for n, d in entries] + [[record_name, "", ""]]
        text = io.StringIO()
        csv.writer(text, lineterminator="\n").writerows(rows)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in [*entries, (record_name, text.getvalue().encode())]:
                info = zipfile.ZipInfo(name, date_time=stamp)
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, data)

    @staticmethod
    def sdist(path: Path, prefix: str, entries: list[tuple[str, bytes]]) -> None:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
            for name, data in entries:
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size, info.mtime, info.mode = len(data), Archive.epoch(), 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tf.addfile(info, io.BytesIO(data))
        with (
            path.open("wb") as out,
            gzip.GzipFile(fileobj=out, mode="wb", mtime=Archive.epoch(), filename="") as gz,
        ):
            gz.write(raw.getvalue())


class Native:
    """The project's own C extensions (`[[tool.cordon-build.native]]`: a module name and its C
    sources), compiled with the interpreter's own compiler and linker (`sysconfig`) and the
    hardening flags below. Nothing is downloaded and nothing outside the standard library and the
    platform compiler runs.

    A wheel with an extension is tagged for this interpreter and platform. Every extension has a
    pure-Python twin that gives the same results, so the pure `py3-none-any` wheel is built, and the
    build says why on stderr, when `CORDON_BUILD_PURE=1`, when there is no compiler, or when the
    compile fails (a newer compiler's new warning under -Werror must not fail a user's install
    from the sdist). `CORDON_BUILD_NATIVE=require` makes the last two an error instead: CI sets it,
    so a release wheel that should be native cannot quietly come out pure.

    `CORDON_WHEEL_PLATFORM` sets the platform tag: CI sets `manylinux_2_28_x86_64` and the like
    inside the manylinux image, whose glibc is what that tag promises. On macOS the build is for
    one architecture, `ARCHFLAGS` (default: this machine's), and the tag says which; the
    interpreter's own `-arch` pairs (python.org builds are universal2) are taken off the link line.
    Reproducible: source paths are mapped out of the binary and the inputs go in sorted order.
    """

    POSIX_FLAGS: ClassVar[tuple[str, ...]] = (
        "-O2", "-fPIC", "-std=c11", "-Wall", "-Wextra", "-Wconversion", "-Wshadow", "-Werror",
        "-fstack-protector-strong", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-fno-strict-overflow",
        "-fno-delete-null-pointer-checks",
    )  # fmt: skip
    #: Linux only (proven there; macOS keeps the common set): stack-clash probes, and the CPU's
    #: control-flow protection (branch target identification and return-address signing on
    #: aarch64, CET on x86_64). FORTIFY 3 falls back to 2's checks on a glibc older than 2.34.
    LINUX_FLAGS: ClassVar[dict[str, tuple[str, ...]]] = {
        "": ("-fstack-clash-protection",),
        "aarch64": ("-mbranch-protection=standard",),
        "x86_64": ("-fcf-protection=full",),
    }
    #: GNU ld and lld; Apple's linker has no -z and already makes no executable stack.
    ELF_LINK: ClassVar[tuple[str, ...]] = ("-Wl,-z,relro,-z,now,-z,noexecstack",)
    MSVC_FLAGS: ClassVar[tuple[str, ...]] = ("/nologo", "/O2", "/GS", "/guard:cf", "/W4", "/WX")
    MSVC_LINK: ClassVar[tuple[str, ...]] = (
        "/guard:cf",
        "/DYNAMICBASE",
        "/HIGHENTROPYVA",
        "/NXCOMPAT",
    )

    class Failed(Exception):
        """The native build could not be made, and `CORDON_BUILD_NATIVE=require` was set."""

    @staticmethod
    def wanted(project: Project) -> list[dict[str, Any]]:
        if os.environ.get("CORDON_BUILD_PURE") == "1":
            return []
        return list(project.build.get("native", []))

    @staticmethod
    def compiler() -> list[str] | None:
        """The C compiler the interpreter was built with, as a command; None when there is none."""
        import shlex
        import shutil
        import sysconfig

        if os.name == "nt":
            return ["cl"] if shutil.which("cl") else None
        command = shlex.split(sysconfig.get_config_var("CC") or "cc")
        return command if command and shutil.which(command[0]) else None

    @staticmethod
    def macos() -> bool:
        import sys

        name: str = (
            sys.platform
        )  # read at run time: a type checker would fix it to its own platform
        return name == "darwin"

    @staticmethod
    def archs() -> list[str]:
        """macOS: the architectures built for (`ARCHFLAGS`, default this machine's); elsewhere none."""
        import platform
        import shlex

        if not Native.macos():
            return []
        words = shlex.split(os.environ.get("ARCHFLAGS") or f"-arch {platform.machine()}")
        return [words[i + 1] for i, w in enumerate(words[:-1]) if w == "-arch"]

    @staticmethod
    def macos_target() -> str:
        """The oldest macOS the binary runs on, and the tag says: the interpreter's, at least 11.0
        when arm64 is built (the first macOS on arm64)."""
        import sysconfig

        target = os.environ.get("MACOSX_DEPLOYMENT_TARGET") or str(
            sysconfig.get_config_var("MACOSX_DEPLOYMENT_TARGET") or "11.0"
        )
        parts = tuple(int(p) for p in target.split(".")[:2] if p.isdigit())
        if "arm64" in Native.archs() and parts < (11, 0):
            return "11.0"
        return ".".join(str(p) for p in (*parts, 0)[:2])

    @staticmethod
    def arch() -> list[str]:
        """macOS: the architecture and deployment-target flags, for the compiler and the linker."""
        archs = Native.archs()
        if not archs:
            return []
        flags = [w for a in archs for w in ("-arch", a)]
        return [*flags, f"-mmacosx-version-min={Native.macos_target()}"]

    @staticmethod
    def linux_flags() -> list[str]:
        import platform
        import sys

        name: str = sys.platform
        if not name.startswith("linux"):
            return []
        return [*Native.LINUX_FLAGS[""], *Native.LINUX_FLAGS.get(platform.machine(), ())]

    @staticmethod
    def linker() -> list[str]:
        import shlex
        import sysconfig

        words = shlex.split(sysconfig.get_config_var("LDSHARED") or "cc -shared")
        if Native.macos():  # the interpreter's -arch pairs out; ours in, by arch()
            kept = []
            skip = False
            for word in words:
                if skip:
                    skip = False
                elif word == "-arch":
                    skip = True
                else:
                    kept.append(word)
            return [*kept, *Native.arch()]
        return [*words, *Native.ELF_LINK]

    @staticmethod
    def build(project: Project, work: Path) -> list[tuple[str, bytes]]:
        """Each extension compiled into `work`, as (archive name, bytes); [] when built pure."""
        import subprocess
        import sys

        wanted = Native.wanted(project)
        required = os.environ.get("CORDON_BUILD_NATIVE") == "require"
        if not wanted:
            if required:
                raise Native.Failed("CORDON_BUILD_NATIVE=require, but no native extension is built")
            return []
        cc = Native.compiler()
        if cc is None:
            if required:
                raise Native.Failed("no C compiler, and CORDON_BUILD_NATIVE=require")
            sys.stderr.write("cordon_build: no C compiler; building the pure wheel (native: no)\n")
            return []
        try:
            return [
                Native._one(project, ext, cc, work)
                for ext in sorted(wanted, key=lambda e: str(e["name"]))
            ]
        except (subprocess.CalledProcessError, OSError) as error:
            if required:
                raise Native.Failed(f"the native build failed: {error}") from error
            sys.stderr.write(
                f"cordon_build: the native build failed ({error}); building the pure wheel\n"
            )
            return []

    @staticmethod
    def _one(project: Project, ext: dict[str, Any], cc: list[str], work: Path) -> tuple[str, bytes]:
        import subprocess
        import sys
        import sysconfig

        include = sysconfig.get_paths()["include"]
        suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
        module = str(ext["name"])
        sources = sorted(str(project.root / s) for s in ext["sources"])
        target = work / (module.split(".")[-1] + suffix)
        if os.name == "nt":
            command = [*cc, *Native.MSVC_FLAGS, f"/I{include}", f"/Fo{work}\\", "/LD", *sources,
                       f"/Fe{target}", "/link", *Native.MSVC_LINK, f"/LIBPATH:{Path(sys.base_prefix) / 'libs'}"]  # fmt: skip
            subprocess.run(command, check=True, cwd=work)  # noqa: S603 - the interpreter's own compiler and our sources
        else:
            compile_ = [*cc, *Native.POSIX_FLAGS, *Native.linux_flags(), *Native.arch(), f"-ffile-prefix-map={project.root}=.", f"-I{include}", "-c"]  # fmt: skip
            objects = []
            for source in sources:
                obj = work / (Path(source).stem + ".o")
                subprocess.run([*compile_, source, "-o", str(obj)], check=True)  # noqa: S603 - the interpreter's own compiler and our sources
                objects.append(str(obj))
            subprocess.run([*Native.linker(), *objects, "-o", str(target)], check=True)  # noqa: S603 - sysconfig's linker and our objects
        return module.replace(".", "/") + suffix, target.read_bytes()

    @staticmethod
    def tag() -> str:
        """This interpreter's wheel tag: cpXY-cpXY-<platform>."""
        import sys
        import sysconfig

        version = f"cp{sys.version_info.major}{sys.version_info.minor}"
        platform = os.environ.get("CORDON_WHEEL_PLATFORM") or sysconfig.get_platform()
        if not os.environ.get("CORDON_WHEEL_PLATFORM") and Native.macos():
            archs = sorted(Native.archs())
            machine = "universal2" if archs == ["arm64", "x86_64"] else "_".join(archs)
            platform = f"macosx-{Native.macos_target()}-{machine}"
        return f"{version}-{version}-{platform.replace('-', '_').replace('.', '_')}"


class Backend:
    """The PEP 517 and PEP 660 hooks."""

    @staticmethod
    def _dist_info(
        project: Project, tag_editable: bool = False, tag: str = "py3-none-any"
    ) -> list[tuple[str, bytes]]:
        info = f"{project.dist}-{project.version}.dist-info"
        purelib = "true" if tag == "py3-none-any" else "false"
        out = [
            (f"{info}/METADATA", project.metadata().encode()),
            (
                f"{info}/WHEEL",
                f"Wheel-Version: 1.0\nGenerator: cordon_build\nRoot-Is-Purelib: {purelib}\nTag: {tag}\n\n".encode(),
            ),
        ]
        entry = project.entry_points()
        if entry:
            out.append((f"{info}/entry_points.txt", entry.encode()))
        out.append(
            (
                f"{info}/top_level.txt",
                "".join(t + "\n" for t in sorted(project.build["packages"])).encode(),
            )
        )
        out += [
            (f"{info}/licenses/{f}", (project.root / f).read_bytes())
            for f in project.license_files()
        ]
        del tag_editable
        return out

    @staticmethod
    def _wheel_name(project: Project, tag: str = "py3-none-any") -> str:
        return f"{project.dist}-{project.version}-{tag}.whl"

    @staticmethod
    def get_requires_for_build_wheel(config_settings: dict[str, Any] | None = None) -> list[str]:
        return []

    @staticmethod
    def get_requires_for_build_sdist(config_settings: dict[str, Any] | None = None) -> list[str]:
        return []

    @staticmethod
    def get_requires_for_build_editable(config_settings: dict[str, Any] | None = None) -> list[str]:
        return []

    @staticmethod
    def prepare_metadata_for_build_wheel(
        metadata_directory: str, config_settings: dict[str, Any] | None = None
    ) -> str:
        project = Project()
        for name, data in Backend._dist_info(project):
            target = Path(metadata_directory) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return f"{project.dist}-{project.version}.dist-info"

    prepare_metadata_for_build_editable = prepare_metadata_for_build_wheel

    @staticmethod
    def build_wheel(
        wheel_directory: str,
        config_settings: dict[str, Any] | None = None,
        metadata_directory: str | None = None,
    ) -> str:
        import tempfile

        project = Project()
        entries = [(name, path.read_bytes()) for name, path in project.wheel_files().items()]
        with tempfile.TemporaryDirectory() as work:
            compiled = Native.build(project, Path(work))
        tag = Native.tag() if compiled else "py3-none-any"
        entries = sorted(entries + compiled)
        entries += Backend._dist_info(project, tag=tag)
        name = Backend._wheel_name(project, tag)
        Archive.wheel(
            Path(wheel_directory) / name,
            entries,
            f"{project.dist}-{project.version}.dist-info/RECORD",
        )
        return name

    @staticmethod
    def build_editable(
        wheel_directory: str,
        config_settings: dict[str, Any] | None = None,
        metadata_directory: str | None = None,
    ) -> str:
        """A wheel holding one `.pth` that puts this tree's `src` on the path (PEP 660)."""
        project = Project()
        src = (project.root / project.build.get("source", "src")).resolve()
        entries = [(f"__editable__.{project.dist}.pth", f"{src}\n".encode())]
        entries += Backend._dist_info(project, tag_editable=True)
        name = Backend._wheel_name(project)
        Archive.wheel(
            Path(wheel_directory) / name,
            entries,
            f"{project.dist}-{project.version}.dist-info/RECORD",
        )
        return name

    @staticmethod
    def build_sdist(sdist_directory: str, config_settings: dict[str, Any] | None = None) -> str:
        project = Project()
        files = set(Manifest(project.root).files())
        files |= {"pyproject.toml", "MANIFEST.in", *project.license_files()}
        if isinstance(project.project.get("readme"), str):
            files.add(project.project["readme"])
        files |= {
            (project.root / "src" / n).relative_to(project.root).as_posix()
            for n in project.wheel_files()
        }
        files |= {  # the native extensions' C sources, so an sdist install can compile them
            str(source) for ext in project.build.get("native", []) for source in ext["sources"]
        }
        files |= {  # the backend itself, so the sdist builds with nothing installed
            p.relative_to(project.root).as_posix()
            for where in project.config["build-system"].get("backend-path", [])
            for p in (project.root / where).glob("*.py")
        }
        entries = [(f, (project.root / f).read_bytes()) for f in sorted(files)]
        entries.append(("PKG-INFO", project.metadata().encode()))
        prefix = f"{project.dist}-{project.version}"
        name = f"{prefix}.tar.gz"
        Archive.sdist(Path(sdist_directory) / name, prefix, sorted(entries))
        return name


get_requires_for_build_wheel = Backend.get_requires_for_build_wheel
get_requires_for_build_sdist = Backend.get_requires_for_build_sdist
get_requires_for_build_editable = Backend.get_requires_for_build_editable
prepare_metadata_for_build_wheel = Backend.prepare_metadata_for_build_wheel
prepare_metadata_for_build_editable = Backend.prepare_metadata_for_build_editable
build_wheel = Backend.build_wheel
build_editable = Backend.build_editable
build_sdist = Backend.build_sdist
