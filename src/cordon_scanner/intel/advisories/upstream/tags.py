"""Telling which upstream release a package was built from: a tag inferred from the version, the
conventions projects tag by, and the proof that the published content matches that tag.
"""

from __future__ import annotations

import collections
import http.client
import io
import re
import tarfile
import threading
import urllib.parse
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.intel.advisories.upstream.base import (
    Archive,
    Unnamed,
    Upstream,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


class TagInference:
    """A version's tag in the repository a package's own ecosystem names, where nothing names the
    tag itself (a source downloaded from the project's own site, a Galaxy collection).

    An inference, kept narrow and stated in every finding it produces: the repository's tags are
    read from the repository itself (git's smart-HTTP ref advertisement, what `git ls-remote`
    asks), only a tag spelled as the version -- `1.2.3`, `v1.2.3`, `<project>-1.2.3`,
    `<project>-v1.2.3`, `release-1.2.3` -- counts, and the candidates must all name one commit.
    OSV is then asked by that commit.
    """

    MAX_REFS_BYTES: ClassVar[int] = 32 << 20
    _refs: ClassVar[dict[str, dict[str, str] | None]] = {}
    _tips: ClassVar[dict[str, dict[str, str]]] = {}
    """`repository -> tag -> the object the tag ref points at` (a tag object or a commit): what a
    fetch asks for, since a ref's tip is fetchable from every server."""

    @staticmethod
    def repository(url: str) -> str | None:
        """An https repository address from what an ecosystem writes (`github:owner/repo`, a
        homepage on a forge, a `.git` clone URL), or None for anything that is not one."""
        text = url.strip()
        text = re.sub(r"^github:", "https://github.com/", text)
        text = re.sub(r"^gitlab:", "https://gitlab.com/", text)
        text = re.sub(r"^git\+", "", text)
        text = re.sub(r"^git://", "https://", text)
        if "/-/" in text:
            # A GitLab page (`https://gitlab.gnome.org/GNOME/libxml2/-/wikis/home`): the project
            # is everything before `/-/`, on any GitLab.
            project = text.split("/-/", 1)[0]
            if re.fullmatch(r"https://[\w.-]+(?::\d+)?/[\w.~-]+(?:/[\w.~-]+){1,8}", project):
                return project
        found = re.match(
            r"^https://(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)/([\w.-]+)/([\w.-]+?)(?:\.git)?/?(?:[#?].*)?$",
            text,
        )
        if found:
            return f"https://{found.group(1)}/{found.group(2)}/{found.group(3)}"
        # A self-hosted git server's clone URL (savannah, sourceware, gitlab.gnome.org).
        found = re.match(r"^https://[\w.-]+(?::\d+)?/[\w./~-]+\.git/?$", text)
        return found.group(0).rstrip("/") if found else None

    @staticmethod
    def refs(repository: str) -> dict[str, str] | None:
        """`tag -> commit` (annotated tags peeled), or None when the server does not speak git's
        smart HTTP."""
        if repository in TagInference._refs:
            return TagInference._refs[repository]
        import urllib.request

        base = repository if repository.endswith(".git") else f"{repository}.git"
        request = urllib.request.Request(  # noqa: S310 - https, from TagInference.repository
            f"{base}/info/refs?service=git-upload-pack",
            headers={"User-Agent": "git/2.45.0 (cordon-scanner)"},
        )
        found: dict[str, str] | None = None
        try:
            # Once more on a failure: a busy forge (savannah) drops a request now and then, and a
            # failure is kept for the whole scan.
            for attempt in (1, 2):
                try:
                    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                        kind = str(response.headers.get("Content-Type") or "")
                        body: bytes = response.read(TagInference.MAX_REFS_BYTES + 1)
                        final = str(response.geturl())
                    break
                except (OSError, http.client.HTTPException):
                    if attempt == 2:
                        raise
            if (
                "git-upload-pack-advertisement" in kind
                and b"version 2" in body[:64]
                and final.startswith("https://")
            ):
                # A server that answers in protocol v2 unasked (git.postgresql.org) lists no
                # refs here: they are asked for with `ls-refs`, peeled.
                found = TagInference.ls_refs(final.split("/info/refs", 1)[0])
                TagInference._tips[repository] = dict(found)
            elif (
                "git-upload-pack-advertisement" in kind and len(body) <= TagInference.MAX_REFS_BYTES
            ):
                found = {}
                peeled: dict[str, str] = {}
                for line in re.findall(rb"[0-9a-f]{4}([0-9a-f]{40}) (refs/tags/[^\x00\n]+)", body):
                    commit, ref = line[0].decode(), line[1].decode()
                    name = ref[len("refs/tags/") :]
                    if name.endswith("^{}"):
                        peeled[name[:-3]] = commit
                    else:
                        found[name] = commit
                found.update(peeled)
                TagInference._tips[repository] = dict(found)
                found.update(peeled)
            elif (
                final.startswith("https://")
                and len(body) <= TagInference.MAX_REFS_BYTES
                and re.match(rb"[0-9a-f]{40}\trefs/", body)
            ):
                # Git's "dumb" HTTP (git.joeyh.name): `info/refs` is the plain list `<id>\t<ref>`,
                # an annotated tag followed by its `^{}` peeled line. Tags only: no tree is fetched
                # this way, so what it names is never proved, only inferred.
                found = {}
                peeled = {}
                for raw_id, raw_ref in re.findall(rb"(?m)^([0-9a-f]{40})\trefs/tags/(\S+)$", body):
                    name = raw_ref.decode("utf-8", "replace")
                    if name.endswith("^{}"):
                        peeled[name[:-3]] = raw_id.decode()
                    else:
                        found[name] = raw_id.decode()
                found.update(peeled)
        except (OSError, ValueError, http.client.HTTPException):
            found = None
        TagInference._refs[repository] = found
        return found

    @staticmethod
    def ls_refs(base: str) -> dict[str, str]:
        """`tag -> commit` by protocol v2's `ls-refs`, annotated tags peeled."""
        import urllib.request

        from cordon_scanner.intel.provenance.gitfetch import GitFetch

        body = b"".join(
            [
                GitFetch._pkt("command=ls-refs\n"),
                GitFetch._pkt("agent=git/2.45.0 (cordon-scanner)\n"),
                b"0001",
                GitFetch._pkt("peel\n"),
                GitFetch._pkt("ref-prefix refs/tags/\n"),
                b"0000",
            ]
        )
        request = urllib.request.Request(  # noqa: S310 - https, checked by the caller
            f"{base}/git-upload-pack",
            data=body,
            headers={
                "User-Agent": "git/2.45.0 (cordon-scanner)",
                "Git-Protocol": "version=2",
                "Content-Type": "application/x-git-upload-pack-request",
                "Accept": "application/x-git-upload-pack-result",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            answer: bytes = response.read(TagInference.MAX_REFS_BYTES + 1)
        if len(answer) > TagInference.MAX_REFS_BYTES:
            raise ValueError("ref listing too large")
        found: dict[str, str] = {}
        for line in GitFetch._lines(answer):
            listed = re.match(
                rb"([0-9a-f]{40}) refs/tags/(\S+)(?: peeled:([0-9a-f]{40}))?", line or b""
            )
            if listed:
                found[listed.group(2).decode()] = (listed.group(3) or listed.group(1)).decode()
        return found

    @staticmethod
    def infer(repository: str, version: str, names: Iterable[str], how: str) -> Upstream | Unnamed:
        tags = TagInference.refs(repository)
        if tags is None:
            return Unnamed(f"{repository} could not be read as a git repository")
        # The version as written, and with its dots as underscores (Ruby's `v3_2_2`, curl's
        # `curl-8_0_0`): the same version, spelled the way some projects tag.
        forms = {version, version.replace(".", "_")}
        spellings = {s for v in forms for s in (v, f"v{v}", f"release-{v}", f"version-{v}")}
        # PostgreSQL's `REL_14_5`, `REL9_6_24`: the underscore form behind its own prefix.
        spellings |= {f"REL_{version.replace('.', '_')}", f"REL{version.replace('.', '_')}"}
        spellings |= {f"n{version}", f"VER-{version.replace('.', '-')}"}
        for name in names:
            if name:
                spellings |= {
                    s
                    for v in forms
                    # GCC's `releases/gcc-15.2.0`; GNOME's `AT_SPI2_CORE_2_40_3` for at-spi2-core.
                    for s in (
                        f"{name}-{v}",
                        f"{name}-v{v}",
                        f"{name}_{v}",
                        f"releases/{name}-{v}",
                        f"{name.replace('-', '_')}_{v}",
                    )
                }
        # Spelled in any case (OpenSSL's `OpenSSL_1_1_1n` for openssl 1.1.1n): every tag that
        # matches still has to name the one commit.
        wanted = {spelling.lower() for spelling in spellings}
        matched = {tag: commit for tag, commit in tags.items() if tag.lower() in wanted}
        if not matched:
            return Unnamed(f"{repository} has no tag spelled as version {version}")
        commits = set(matched.values())
        if len(commits) != 1:
            return Unnamed(f"{repository}'s tags for {version} name different commits")
        tag = sorted(matched)[0]
        commit = commits.pop()
        return Upstream(
            {"commit": commit},
            f"{how}, inferred: the tag {tag} in {repository}, the only commit a tag spelled as "
            f"version {version} names",
            inferred=True,
            tag=tag,
        )


class Conventions:
    """Repositories a download host's own layout implies for a release it serves: GNU's
    `ftp.gnu.org/gnu/<name>/` and savannah's `<name>.git`, sourceware's `pub/<name>/` and its
    `git/<name>.git`, GNOME's `sources/<name>/` and its GitLab. A guess by itself, so used only
    to be proved against the release (`ContentProof`), never as an inference."""

    #: GNU's release directories (ftp.gnu.org and its mirrors), for the projects below.
    GNU: ClassVar[str] = (
        r"^https?://(?:mirror\.bazel\.build/)?(?:ftp\.gnu\.org/(?:pub/)?gnu|ftpmirror\.gnu\.org(?:/gnu)?|mirrors\.kernel\.org/gnu)/"
    )
    FORMS: ClassVar[tuple[tuple[re.Pattern[str], str], ...]] = (
        # GNU projects whose repository is not savannah's.
        (re.compile(GNU + r"gcc/"), "https://gcc.gnu.org/git/gcc.git"),
        (re.compile(GNU + r"(?:binutils|gdb)/"), "https://sourceware.org/git/binutils-gdb.git"),
        (re.compile(GNU + r"glibc/"), "https://sourceware.org/git/glibc.git"),
        (re.compile(GNU + r"(mpc|mpfr)/"), "https://gitlab.inria.fr/{0}/{0}.git"),
        # XZ Utils: SourceForge's lzmautils and tukaani.org serve its releases.
        (
            re.compile(
                r"^https?://(?:(?:downloads\.)?sourceforge\.net/projects?/lzmautils/"
                r"|tukaani\.org/xz/|github\.com/tukaani-project/xz/releases/)"
            ),
            "https://github.com/tukaani-project/xz",
        ),
        (
            re.compile(
                r"^https?://(?:mirror\.bazel\.build/)?(?:ftp\.gnu\.org/gnu|ftpmirror\.gnu\.org(?:/gnu)?"
                r"|mirrors\.kernel\.org/gnu|ftp\.gnu\.org/pub/gnu)/([\w.+-]+)/"
            ),
            "https://git.savannah.gnu.org/git/{0}.git",
        ),
        (
            re.compile(
                r"^https?://(?:mirror\.bazel\.build/)?(?:www\.)?sourceware\.org/pub/([\w.+-]+)/"
            ),
            "https://sourceware.org/git/{0}.git",
        ),
        (
            re.compile(
                r"^https?://(?:download-mirror\.savannah\.(?:gnu|nongnu)\.org"
                r"|download\.savannah\.gnu\.org)/releases/([\w.+-]+)/"
            ),
            "https://git.savannah.gnu.org/git/{0}.git",
        ),
        # SourceForge's git: `git.code.sf.net/p/<project>/code` (or `/git`), where a project
        # keeps one.
        (
            re.compile(
                r"^https?://(?:downloads\.)?sourceforge\.net/projects?/([\w.-]+)/"
                r"|^https?://prdownloads\.sourceforge\.net/([\w.-]+)/"
            ),
            "https://git.code.sf.net/p/{}/code",
        ),
        (
            re.compile(
                r"^https?://(?:downloads\.)?sourceforge\.net/projects?/([\w.-]+)/"
                r"|^https?://prdownloads\.sourceforge\.net/([\w.-]+)/"
            ),
            "https://git.code.sf.net/p/{}/git",
        ),
        # The Apache Software Foundation's releases, and its mirrors of each project on GitHub.
        (
            re.compile(
                r"^https?://(?:archive\.apache\.org/dist|downloads\.apache\.org|dlcdn\.apache\.org"
                r"|www\.apache\.org/dist)/([\w.-]+)/"
            ),
            "https://github.com/apache/{}",
        ),
        (
            re.compile(r"^https?://(?:www\.)?netfilter\.org/projects/([\w.-]+)/files/"),
            "https://git.netfilter.org/{}",
        ),
        (
            re.compile(r"^https?://ftp\.postgresql\.org/pub/source/v[\d.]+/(postgresql)-"),
            "https://git.postgresql.org/git/{}.git",
        ),
        (
            re.compile(r"^https?://(?:www\.)?gnupg\.org/ftp/gcrypt/([\w.+-]+)/"),
            "https://dev.gnupg.org/source/{}.git",
        ),
        (
            re.compile(r"^https?://(?:www\.)?python\.org/ftp/(python)/"),
            "https://github.com/python/cpython",
        ),
        (
            re.compile(r"^https?://(?:www\.)?sqlite\.org/\d{4}/(sqlite)-"),
            "https://github.com/sqlite/sqlite",
        ),
        (
            re.compile(r"^https?://distfiles\.(?:ariadne\.space|dereferenced\.org)/(pkgconf)/"),
            "https://github.com/pkgconf/pkgconf",
        ),
        (
            re.compile(r"^https?://(?:www\.)?nasm\.us/pub/(nasm)/"),
            "https://github.com/netwide-assembler/nasm",
        ),
        (
            re.compile(r"^https?://(?:www\.)?tortall\.net/projects/(yasm)/"),
            "https://github.com/yasm/yasm",
        ),
        (
            re.compile(
                r"^https?://(?:download|downloads)\.sourceforge\.net/(?:project/)?(libpng)/"
            ),
            "https://github.com/pnggroup/libpng",
        ),
        (
            re.compile(r"^https?://download\.osgeo\.org/(libtiff)/"),
            "https://gitlab.com/libtiff/libtiff",
        ),
        (
            re.compile(
                r"^https?://storage\.googleapis\.com/downloads\.webmproject\.org/releases/webp/(libwebp)-"
            ),
            "https://github.com/webmproject/libwebp",
        ),
        (
            re.compile(r"^https?://downloads\.videolan\.org/(?:pub/)?videolan/(dav1d)/"),
            "https://code.videolan.org/videolan/dav1d",
        ),
        (
            re.compile(r"^https?://(?:www\.)?ffmpeg\.org/+releases/(ffmpeg)-"),
            "https://git.ffmpeg.org/ffmpeg.git",
        ),
        (
            re.compile(r"^https?://storage\.googleapis\.com/aom-releases/(libaom)-"),
            "https://aomedia.googlesource.com/aom",
        ),
        (
            re.compile(r"^https?://download\.open-mpi\.org/release/(hwloc)/"),
            "https://github.com/open-mpi/hwloc",
        ),
        (
            re.compile(r"^https?://download\.open-mpi\.org/release/(open-mpi)/"),
            "https://github.com/open-mpi/ompi",
        ),
        (
            re.compile(
                r"^https?://(?:download|downloads)\.videolan\.org/(?:pub/)?videolan/(x265)/"
            ),
            "https://bitbucket.org/multicoreware/x265_git",
        ),
        (
            re.compile(r"^https?://(?:www\.)?libsdl\.org/projects/(SDL_\w+)/release/"),
            "https://github.com/libsdl-org/{0}",
        ),
        (
            re.compile(r"^https?://(?:www\.)?fftw\.org/(fftw)-"),
            "https://github.com/FFTW/fftw3",
        ),
        (
            re.compile(r"^https?://dri\.freedesktop\.org/(libdrm)/"),
            "https://gitlab.freedesktop.org/mesa/drm",
        ),
        (
            re.compile(r"^https?://(?:www\.)?sourceware\.org/(elfutils)/ftp/"),
            "https://sourceware.org/git/elfutils.git",
        ),
        (
            re.compile(
                r"^https?://(?:cdn|mirrors\.edge|www)\.kernel\.org/pub/linux/utils/(util-linux)/"
            ),
            "https://github.com/util-linux/util-linux",
        ),
        (
            re.compile(r"^https?://download\.savannah\.(?:gnu|nongnu)\.org/releases/(freetype)/"),
            "https://gitlab.freedesktop.org/freetype/freetype",
        ),
        (re.compile(r"^https?://(?:www\.)?lua\.org/ftp/(lua)-"), "https://github.com/lua/lua"),
        (
            re.compile(r"^https?://(?:www\.)?openssl\.org/source/(?:old/[\w.]+/)?(openssl)-"),
            "https://github.com/openssl/openssl",
        ),
        (
            re.compile(r"^https?://cache\.ruby-lang\.org/pub/(ruby)/"),
            "https://github.com/ruby/{0}",
        ),
        (
            re.compile(
                r"^https?://(?:download\.gnome\.org|ftp\.gnome\.org/pub/(?:gnome|GNOME))/sources/([\w.+-]+)/"
            ),
            "https://gitlab.gnome.org/GNOME/{0}",
        ),
        # Small tools whose own sites serve the releases their public repositories tag.
        (
            re.compile(r"^https?://mama\.indstate\.edu/users/ice/(tree)/"),
            "https://gitlab.com/OldManProgrammer/unix-tree",
        ),
        (
            re.compile(r"^https?://(?:www\.)?ivarch\.com/programs/sources/(pv)-"),
            "https://github.com/a-j-wood/pv",
        ),
        (
            re.compile(r"^https?://(?:www\.)?colordiff\.org/(colordiff)-"),
            "https://github.com/daveewart/colordiff",
        ),
        (
            re.compile(r"^https?://zsync\.moria\.org\.uk/download/(zsync)-"),
            "https://github.com/cph6/zsync",
        ),
        (
            re.compile(
                r"^https?://(?:www\.)?x\.org/(?:releases|archive)/+individual/data/xkeyboard-config/"
            ),
            "https://gitlab.freedesktop.org/xkeyboard-config/xkeyboard-config",
        ),
        (
            re.compile(r"^https?://pkg-config\.freedesktop\.org/releases/pkg-config-"),
            "https://gitlab.freedesktop.org/pkg-config/pkg-config",
        ),
        (
            re.compile(r"^https?://(?:www\.)?open-mpi\.org/software/(hwloc)/"),
            "https://github.com/open-mpi/hwloc",
        ),
        # XCB's utility libraries, released as xcb-util-*, from xorg/lib/libxcb-*.
        (
            re.compile(
                r"^https?://xcb\.freedesktop\.org/dist/xcb-util-(image|cursor|keysyms|wm)-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/lib/libxcb-{0}",
        ),
        (
            re.compile(r"^https?://xcb\.freedesktop\.org/dist/xcb-util-renderutil-\d"),
            "https://gitlab.freedesktop.org/xorg/lib/libxcb-render-util",
        ),
        (
            re.compile(r"^https?://xcb\.freedesktop\.org/dist/xcb-util-\d"),
            "https://gitlab.freedesktop.org/xorg/lib/libxcb-util",
        ),
        (
            re.compile(r"^https?://(?:www\.)?gaia-gis\.it/gaia-sins/(librttopo)-"),
            "https://git.osgeo.org/gitea/rttopo/librttopo",
        ),
        (
            re.compile(r"^https?://download\.libsodium\.org/libsodium/releases/"),
            "https://github.com/jedisct1/libsodium",
        ),
        (
            re.compile(
                r"^https?://downloads\.xiph\.org/releases/(ogg|vorbis|flac|opus|theora|speex)/"
            ),
            "https://gitlab.xiph.org/xiph/{0}",
        ),
        (
            re.compile(r"^https?://icon-theme\.freedesktop\.org/releases/hicolor-icon-theme-"),
            "https://gitlab.freedesktop.org/xdg/default-icon-theme",
        ),
        (
            re.compile(r"^https?://download\.osgeo\.org/geotiff/libgeotiff/"),
            "https://github.com/OSGeo/libgeotiff",
        ),
        (
            re.compile(
                r"^https?://(?:www\.)?freedesktop\.org/software/pulseaudio/releases/pulseaudio-"
            ),
            "https://gitlab.freedesktop.org/pulseaudio/pulseaudio",
        ),
        (
            re.compile(r"^https?://confluence\.ecmwf\.int/download/attachments/\d+/eccodes-"),
            "https://github.com/ecmwf/eccodes",
        ),
        (
            re.compile(r"^https?://(?:downloads\.)?sourceforge\.net/projects?/freeglut/"),
            "https://github.com/freeglut/freeglut",
        ),
        # XCB's libpthread-stubs is released under that name from `xorg/lib/pthread-stubs`.
        (
            re.compile(
                r"^https?://(?:www\.x\.org|xorg\.freedesktop\.org|xcb\.freedesktop\.org)/(?:releases/individual/xcb/|archive/individual/xcb/|dist/)libpthread-stubs-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/lib/pthread-stubs",
        ),
        # X.org's util-macros is released under that name from its repository `xorg/util/macros`.
        (
            re.compile(
                r"^https?://(?:www\.)?x\.org/(?:releases|archive)/+individual/util/util-macros-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/util/macros",
        ),
        (
            re.compile(r"^https?://ziglang\.org/download/[\d.]+/(zig)-"),
            "https://github.com/ziglang/zig",
        ),
        (
            re.compile(r"^https?://(?:www\.)?spice-space\.org/download/gtk/(spice-gtk)-"),
            "https://gitlab.freedesktop.org/spice/spice-gtk",
        ),
        (
            re.compile(
                r"^https?://(?:www\.)?x\.org/(?:releases|archive)/+individual/([\w-]+)/([\w.+-]+?)-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/{0}/{1}",
        ),
        (
            re.compile(
                r"^https?://xorg\.freedesktop\.org/(?:releases|archive)/individual/([\w-]+)/([\w.+-]+?)-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/{0}/{1}",
        ),
    )

    @staticmethod
    def repositories(urls: Iterable[str]) -> list[str]:
        out: list[str] = []
        for url in urls:
            for form, template in Conventions.FORMS:
                found = form.match(url)
                if found:
                    # A form with alternatives has a group per alternative: those that matched.
                    out.append(template.format(*(g for g in found.groups() if g is not None)))
        return list(dict.fromkeys(out))


class ContentProof:
    """Whether an inferred tag IS the source a recipe builds: the release archive the recipe pins,
    checked against its digest, beside the tag's tree fetched by git's own protocol, compared by
    git blob id (dot-files aside).

    Refuted when any file both hold differs -- which is how a neighbouring version's tag fails:
    whatever changed between the two is shipped. Exactly two differences are git's own, not
    different source: its end-of-line conversion (`text eol=crlf`), and a file the tag holds
    empty that the release fills in (GNU's ChangeLog, written by `make dist`). A release may also
    add files (`configure`, generated docs) and leave some out (tests, fuzzing inputs).

    Proven when nothing differs and enough is shared to mean something: at least `MIN_SHARED`
    identical files, or, for a small project, at least `MIN_SMALL` that are `MIN_SHARE` of the
    tag's. A wrong tag could pass only by differing in files the release does not ship -- the same
    shipped code, so the same vulnerabilities."""

    MIN_SHARED: ClassVar[int] = 100
    #: Documentation a release may edit: its news, changelog, readme and credits, by name.
    PROSE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)(?:README|NEWS|CHANGES|CHANGELOG|HISTORY|AUTHORS|THANKS|TODO|RELEASE[-_]?NOTES)"
        r"(?:\.(?:md|txt|rst|adoc))?"
    )
    MIN_SMALL: ClassVar[int] = 5
    MIN_SHARE: ClassVar[float] = 0.9
    EMPTY_BLOB: ClassVar[str] = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    """Git's id for an empty file."""
    MAX_ARCHIVE_BYTES: ClassVar[int] = 256 << 20
    SOCKET_SECONDS: ClassVar[float] = 30.0
    DOWNLOAD_SECONDS: ClassVar[float] = 300.0
    _running: ClassVar[threading.BoundedSemaphore] = threading.BoundedSemaphore(2)
    _results: ClassVar[dict[tuple[str, str, str], tuple[str, str]]] = {}

    @staticmethod
    def _digest_matches(body: bytes, digest: str) -> bool:
        import base64
        import hashlib

        if "-" in digest and ":" not in digest:  # SRI
            algorithm, _, encoded = digest.partition("-")
            try:
                expected = base64.b64decode(encoded).hex()
            except ValueError:
                return False
        else:
            algorithm, _, expected = digest.partition(":")
        if algorithm not in ("sha256", "sha512"):
            return False
        return hashlib.new(algorithm, body).hexdigest() == expected.lower()

    @staticmethod
    def _download(url: str) -> bytes:
        import urllib.request

        # Plain http is allowed here only: what is read is used only if it hashes to the digest
        # the recipe pins (zlib's conda recipe names http://zlib.net/), so the transport cannot
        # change what is compared.
        if not url.startswith(("https://", "http://")):
            raise ValueError("not http(s)")
        import time

        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
        # Each connect and read has its own short timeout -- a host that drops packets fails in
        # seconds, not after the read timeout for every address it resolves to -- and the whole
        # download a deadline, so a server trickling bytes cannot hold a scan.
        deadline = time.monotonic() + ContentProof.DOWNLOAD_SECONDS
        chunks: list[bytes] = []
        size = 0
        with urllib.request.urlopen(request, timeout=ContentProof.SOCKET_SECONDS) as response:  # noqa: S310
            while True:
                chunk: bytes = response.read(1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > ContentProof.MAX_ARCHIVE_BYTES:
                    raise ValueError("archive too large")
                if time.monotonic() > deadline:
                    raise TimeoutError("the release archive took too long to download")
        return b"".join(chunks)

    @staticmethod
    def blobs(body: bytes) -> dict[str, tuple[str, str | None]]:
        """`path -> (git blob id, blob id with CRLF made LF, where it has a CRLF)` of each regular
        file, the archive's one top-level folder removed. Each file is hashed as it is read and
        not kept: a toolchain's release (gcc, llvm) is gigabytes once inflated."""
        import zipfile

        from cordon_scanner.intel.provenance.gitfetch import GitPack

        def ids(data: bytes) -> tuple[str, str | None]:
            converted = GitPack.blob_id(data.replace(b"\r\n", b"\n")) if b"\r\n" in data else None
            return GitPack.blob_id(data), converted

        out: dict[str, tuple[str, str | None]] = {}
        if body[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(body)) as zipped:
                for info in zipped.infolist():
                    if not info.is_dir():
                        out[info.filename] = ids(zipped.read(info))
        else:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r|*") as archive:
                for member in archive:
                    if member.isfile():
                        handle = archive.extractfile(member)
                        if handle is not None:
                            out[member.name] = ids(handle.read())
        tops = {path.split("/", 1)[0] for path in out}
        if len(tops) == 1 and all("/" in path for path in out):
            out = {path.split("/", 1)[1]: found for path, found in out.items()}
        return out

    @staticmethod
    def tree_archive(repository: str, commit: str) -> str | None:
        """The forge's archive of exactly this commit, where the forge has a fixed form for one."""
        if repository.startswith("https://github.com/"):
            return f"https://codeload.github.com/{repository[len('https://github.com/') :]}/tar.gz/{commit}"
        host = urllib.parse.urlsplit(repository).hostname or ""
        if (
            repository.startswith("https://")
            and "gitlab" in host
            and not repository.endswith(".git")
        ):
            # GitLab: `/-/archive/<sha>/<name>-<sha>.tar.gz` (gitlab.com, gitlab.gnome.org, ...).
            name = repository.rstrip("/").rsplit("/", 1)[-1]
            return f"{repository.rstrip('/')}/-/archive/{commit}/{name}-{commit}.tar.gz"
        if host == "codeberg.org":
            return f"{repository.rstrip('/')}/archive/{commit}.tar.gz"
        found = re.fullmatch(
            r"https://git\.savannah\.(?:gnu|nongnu)\.org/git/([\w.+-]+)\.git", repository
        )
        if found:
            # Savannah runs cgit: `/cgit/<repo>.git/snapshot/<repo>-<sha>.tar.gz`.
            host_root = repository.split("/git/", 1)[0]
            return (
                f"{host_root}/cgit/{found.group(1)}.git/snapshot/{found.group(1)}-{commit}.tar.gz"
            )
        return None

    @staticmethod
    def check(archive: Archive, repository: str, commit: str, tag: str = "") -> tuple[str, str]:
        """`(outcome, detail)`: `proven`, `refuted`, or `unprovable`."""
        key = (repository, commit, archive.digest)
        cached = ContentProof._results.get(key)
        if cached is not None:
            return cached
        # A release archive and its tag's tree are held at once: two proofs at a time, whatever
        # the number of lookups running.
        with ContentProof._running:
            result = ContentProof._check(archive, repository, commit, tag)
        ContentProof._results[key] = result
        return result

    @staticmethod
    def _check(archive: Archive, repository: str, commit: str, tag: str) -> tuple[str, str]:
        from cordon_scanner.intel.provenance.gitfetch import GitFetch, GitFetchError

        tip = next(
            (
                TagInference._tips.get(repository, {}).get(tag, "")
                for tag, peeled in (TagInference._refs.get(repository) or {}).items()
                if peeled == commit and tag in TagInference._tips.get(repository, {})
            ),
            commit,
        )
        release: bytes | None = None
        # A recipe's URL may have moved (zlib.net keeps only its newest release there); the same
        # file published as the GitHub release's asset is tried too. Only bytes that hash to the
        # recipe's digest are ever used, so another address cannot change what is compared.
        candidates = list(archive.urls)
        if tag and repository.startswith("https://github.com/"):
            candidates += [
                f"{repository}/releases/download/{tag}/{url.rsplit('/', 1)[-1]}"
                for url in archive.urls
            ]
        # GNU's own mirror redirector for a file on ftp.gnu.org, which is often too loaded to answer.
        candidates += [
            re.sub(r"^https?://ftp\.gnu\.org/(?:pub/)?gnu/", "https://ftpmirror.gnu.org/gnu/", url)
            for url in archive.urls
            if re.match(r"^https?://ftp\.gnu\.org/(?:pub/)?gnu/", url)
        ]
        for url in dict.fromkeys(candidates):
            try:
                body = ContentProof._download(url)
            except (OSError, ValueError, http.client.HTTPException):
                continue
            if ContentProof._digest_matches(body, archive.digest):
                release = body
                break
        if release is None:
            return "unprovable", "no release archive matching the recipe's digest could be read"
        try:
            hashed = ContentProof.blobs(release)
            release = body = b""  # the archive is not needed past its files' ids
            ours = {path: found[0] for path, found in hashed.items()}
        except (OSError, ValueError, tarfile.TarError, EOFError, http.client.HTTPException) as exc:
            return "unprovable", f"the release archive could not be read ({type(exc).__name__})"
        try:
            # The tag's tree by git's own protocol: blob ids, compared with the release's files
            # hashed the way git hashes them.
            theirs = GitFetch.tree(repository, tip)
        except (GitFetchError, OSError, ValueError, http.client.HTTPException) as exc:
            return (
                "unprovable",
                f"the tag's tree could not be fetched ({type(exc).__name__}: {exc})"[:200],
            )
        source = {
            path: blob
            for path, blob in theirs.items()
            if not any(part.startswith(".") for part in path.split("/"))
        }
        # Files paired by path; where that pairs too few, by name -- a release laid out in other
        # directories than its tag (Lua's tarball keeps src/ and doc/, its repository is flat),
        # paired only where a name is unique on both sides.
        pairs = [(path, path) for path in source if path in ours]
        relocated = False
        if not ContentProof._enough(len(pairs), len(source)):

            def unique(paths: Iterable[str]) -> dict[str, str]:
                names = collections.Counter(path.rsplit("/", 1)[-1] for path in paths)
                return {
                    path.rsplit("/", 1)[-1]: path
                    for path in paths
                    if names[path.rsplit("/", 1)[-1]] == 1
                }

            mine, tagged = unique(ours), unique(source)
            by_name = [(mine[name], tagged[name]) for name in mine if name in tagged]
            if len(by_name) > len(pairs):
                pairs, relocated = by_name, True
        differing = [(a, b) for a, b in pairs if ours[a] != source[b]]
        # Git writes a file marked `text eol=crlf` out with CRLF and stores it with LF (git's .bat
        # files): the same content by git's own conversion, which nothing else is excused by.
        converted = [
            (a, b) for a, b in differing if hashed[a][1] is not None and hashed[a][1] == source[b]
        ]
        differing = [pair for pair in differing if pair not in converted]
        # A file the tag holds empty that the release fills in (GNU's ChangeLog, written from the
        # git log by `make dist`): a placeholder for something generated, not different source.
        filled = [(a, b) for a, b in differing if source[b] == ContentProof.EMPTY_BLOB]
        differing = [pair for pair in differing if pair not in filled]
        # Prose the release edits on its way out (mpc's NEWS dated for the release): not code, and
        # never a build file -- a Makefile.am or a version file that differs still refutes.
        prose = [(a, b) for a, b in differing if ContentProof.PROSE.fullmatch(b.rsplit("/", 1)[-1])]
        differing = [pair for pair in differing if pair not in prose]
        if differing:
            return "refuted", f"{len(differing)} of the files both hold differ ({differing[0][1]})"
        if not ContentProof._enough(len(pairs), len(source)):
            return (
                "unprovable",
                f"the release holds {len(pairs)} of the tag's {len(source)} files",
            )
        return (
            "proven",
            f"the release archive holds {len(pairs)} of its {len(source)} files, each with the same git blob id"
            + (" (paired by file name: the release lays them out elsewhere)" if relocated else "")
            + (f" ({len(converted)} after git's end-of-line conversion)" if converted else "")
            + (f" ({len(filled)} empty in the tag, filled by the release)" if filled else "")
            + (
                f" (its documentation differs: {', '.join(sorted(b for _, b in prose))})"
                if prose
                else ""
            ),
        )

    @staticmethod
    def _enough(shared: int, tagged: int) -> bool:
        """Enough identical files to mean something: MIN_SHARED, or for a small project MIN_SMALL
        that are MIN_SHARE of the tag's -- or all of the tag's but one (X.org's renderproto: 8 of
        its 9, the release leaving out a build file of the tag's)."""
        return shared >= ContentProof.MIN_SHARED or (
            shared >= ContentProof.MIN_SMALL
            and (shared >= ContentProof.MIN_SHARE * tagged or tagged - shared <= 1)
        )


__all__ = ["ContentProof", "Conventions", "TagInference"]
