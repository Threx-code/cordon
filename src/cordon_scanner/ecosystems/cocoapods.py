"""CocoaPods.

```
  Podfile        source, platform, target/abstract_target, pod "Name" (version, :git/:tag/:commit/
                 :branch, :path, :podspec, :subspecs, :configurations), plugin, pre/post_install
  *.podspec      dependency (and per subspec), deployment targets, prepare_command, script_phases,
                 vendored_frameworks
  Podfile.lock   PODS (subspecs folded into their pod), DEPENDENCIES, SPEC REPOS, EXTERNAL SOURCES,
                 CHECKOUT OPTIONS, SPEC CHECKSUMS, COCOAPODS
```

The Podfile and podspecs are Ruby, read statically like a Gemfile (`ecosystems/rubygems.py`).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)
from cordon_scanner.ecosystems.rubygems import RubySource

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent


class PodName:
    @staticmethod
    def root(name: str) -> str:
        """`SDWebImage/Core` -> `SDWebImage`: a subspec is part of its pod."""
        return name.split("/", 1)[0].strip()


class Podfile:
    OPENS: ClassVar[re.Pattern[str]] = re.compile(r"\bdo(?:\s*\|[^|]*\|)?\s*$")

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            lines = RubySource.lines(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable Podfile: {exc}")
        declared: dict[str, DeclaredDependency] = {}
        sources: list[str] = []
        hooks: list[Hook] = []
        depth = 0
        targets: list[str] = []
        test_targets: set[str] = set()
        for number, line in lines:
            if line == "end":
                depth -= 1
                if targets and len(targets) > depth:
                    targets.pop()
                if depth < 0:
                    return BaseEcosystem._err(
                        content, ecosystem, f"line {number}: `end` with no block open"
                    )
                continue
            head = re.match(r"^(\w+!?)", line)
            word = head.group(0) if head else ""
            opens = bool(Podfile.OPENS.search(line))
            if RubySource.opens_keyword_block(line) and not opens:
                # `def`, `if`, `unless` ...: a block, not a target; inside one, it is the target's.
                depth += 1
                if targets:
                    targets.append(targets[-1])
                continue
            if opens:
                depth += 1
                if word in ("target", "abstract_target"):
                    targets.append((RubySource.strings(line) or ["?"])[0])
                elif targets:
                    targets.append(targets[-1])  # another block inside the target
                if word in ("post_install", "pre_install", "post_integrate", "pre_integrate"):
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=word,
                            command="Podfile hook (Ruby run by pod install)",
                            ecosystem=ecosystem,
                        )
                    )
                continue
            if word == "inherit!" and ":search_paths" in line and targets:
                # A test target's idiom: it links against the host app and adds only test pods.
                test_targets.add(targets[-1])
                continue
            if word == "source":
                url = (RubySource.strings(line) or [""])[0]
                if url:
                    sources.append(f"source {url}")
            elif word == "platform":
                found = re.match(r"platform\s+:(\w+)\s*,\s*['\"]([\d.]+)['\"]", line)
                if found:
                    declared[f"platform:{found.group(1)}"] = DeclaredDependency(
                        name=found.group(1),
                        spec=f">= {found.group(2)}",
                        scope=Scope.PLATFORM,
                        field_name="platform",
                    )
            elif word == "plugin":
                name = (RubySource.strings(line) or [""])[0]
                if name:
                    declared[name] = DeclaredDependency(
                        name=name, spec="*", scope=Scope.TOOL, field_name="plugin"
                    )
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"plugin {name}",
                            command="a CocoaPods plugin gem, loaded by pod install",
                            ecosystem=ecosystem,
                        )
                    )
            elif word == "pod":
                found_pod = Podfile._pod(line, targets)
                if (
                    found_pod is not None
                    and targets
                    and (targets[-1] in test_targets or re.search(r"(?:UI)?Tests$", targets[-1]))
                ):
                    found_pod = DeclaredDependency(
                        name=found_pod.name,
                        spec=found_pod.spec,
                        scope=Scope.TEST,
                        field_name=found_pod.field_name,
                        platform=found_pod.platform,
                    )
                if found_pod is not None:
                    key = PodName.root(found_pod.name)
                    existing = declared.get(key)
                    if existing is None:
                        declared[key] = found_pod
                    else:
                        # Two subspecs of one pod: one dependency, both subspecs as conditions.
                        declared[key] = DeclaredDependency(
                            name=key,
                            spec=existing.spec,
                            scope=existing.scope,
                            field_name=existing.field_name,
                            platform=tuple(
                                dict.fromkeys((*existing.platform, *found_pod.platform))
                            ),
                        )
        if depth > 0:
            return BaseEcosystem._err(
                content, ecosystem, f"{depth} block(s) never closed with `end`"
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared.values()),
            hooks=tuple(hooks),
            sources=tuple(sources),
        )

    @staticmethod
    def _pod(line: str, targets: list[str]) -> DeclaredDependency | None:
        literals = RubySource.strings(line.split(",", 1)[0])
        if not literals:
            return None
        name = literals[0]
        rest = line.split(",", 1)[1] if "," in line else ""
        positional = re.split(r":\w+\s*=>|\b\w+:\s", rest, maxsplit=1)[0]
        requirements = RubySource.strings(positional)
        conditions: list[str] = []
        if "/" in name:
            conditions.append(f"subspec {name.split('/', 1)[1]}")
        subspecs = re.search(r":subspecs\s*=>\s*\[([^\]]*)\]|subspecs:\s*\[([^\]]*)\]", line)
        if subspecs:
            conditions.extend(
                f"subspec {s}"
                for s in RubySource.strings(subspecs.group(1) or subspecs.group(2) or "")
            )
        configurations = re.search(
            r":configurations?\s*=>\s*\[?([^\]\n]*)\]?|configurations?:\s*\[?([^\]\n]*)\]?", line
        )
        if configurations:
            for value in RubySource.strings(
                configurations.group(1) or configurations.group(2) or ""
            ):
                conditions.append(f"configuration {value}")
        git = RubySource.option(line, "git")
        path = RubySource.option(line, "path")
        podspec = RubySource.option(line, "podspec")
        if git:
            reference = (
                RubySource.option(line, "commit")
                or RubySource.option(line, "tag")
                or RubySource.option(line, "branch")
            )
            spec = f"git+{git}" + (f"#{reference}" if reference else "")
        elif path:
            spec = f"path:{path}"
        elif podspec:
            spec = podspec if "://" in podspec else f"path:{podspec}"
        else:
            spec = ", ".join(requirements) or "*"
        return DeclaredDependency(
            name=PodName.root(name),
            spec=spec,
            field_name="pod" + (f" (target {targets[-1]})" if targets else ""),
            platform=tuple(conditions),
        )


class Podspec:
    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            lines = RubySource.lines(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable podspec: {exc}")
        if content.basename.endswith(".podspec.json"):
            return BaseEcosystem._err(content, ecosystem, "a JSON podspec is not read")
        opened = sum(1 for _, line in lines if re.search(r"\bdo\s*(?:\|[^|]*\|)?\s*$", line))
        closed = sum(1 for _, line in lines if re.match(r"\s*end\b", line))
        if opened > closed:
            # A podspec is one `Pod::Spec.new do |s| ... end` block: a block left open is a file
            # cut short, whatever it had declared before the cut.
            return BaseEcosystem._err(
                content, ecosystem, "a block is never closed: the file is cut short"
            )
        name = None
        declared: dict[str, DeclaredDependency] = {}
        hooks: list[Hook] = []
        # `s.test_spec 'Tests' do |test_spec|` and `s.app_spec ... do |app_spec|`: the block's own
        # variable carries its dependencies, which a test or a demo app needs and the pod does not.
        scoped: dict[str, Scope] = {}
        for _, line in lines:
            block = re.search(r"\.(test_spec|app_spec)\b.*\bdo\s*\|\s*(\w+)\s*\|", line)
            if block:
                scoped[block.group(2)] = Scope.TEST if block.group(1) == "test_spec" else Scope.DEV
            found = re.search(r"\.name\s*=\s*['\"]([^'\"]+)['\"]", line)
            if found and name is None:
                name = found.group(1)
            dependency = re.search(r"(\w+)\.dependency\s*\(?\s*['\"]([^'\"]+)['\"](.*)$", line)
            if dependency:
                pod = PodName.root(dependency.group(2))
                if name and pod == name:
                    continue  # a subspec depending on a sibling subspec of the same pod
                scope = scoped.get(dependency.group(1), Scope.RUNTIME)
                key = pod if scope is Scope.RUNTIME else f"{scope.value}:{pod}"
                declared[key] = DeclaredDependency(
                    name=pod,
                    spec=", ".join(RubySource.strings(dependency.group(3))) or "*",
                    scope=scope,
                    field_name="dependency"
                    if scope is Scope.RUNTIME
                    else f"{dependency.group(1)}.dependency",
                )
            target = re.search(
                r"\.(ios|osx|macos|tvos|watchos|visionos)\.deployment_target\s*=\s*['\"]([\d.]+)['\"]",
                line,
            )
            if target:
                declared[f"platform:{target.group(1)}"] = DeclaredDependency(
                    name=target.group(1),
                    spec=f">= {target.group(2)}",
                    scope=Scope.PLATFORM,
                    field_name="deployment_target",
                )
            if re.search(r"\.prepare_command\s*=", line):
                command = " ".join(RubySource.strings(line))[:200]
                # Run by `pod install` on the machine of whoever installs the pod.
                hooks.append(
                    Hook(
                        kind="preinstall",
                        path=content.path,
                        name="prepare_command",
                        command=command,
                        ecosystem=ecosystem,
                    )
                )
            if re.search(r"\.script_phases?\s*=", line):
                hooks.append(
                    Hook(kind="build", path=content.path, name="script_phases", ecosystem=ecosystem)
                )
            if re.search(r"\.vendored_frameworks?\s*=", line):
                for framework in RubySource.strings(line):
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"vendored framework {framework}",
                            ecosystem=ecosystem,
                        )
                    )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=name,
            dependencies=tuple(declared.values()),
            hooks=tuple(hooks),
        )


class PodfileLock:
    POD: ClassVar[re.Pattern[str]] = re.compile(r'^  - "?([^\s"(]+)"? \(([^)]+)\)(:?)$')
    EDGE: ClassVar[re.Pattern[str]] = re.compile(r'^    - "?([^\s"(]+)"?')

    @staticmethod
    def sections(text: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        current = ""
        for raw in text.splitlines():
            if not raw.strip():
                continue
            if not raw.startswith(" "):
                current = raw.rstrip(":").split(":", 1)[0]
                out.setdefault(current, [])
                if ":" in raw and raw.split(":", 1)[1].strip():
                    out[current].append(raw.split(":", 1)[1].strip())
                continue
            out.setdefault(current, []).append(raw)
        return out

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        sections = PodfileLock.sections(content.text)
        if "PODS" not in sections:
            return LockGraph(path=content.path, ecosystem=ecosystem, parse_error="no PODS section")
        pods: dict[str, dict[str, object]] = {}
        current: str | None = None
        unreadable = 0
        for line in sections["PODS"]:
            found = PodfileLock.POD.match(line)
            if found:
                full, version = found.group(1), found.group(2)
                root = PodName.root(full)
                slot = pods.setdefault(
                    root, {"version": version, "subspecs": set(), "edges": set()}
                )
                if "/" in full:
                    slot["subspecs"].add(full.split("/", 1)[1])  # type: ignore[attr-defined]
                current = root
                continue
            edge = PodfileLock.EDGE.match(line)
            if edge and current is not None:
                target = PodName.root(edge.group(1))
                if target != current:
                    pods[current]["edges"].add(target)  # type: ignore[attr-defined]
                continue
            unreadable += 1
        if unreadable and not pods:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} PODS line(s) could not be read",
            )
        direct = {
            PodName.root(m.group(1))
            for m in (
                re.match(r'^  - "?([^\s"(]+)', line) for line in sections.get("DEPENDENCIES", [])
            )
            if m
        }
        repositories: dict[str, str] = {}
        repository = ""
        for line in sections.get("SPEC REPOS", []):
            # `trunk:` or a repository URL, which has colons of its own.
            header = re.match(r'^  "?(\S+?)"?:$', line)
            if header:
                repository = header.group(1)
                continue
            listed = re.match(r'^    - "?([^\s"]+)"?', line)
            if listed:
                repositories[listed.group(1)] = repository
        external: dict[str, dict[str, str]] = {}
        for section in ("EXTERNAL SOURCES", "CHECKOUT OPTIONS"):
            pod = ""
            for line in sections.get(section, []):
                header = re.match(r"^  \"?([^\":]+)\"?:$", line)
                if header:
                    pod = header.group(1)
                    continue
                option = re.match(r'^    :(\w+): "?([^"]+)"?$', line)
                if option and pod:
                    external.setdefault(pod, {})[option.group(1)] = option.group(2)
        checksums = {}
        for line in sections.get("SPEC CHECKSUMS", []):
            found_sum = re.match(r'^  "?([^\s":]+)"?: (\S+)$', line)
            if found_sum:
                checksums[found_sum.group(1)] = found_sum.group(2)
        entries: list[LockEntry] = []
        for name, slot in sorted(pods.items()):
            options = external.get(name, {})
            local = "path" in options
            resolved_from = None
            if "git" in options:
                reference = (
                    options.get("commit") or options.get("tag") or options.get("branch") or ""
                )
                resolved_from = f"git+{options['git']}#{reference}"
            elif "podspec" in options:
                resolved_from = options["podspec"]
            elif repositories.get(name) not in (
                None,
                "trunk",
                "https://github.com/CocoaPods/Specs.git",
            ):
                resolved_from = f"registry:{repositories[name]}"
            subspecs = sorted(slot["subspecs"])  # type: ignore[call-overload]
            checksum = checksums.get(name)
            entries.append(
                LockEntry(
                    name=name,
                    version=str(slot["version"]),
                    # SPEC CHECKSUMS: the SHA-1 of the podspec CocoaPods installed from.
                    integrity=f"sha1:{checksum}" if checksum and not local else None,
                    resolved_from=resolved_from,
                    direct=name in direct,
                    local=local,
                    dependencies=tuple(sorted(slot["edges"])),  # type: ignore[call-overload]
                    platform=tuple(f"subspec {s}" for s in subspecs),
                )
            )
        version = (sections.get("COCOAPODS") or [""])[0].strip()
        if version:
            entries.append(
                LockEntry(name="cocoapods", version=version, scope=Scope.TOOL, direct=True)
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class CocoaPodsEcosystem(BaseEcosystem):
    id = "cocoapods"
    purl_type = "cocoapods"
    manifest_globs: tuple[str, ...] = ("**/Podfile", "**/*.podspec")
    lockfile_globs: tuple[str, ...] = ("**/Podfile.lock",)
    registry_hosts: frozenset[str] = frozenset(
        {"cdn.cocoapods.org", "trunk.cocoapods.org", "github.com/CocoaPods/Specs"}
    )

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.basename.endswith((".podspec", ".podspec.json")):
            return Podspec.parse(content, self.id)
        return Podfile.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return PodfileLock.parse(content, self.id)


__all__ = ["CocoaPodsEcosystem", "PodName", "Podfile", "PodfileLock", "Podspec"]
