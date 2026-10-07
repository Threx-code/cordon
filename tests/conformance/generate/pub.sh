#!/bin/sh
# Regenerates the real-world Pub conformance case: `dart pub get` resolves a pub workspace (root
# `workspace:`, members with `resolution: workspace`), hosted and git dependencies, a path
# dependency between members, dev dependencies, a dependency override and SDK constraints.
# `dart pub deps --json` is the authoritative inventory. No package code runs.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" dart:stable sh /conformance/generate/pub.sh
set -eu
OUT=/conformance/cases/pub/real-workspace
rm -rf /tmp/p && mkdir -p /tmp/p/packages/app/lib /tmp/p/packages/core/lib && cd /tmp/p

cat > pubspec.yaml <<'EOF'
name: conformance_workspace
publish_to: none
environment:
  sdk: ^3.6.0
workspace:
  - packages/app
  - packages/core
dev_dependencies:
  lints: ^5.1.0
EOF

cat > packages/core/pubspec.yaml <<'EOF'
name: core
version: 0.1.0
publish_to: none
resolution: workspace
environment:
  sdk: ^3.6.0
dependencies:
  collection: ^1.19.0
  meta: ^1.15.0
EOF

cat > packages/app/pubspec.yaml <<'EOF'
name: app
version: 1.0.0
publish_to: none
resolution: workspace
environment:
  sdk: ^3.6.0
dependencies:
  core:
    path: ../core
  http: ^1.2.2
  path: ^1.9.0
  characters:
    git:
      url: https://github.com/dart-lang/core.git
      path: pkgs/characters
      ref: characters-v1.4.0
dev_dependencies:
  test: ^1.25.0
dependency_overrides:
  meta: 1.16.0
EOF

dart pub get >/dev/null
dart pub deps --json > /tmp/deps.json

rm -rf "$OUT" && mkdir -p "$OUT/packages/app" "$OUT/packages/core" "$OUT/.dart_tool"
cp pubspec.yaml pubspec.lock "$OUT/"
cp packages/app/pubspec.yaml "$OUT/packages/app/" && cp packages/core/pubspec.yaml "$OUT/packages/core/"
cp .dart_tool/package_config.json "$OUT/.dart_tool/"

cat > /tmp/authoritative.dart <<'EOF'
import 'dart:convert';
import 'dart:io';

void main(List<String> args) {
  final deps = jsonDecode(File('/tmp/deps.json').readAsStringSync()) as Map<String, dynamic>;
  final own = {'conformance_workspace', 'app', 'core'};
  final packages = <String>{};
  for (final p in (deps['packages'] as List).cast<Map<String, dynamic>>()) {
    final name = p['name'] as String;
    if (own.contains(name) || p['source'] == 'root') continue;
    packages.add('$name@${p['version']}');
  }
  final sorted = packages.toList()..sort();
  final out = {
    'tool': 'dart pub deps --json (Dart ${Platform.version.split(' ').first})',
    'packages': sorted,
  };
  File('${args[0]}/authoritative.json').writeAsStringSync(const JsonEncoder.withIndent(' ').convert(out));
  print('listed ${sorted.length}');
}
EOF
dart run /tmp/authoritative.dart "$OUT"
grep -n "dependency:\|source:" pubspec.lock | sort | uniq -c | sort -rn | head
sed -n '1,12p' pubspec.lock
echo done
