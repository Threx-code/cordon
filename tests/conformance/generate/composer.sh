#!/bin/sh
# Regenerates the real-world Composer conformance case: Composer 2 resolves a project with require
# and require-dev, platform requirements, provide/replace/conflict, an inline alias, stability
# flags, a path repository, a VCS repository pinned to a branch, an allowed plugin, an abandoned
# package and lifecycle scripts. `composer show --locked --format=json` is the authoritative
# inventory. `--no-scripts --no-plugins --no-install`: nothing from any package runs.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" composer:2 sh /conformance/generate/composer.sh
set -eu
OUT=/conformance/cases/composer/real-application
rm -rf /tmp/c && mkdir -p /tmp/c/packages/acme-util && cd /tmp/c

cat > packages/acme-util/composer.json <<'EOF'
{
    "name": "acme/util",
    "description": "An internal package, required through a path repository.",
    "version": "1.2.0",
    "type": "library",
    "license": "MIT",
    "require": {"php": ">=8.1"},
    "autoload": {"psr-4": {"Acme\\Util\\": "src/"}}
}
EOF

cat > composer.json <<'EOF'
{
    "name": "acme/application",
    "description": "Conformance fixture.",
    "type": "project",
    "license": "proprietary",
    "minimum-stability": "dev",
    "prefer-stable": true,
    "repositories": [
        {"type": "path", "url": "packages/acme-util", "options": {"symlink": false}},
        {"type": "vcs", "url": "https://github.com/php-fig/clock"}
    ],
    "require": {
        "php": ">=8.1",
        "ext-json": "*",
        "ext-mbstring": "*",
        "monolog/monolog": "^3.7",
        "guzzlehttp/guzzle": "^7.9",
        "symfony/console": "6.4.*",
        "acme/util": "^1.2",
        "psr/clock": "dev-master as 1.0.0",
        "php-http/discovery": "^1.20",
        "swiftmailer/swiftmailer": "^6.3",
        "symfony/polyfill-ctype": "1.31.0 as 1.30.0"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.5",
        "phpstan/phpstan": "^1.12@stable"
    },
    "provide": {"psr/log-implementation": "3.0"},
    "replace": {"symfony/polyfill-php80": "*"},
    "conflict": {"monolog/monolog": "<3.0"},
    "config": {
        "allow-plugins": {"php-http/discovery": true},
        "platform": {"php": "8.2.0"}
    },
    "scripts": {
        "post-install-cmd": ["@php -r \"echo 'installed';\""],
        "test": "phpunit"
    }
}
EOF

composer update --no-install --no-scripts --no-plugins --no-interaction --quiet --ignore-platform-req=ext-*
composer show --locked --format=json > /tmp/shown.json

php -r '
$out = $argv[1];
if (is_dir($out)) {
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($out, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) {
        if ($f->getFilename() === "expect.yaml" && $f->getPath() === $out) continue;
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
}
@mkdir("$out/packages/acme-util", 0777, true);
copy("composer.json", "$out/composer.json");
copy("composer.lock", "$out/composer.lock");
copy("packages/acme-util/composer.json", "$out/packages/acme-util/composer.json");
$shown = json_decode(file_get_contents("/tmp/shown.json"), true);
$truth = [];
// `composer show` appends the commit to a branch version (`dev-master fb246b4`); the version
// is the first word, as the lock records it.
foreach ($shown["locked"] as $p) { $truth[] = $p["name"] . "@" . explode(" ", $p["version"])[0]; }
sort($truth);
file_put_contents("$out/authoritative.json", json_encode([
    "tool" => "composer show --locked --format=json",
    "packages" => $truth,
    "ignore" => ["acme/util" => "a path repository package: the project'"'"'s own code, read as source"],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "locked ", count($truth), "\n";
' "$OUT"
php -r '$l = json_decode(file_get_contents("composer.lock"), true); echo json_encode(["aliases" => $l["aliases"], "stability" => $l["stability-flags"], "platform" => $l["platform"], "abandoned" => array_values(array_filter(array_map(fn($p) => isset($p["abandoned"]) ? [$p["name"], $p["abandoned"]] : null, $l["packages"])))], JSON_PRETTY_PRINT), "\n";'
echo done
