#!/bin/sh
# Regenerates the real-world Gradle conformance case: Gradle resolves a multi-project build (Groovy
# and Kotlin DSLs, a version catalog, a platform, constraints, a dynamic version, a classifier, a
# strict version, an exclusion, a composite build and a plugin), writes its own lockfiles and
# verification metadata, and an init script records what it resolved per configuration as the
# authoritative inventory -- read from Gradle's resolution result, not from the lockfiles.
# No project code is compiled or run. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" gradle:8.10.2-jdk21 sh /conformance/generate/gradle.sh
set -eu
OUT=/conformance/cases/gradle/real-multiproject
rm -rf /tmp/g && mkdir -p /tmp/g/gradle /tmp/g/lib /tmp/g/app /tmp/g/shared && cd /tmp/g

cat > settings.gradle.kts <<'EOF'
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "conformance"
include(":app", ":lib")
includeBuild("shared")
EOF

cat > build.gradle.kts <<'EOF'
plugins {
    alias(libs.plugins.versions)
}

buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}
EOF

cat > gradle/libs.versions.toml <<'EOF'
[versions]
guava = "33.3.1-jre"
jackson = "2.18.0"

[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
jackson-databind = { group = "com.fasterxml.jackson.core", name = "jackson-databind" }
jackson-bom = { module = "com.fasterxml.jackson:jackson-bom", version.ref = "jackson" }
commons-text = "org.apache.commons:commons-text:1.12.0"
junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version = "5.11.3" }
unused-library = "org.example.unused:never-referenced:9.9.9"

[bundles]
jackson = ["jackson-databind"]

[plugins]
versions = { id = "com.github.ben-manes.versions", version = "0.51.0" }
EOF

cat > lib/build.gradle <<'EOF'
plugins {
    id 'java-library'
}

dependencyLocking {
    lockAllConfigurations()
}

def slf4jVersion = '2.0.16'

dependencies {
    api libs.guava
    implementation platform(libs.jackson.bom)
    implementation libs.bundles.jackson
    implementation "org.slf4j:slf4j-api:${slf4jVersion}"
    implementation(group: 'org.apache.httpcomponents', name: 'httpclient', version: '4.5.14') {
        exclude group: 'commons-logging', module: 'commons-logging'
    }
    implementation 'org.yaml:snakeyaml:2.+'
    compileOnly 'org.projectlombok:lombok:1.18.34'
    annotationProcessor 'org.projectlombok:lombok:1.18.34'
    runtimeOnly 'com.h2database:h2:2.3.232'
    testImplementation libs.junit.jupiter
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher:1.11.3'

    constraints {
        implementation('commons-codec:commons-codec:1.17.1') {
            because 'httpclient 4.5.14 brings 1.11'
        }
    }
}
EOF

cat > app/build.gradle.kts <<'EOF'
plugins {
    application
}

dependencyLocking {
    lockAllConfigurations()
}

val nettyClassifier = "linux-x86_64"

dependencies {
    implementation(project(":lib"))
    implementation(libs.commons.text)
    implementation("com.example.shared:shared-util:1.0.0")
    implementation("io.netty:netty-transport-native-epoll:4.1.114.Final:$nettyClassifier")
    implementation("org.apache.commons:commons-lang3") {
        version {
            strictly("3.17.0")
        }
    }
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.3")
}

application {
    mainClass.set("app.Main")
}
EOF

cat > shared/settings.gradle.kts <<'EOF'
rootProject.name = "shared-util"
EOF
cat > shared/build.gradle.kts <<'EOF'
plugins {
    `java-library`
}

group = "com.example.shared"
version = "1.0.0"
EOF

cat > /tmp/cordon.init.gradle <<'EOF'
allprojects {
    tasks.register("resolveAndLockAll") {
        notCompatibleWithConfigurationCache("resolves configurations at execution")
        doLast {
            project.configurations.findAll { it.canBeResolved }.each { it.resolve() }
            project.buildscript.configurations.findAll { it.canBeResolved }.each { it.resolve() }
        }
    }
    tasks.register("cordonResolved") {
        notCompatibleWithConfigurationCache("reads the resolution result")
        doLast {
            def out = new File("/tmp/resolved-${project.name}.txt")
            out.text = ""
            project.configurations.findAll { it.canBeResolved }.each { c ->
                c.incoming.resolutionResult.allComponents.each { comp ->
                    def id = comp.id
                    if (id instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
                        out << "${c.name} ${id.group}:${id.module}@${id.version}\n"
                    }
                }
            }
        }
    }
}
EOF

gradle -q wrapper --gradle-version 8.10.2 >/dev/null 2>&1
gradle -q --init-script /tmp/cordon.init.gradle --write-locks --write-verification-metadata sha256 resolveAndLockAll
gradle -q --init-script /tmp/cordon.init.gradle cordonResolved

command -v python3 >/dev/null || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1; }
python3 - "$OUT" <<'PY'
import json, os, shutil, sys
out = sys.argv[1]
if os.path.isdir(out):
    for name in os.listdir(out):
        if name not in ("expect.yaml", "README.md"):
            path = os.path.join(out, name)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
os.makedirs(out, exist_ok=True)
keep = [
    "settings.gradle.kts", "build.gradle.kts", "gradle/libs.versions.toml", "gradle/verification-metadata.xml",
    "gradle/wrapper/gradle-wrapper.properties", "lib/build.gradle", "app/build.gradle.kts",
    "shared/settings.gradle.kts", "shared/build.gradle.kts",
    "gradle.lockfile", "buildscript-gradle.lockfile", "lib/gradle.lockfile", "app/gradle.lockfile",
]
for relative in keep:
    if os.path.exists(relative):
        os.makedirs(os.path.dirname(os.path.join(out, relative)) or out, exist_ok=True)
        shutil.copy(relative, os.path.join(out, relative))
truth = set()
by_configuration = {}
for project in ("lib", "app"):
    for line in open(f"/tmp/resolved-{project}.txt"):
        configuration, coordinate = line.split()
        if coordinate.startswith("com.example.shared:"):
            continue
        truth.add(coordinate)
        by_configuration.setdefault(coordinate, set()).add(f"{project}:{configuration}")
document = {
    "tool": "Gradle's resolution result for every resolvable configuration of :lib and :app",
    "packages": sorted(truth),
    "exclude": {"dependency_type": {"tool": "the root build's plugin classpath is not a project configuration"}},
    "configurations": {k: sorted(v) for k, v in sorted(by_configuration.items())},
}
json.dump(document, open(os.path.join(out, "authoritative.json"), "w"), indent=1)
print("resolved", len(truth))
PY
ls -R "$OUT" | head -40
head -20 lib/gradle.lockfile
echo done
