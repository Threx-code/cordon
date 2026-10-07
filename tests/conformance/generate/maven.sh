#!/bin/sh
# Regenerates the real-world Maven conformance cases: Maven resolves a multi-module build, and its
# own dependency:tree / dependency:list output is kept -- as the authoritative inventory, and in
# one case as the effective-graph file a project can supply. Nothing is compiled or run.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" maven:3.9-eclipse-temurin-21 sh /conformance/generate/maven.sh
set -eu
OUT=/conformance/cases/maven
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1 || true
rm -rf /tmp/m && mkdir -p /tmp/m/core /tmp/m/app && cd /tmp/m

cat > pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.conformance</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>core</module>
    <module>app</module>
  </modules>
  <properties>
    <guava.version>33.3.1-jre</guava.version>
    <maven.compiler.release>21</maven.compiler.release>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>2.18.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-lang3</artifactId>
        <version>3.17.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-enforcer-plugin</artifactId>
        <version>3.5.0</version>
      </plugin>
    </plugins>
  </build>
  <profiles>
    <profile>
      <id>metrics</id>
      <activation><property><name>metrics</name></property></activation>
      <dependencies>
        <dependency>
          <groupId>io.micrometer</groupId>
          <artifactId>micrometer-core</artifactId>
          <version>1.13.6</version>
        </dependency>
      </dependencies>
    </profile>
  </profiles>
</project>
EOF

cat > core/pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example.conformance</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>core</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.16</version>
      <optional>true</optional>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-transport-native-epoll</artifactId>
      <version>4.1.114.Final</version>
      <classifier>linux-x86_64</classifier>
    </dependency>
    <dependency>
      <groupId>org.apache.httpcomponents</groupId>
      <artifactId>httpclient</artifactId>
      <version>4.5.14</version>
      <exclusions>
        <exclusion>
          <groupId>commons-logging</groupId>
          <artifactId>commons-logging</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>javax.servlet-api</artifactId>
      <version>4.0.1</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>[2.0,2.3)</version>
    </dependency>
  </dependencies>
</project>
EOF

cat > app/pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example.conformance</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.example.conformance</groupId>
      <artifactId>core</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <version>2.3.232</version>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
</project>
EOF

# The Maven wrapper, as `mvn wrapper:wrapper` writes it, with the distribution's checksum.
mvn -q -N wrapper:wrapper -Dmaven=3.9.9 >/dev/null 2>&1 || true

mvn -q -B install -DskipTests -Dmaven.main.skip -Dmaven.test.skip=true -Denforcer.skip >/dev/null 2>&1 || true
for m in core app; do
  (cd $m && mvn -q -B dependency:tree -Dscope=test -DoutputFile=dependency-tree.txt -DappendOutput=false >/dev/null 2>&1)
  (cd $m && mvn -q -B dependency:list -DincludeScope=test -DoutputFile=list.txt -DexcludeTransitive=false >/dev/null 2>&1)
done
# Maven Resolver's trusted checksums: the SHA-256 of every artefact the build resolved, recorded
# by Maven itself into .mvn/checksums/ for a project to commit and verify against.
mvn -q -B dependency:resolve \
  -Daether.artifactResolver.postProcessor.trustedChecksums=true \
  -Daether.artifactResolver.postProcessor.trustedChecksums.record=true \
  -Daether.trustedChecksumsSource.summaryFile=true \
  -Daether.trustedChecksumsSource.summaryFile.basedir=/tmp/m/.mvn/checksums \
  -Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256 >/dev/null 2>&1

python3 - "$OUT" <<'PY'
import json, os, re, sys, shutil
out = sys.argv[1]
def listed(path):
    found = set()
    for line in open(path):
        m = re.match(r"\s+([\w.\-]+):([\w.\-]+):[\w.\-]+(?::[\w.\-]+)?:([\w.\-\[\]\(\),]+):\w+", line)
        if m and not m.group(1).startswith("com.example.conformance"):
            found.add(f"{m.group(1)}:{m.group(2)}@{m.group(3)}")
    return found
def direct(tree):
    found = set()
    for line in list(open(tree))[1:]:
        m = re.match(r"^[+\\]- ([\w.\-]+):([\w.\-]+):[\w.\-]+(?::[\w.\-]+)?:([\w.\-]+):\w+", line)
        if m and not m.group(1).startswith("com.example.conformance"):
            found.add(f"{m.group(1)}:{m.group(2)}@{m.group(3)}")
    return found
# Case 1: the POMs alone. Offline, only what they declare can be known: Maven's direct
# dependencies of each module are the authoritative set.
case = os.path.join(out, "real-multimodule")
for d in ("core", "app", ".mvn/wrapper"):
    os.makedirs(os.path.join(case, d), exist_ok=True)
shutil.copy("pom.xml", case)
for m in ("core", "app"):
    shutil.copy(f"{m}/pom.xml", os.path.join(case, m))
if os.path.exists(".mvn/wrapper/maven-wrapper.properties"):
    shutil.copy(".mvn/wrapper/maven-wrapper.properties", os.path.join(case, ".mvn/wrapper"))
truth = sorted(direct("core/dependency-tree.txt") | direct("app/dependency-tree.txt"))
excluded = {
    "dependency_type": {"tool": "build plugins and the Maven distribution are not in dependency:tree"},
    "condition_prefix": {"profile ": "a dependency in a profile that is not active is not in dependency:tree"},
}
ignore = {
    "com.fasterxml.jackson.core:jackson-databind": "its version comes from jackson-bom, an imported BOM served by Maven Central: offline, the POMs alone cannot say which version, and the scan reports it unresolved with that reason",
    "org.yaml:snakeyaml": "declared as the range [2.0,2.3): which release Maven picks depends on the repository's metadata on the day, and the scan reports it unresolved with that reason",
}
json.dump({"tool": "mvn dependency:tree, direct dependencies of each module", "packages": truth, "exclude": excluded, "ignore": ignore}, open(os.path.join(case, "authoritative.json"), "w"), indent=1)
# Case 2: the same build with the effective graph supplied (dependency:tree output), checked
# against dependency:list, Maven's own flat listing of the resolution.
case = os.path.join(out, "real-effective-graph")
for d in ("core", "app", ".mvn/checksums"):
    os.makedirs(os.path.join(case, d), exist_ok=True)
shutil.copy("pom.xml", case)
shutil.copy(".mvn/checksums/checksums-central.sha256", os.path.join(case, ".mvn/checksums"))
for m in ("core", "app"):
    shutil.copy(f"{m}/pom.xml", os.path.join(case, m))
    shutil.copy(f"{m}/dependency-tree.txt", os.path.join(case, m))
truth = sorted(listed("core/list.txt") | listed("app/list.txt"))
json.dump({"tool": "mvn dependency:list -DincludeScope=test", "packages": truth, "exclude": excluded}, open(os.path.join(case, "authoritative.json"), "w"), indent=1)
print("direct", len(direct("core/dependency-tree.txt")), "listed", len(truth))
PY
head -12 core/dependency-tree.txt
cat .mvn/wrapper/maven-wrapper.properties 2>/dev/null | head -5
echo done
