# Builds, tests and verifies the plugin: `docker build -f editors/jetbrains/Dockerfile -o out editors/jetbrains`.
# JetBrains' Plugin Verifier checks it against the oldest and newest IDEs it claims (build.gradle.kts).
# The official Gradle 9.8.1 image on JDK 21, pinned by digest: nothing is downloaded and run here.
FROM gradle:9.8.1-jdk21@sha256:d5c815d1281e3edc7e986ca573b1b309639747fa0d91a2199adadf327cfdf634 AS build
WORKDIR /build
COPY . .
RUN gradle --no-daemon -q test buildPlugin verifyPlugin

FROM scratch
COPY --from=build /build/build/distributions/ /
COPY --from=build /build/build/reports/pluginVerifier/ /verifier/
