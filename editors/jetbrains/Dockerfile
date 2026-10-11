# Builds, tests and verifies the plugin: `docker build -f editors/jetbrains/Dockerfile -o out editors/jetbrains`.
# JetBrains' Plugin Verifier checks it against the oldest and newest IDEs it claims (build.gradle.kts).
FROM eclipse-temurin:21-jdk@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b AS build
ARG GRADLE=9.8.1
ARG GRADLE_SHA256=dce76f55f8e251a3a1f130eb120f30b3d271de2b76c9b0729d316b5a1b6dc01f
RUN curl -fsSL -o /tmp/gradle.zip https://services.gradle.org/distributions/gradle-${GRADLE}-bin.zip \
 && echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum -c - \
 && cd /opt && jar xf /tmp/gradle.zip && chmod +x /opt/gradle-${GRADLE}/bin/gradle && rm /tmp/gradle.zip
WORKDIR /build
COPY . .
RUN /opt/gradle-${GRADLE}/bin/gradle --no-daemon -q test buildPlugin verifyPlugin

FROM scratch
COPY --from=build /build/build/distributions/ /
COPY --from=build /build/build/reports/pluginVerifier/ /verifier/
