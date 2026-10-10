# Homebrew's own Dockerfile names its base `ubuntu:"${version}"`: BuildKit removes the quotes.
ARG version=24.04
FROM ubuntu:"${version}" AS build
FROM 'alpine':3.20
COPY --from="build" /out /out
