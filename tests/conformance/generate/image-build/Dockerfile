# syntax=docker/dockerfile:1
# The image behind cases/image/real-saved-image: a real build whose last stage is assembled FROM
# scratch, as distroless images are -- a package database and the files that matter, kept small
# enough to commit. Built and saved by generate/image_build.sh.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY main.go ./
RUN go mod init example.com/hello \
 && go get github.com/google/uuid@v1.6.0 \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hello .

FROM alpine:3.20 AS packages
RUN apk add --no-cache jq

FROM python:3.12-alpine AS python
RUN pip install --no-cache-dir --no-compile --target /site six==1.16.0

FROM scratch
COPY --from=packages /etc/os-release /etc/os-release
COPY --from=packages /etc/apk/world /etc/apk/world
COPY --from=packages /lib/apk/db/installed /lib/apk/db/installed
COPY --from=build /out/hello /usr/local/bin/hello
COPY --from=python /site/six-1.16.0.dist-info /usr/lib/python3.12/site-packages/six-1.16.0.dist-info
LABEL org.opencontainers.image.source="https://github.com/acme/hello" \
      org.opencontainers.image.revision="0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5"
USER 65532
ENTRYPOINT ["/usr/local/bin/hello"]
