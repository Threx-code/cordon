ARG BASE=debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM --platform=$BUILDPLATFORM golang:1.23 AS builder
RUN go build -o /out/app ./cmd/app

FROM builder AS test
RUN go test ./...

FROM ${BASE}
COPY --from=builder /out/app /usr/local/bin/app
