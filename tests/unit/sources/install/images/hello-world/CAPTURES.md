# hello-world captures

Real responses from Docker Hub (`registry-1.docker.io`, repository `library/hello-world`) on 2026-11-27, fetched with the
product's own `RegistryImage` and a generic agent:

- `index.json`: the OCI image index for tag `latest` (20 platform manifests, attestations included).
- `manifest.json`: the `linux/amd64` manifest, digest `sha256:d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e`.
- `config.json`: its config blob (577 bytes).
- `layer.tar.gz`: its only layer (2,415 bytes).

Nothing is edited. The tests serve these through the real registry client.
