# Container image captures: Docker Hub library/hello-world (fetched 2026-11-27)

The real answers the image planner reads; `test_install_image.py` serves them through the real registry client.

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| config.json | https://registry-1.docker.io/v2/library/hello-world/blobs/sha256:e2ac70e7319a02c5a477f5825259bd118b94e8b02c279c67afa63adab6d8685b | none stated (registry metadata) | the product's own RegistryImage client with a generic User-Agent, no token; the config blob, digest-checked | e2ac70e7319a02c5a477f5825259bd118b94e8b02c279c67afa63adab6d8685b |
| index.json | https://registry-1.docker.io/v2/library/hello-world/manifests/latest | none stated (registry metadata) | the product's own RegistryImage client with a generic User-Agent, no token; the OCI index, as served | 1e4c05b897a751332ce85c7e9449da2d93514ea2dea6dbb0e2753c9e949b2bfa |
| layer.tar.gz | https://registry-1.docker.io/v2/library/hello-world/blobs/sha256:4f55086f7dd096d48b0e49be066971a8ed996521c2e190aa21b2435a847198b4 | MIT (docker-library/hello-world) | the product's own RegistryImage client with a generic User-Agent, no token; the only layer, digest-checked | 4f55086f7dd096d48b0e49be066971a8ed996521c2e190aa21b2435a847198b4 |
| manifest.json | https://registry-1.docker.io/v2/library/hello-world/manifests/sha256:d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e | none stated (registry metadata) | the product's own RegistryImage client with a generic User-Agent, no token; the linux/amd64 manifest, as served | d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e |
