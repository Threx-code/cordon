# package_format_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| bazel-source.json | https://bcr.bazel.build/modules/abseil-cpp/20240116.2/source.json | Apache-2.0 (Bazel Central Registry) | curl with a generic User-Agent, kept as served | 750d5e29326fb59cbe61116a7b803c8a1d0a7090a9c8ed89888d188e3c473fc7 |
| cocoapods-podspec.json | https://cdn.jsdelivr.net/cocoa/Specs/d/a/2/Alamofire/5.8.0/Alamofire.podspec.json | MIT (Alamofire) | curl with a generic User-Agent, kept as served | c97f1469d1025d0c23d9b72f16c5e344a0f31966ed38af060ec59b18ce4d60a6 |
| helm-chart-hello-world.tgz | the Helm project's hello-world-0.1.0.tgz chart, a GitHub release asset | Apache-2.0 (helm) | curl with a generic User-Agent, kept as served | 5365e3344584f36fd0dca6c1bd92dc9176ed8ec5ee8146cae8a76a4f990271c3 |
| members.json | the member names of public archives: a Helm chart, a pub.dev package, a Homebrew bottle (first 4 KB), a VS Code extension, a Terraform provider zip, a Packagist dist, a GitHub Action tarball, an opam archive, an Ansible collection, a Julia package, a saved Docker image, a Conan revision, a Swift package archive (each key names its source and sha256) | member names only, no package content (the packages carry their own licences: MIT, Apache-2.0, BSD, MPL-2.0) | run on the host over archives read in place (no archive extracted or kept): `make_format_fixtures.py` | e9b7401ca96cb93e3f5295f4fb2750a34a2ab001116e655ad1bf0a560eef6f4d |
| nix-hello.nar.head | the first 256 bytes of the NAR of GNU hello 2.12.3 (https://cache.nixos.org/nar/1y5kxwvk55lwqfb1qrb8v5ap2kx638w1m65vh80gi9xp8ad4y0cr.nar.zst) | GPL-3.0 (GNU hello); the first 256 bytes only | curl, then `zstd -dc` and the first 256 bytes | debe1c5143dbd708ba8a68e523ae08f4eef7cf0abd66fee2d9c40cb3b4908634 |
| terraform-module-download-headers.txt | response headers of https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/5.8.1/download | none (HTTP headers) | curl -D, body discarded | 412112bbf66d02e80d87a07ea0f0c1b568454be4ee6149cd6f55e30cf62fee0f |
| vcpkg-portfile.cmake | https://raw.githubusercontent.com/microsoft/vcpkg/master/ports/zlib/portfile.cmake | MIT (vcpkg) | curl with a generic User-Agent, kept as served | bd7997a01c9eb49d6ed4fb2e5fc331a2700556145e66e8c9ca2b1f1e44d1ac84 |
