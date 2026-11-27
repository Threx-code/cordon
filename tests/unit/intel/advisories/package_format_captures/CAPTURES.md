# Where each fixture here came from

Real, published, legitimately licensed files, or exact extracts of them (a member list, the first bytes, the headers).
`members.json` holds each archive's member list with that archive's own source and sha256 per entry.

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| members.json | the archives each entry names (codeload, Galaxy, Homebrew bottles, Packagist, ConanCenter, Helm, docker save, Pkg server, opam cache, pub.dev, swift archive-source, HashiCorp releases, Open VSX) | each entry's own (MIT, Apache-2.0, BSD and the like) | member names only, read without extracting | e9b7401ca96cb93e3f5295f4fb2750a34a2ab001116e655ad1bf0a560eef6f4d |
| bazel-source.json | https://bcr.bazel.build (a module's source.json) | Apache-2.0 (Bazel Central Registry) | as served | 750d5e29326fb59cbe61116a7b803c8a1d0a7090a9c8ed89888d188e3c473fc7 |
| cocoapods-podspec.json | https://cdn.cocoapods.org (a trunk podspec) | MIT (CocoaPods Specs) | as served | c97f1469d1025d0c23d9b72f16c5e344a0f31966ed38af060ec59b18ce4d60a6 |
| helm-chart-hello-world.tgz | a Helm chart repository's hello-world chart | Apache-2.0 | as served | 5365e3344584f36fd0dca6c1bd92dc9176ed8ec5ee8146cae8a76a4f990271c3 |
| nix-hello.nar.head | https://cache.nixos.org/nar/1y5kxwvk55lwqfb1qrb8v5ap2kx638w1m65vh80gi9xp8ad4y0cr.nar.zst | GPL-3.0 (GNU hello) | the first 256 bytes of the NAR only | debe1c5143dbd708ba8a68e523ae08f4eef7cf0abd66fee2d9c40cb3b4908634 |
| terraform-module-download-headers.txt | https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/5.8.1/download | Apache-2.0 (terraform-aws-vpc) | response headers only | 412112bbf66d02e80d87a07ea0f0c1b568454be4ee6149cd6f55e30cf62fee0f |
| vcpkg-portfile.cmake | https://raw.githubusercontent.com/microsoft/vcpkg/master/ports/zlib/portfile.cmake | MIT (vcpkg) | as served | bd7997a01c9eb49d6ed4fb2e5fc331a2700556145e66e8c9ca2b1f1e44d1ac84 |
