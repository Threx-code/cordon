# vcpkg captures (real files, taken 2026-11-28)

The files of eight ports of github.com/microsoft/vcpkg (MIT) at commit 99541cc939bf01ae3c42f928266d648f5acb88fd, copied byte for byte from a full clone of that repository (`git clone` of https://github.com/microsoft/vcpkg, HEAD of 2026-11-27, checked out at that commit); nothing was edited. `.gitattributes` marks `*_captures` folders binary.

- zlib: `vcpkg_from_github` with `REF v${VERSION}` and a SHA512: the plain case
- libpng: depends on zlib and three host ports (one for a platform); a `vcpkg_download_distfile` under an `apng` feature whose URL and file name use `set()` variables
- vcpkg-cmake, vcpkg-cmake-config, vcpkg-cmake-get-vars: host ports with no download
- cmocka: `vcpkg_from_gitlab`: refused
- aom: `vcpkg_from_git`: refused
- acl: `vcpkg_download_distfile` with no `vcpkg_from_*`

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| ports/zlib/0001-no-version-script-on-ohos.patch | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | eceb3e71d44c6febd2ff1d6877116b7f3f1da2fd346c8c300e8cdac8d142fd57 |
| ports/zlib/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | bd7997a01c9eb49d6ed4fb2e5fc331a2700556145e66e8c9ca2b1f1e44d1ac84 |
| ports/zlib/usage | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 2fdbc95707f61d7f468ece88e460b1bcc22713af34978c7a1b80b689fc39cb67 |
| ports/zlib/vcpkg-cmake-wrapper.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | c05300341bb682e1621097822d1f411440ac530d39834a57cb7615390ba54326 |
| ports/zlib/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 4c025f3c6566dbfd6a1e81957f8f00cf653c6c4f55f5a42438ed8d939bd9a8ce |
| ports/libpng/cmake.patch | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | e1c91b1739580791b8bfe770981cdb07bf65261caf6b2a99da988a8bb21d4094 |
| ports/libpng/genout-compiler-target.patch | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 7b20258aff72f40220cf5d759c4adf69341bf050e599db5fb39ea3ea2794a349 |
| ports/libpng/libpng-config.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 24086e8ff194402a0f2d68e9f992ca7a6899a194883a9df0054818e42d41c246 |
| ports/libpng/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | c6ab8741c8ecdb986b8686f4f8fdf4a1fa1dc091e79f175eec5888d4479aded9 |
| ports/libpng/usage | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 78d7cf48b6a62ad52b10cb5f2134b2f6b61128c08802e10092020e28fb992542 |
| ports/libpng/vcpkg-cmake-wrapper.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 4267e69abf185f2228a4cc012e3fe87d5de21a187c75950b5a7615f41c3f6371 |
| ports/libpng/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | d358c9072e8cc8cc5e985abbd5a4c5211cf74af37560f9aba61837af85e3f120 |
| ports/vcpkg-cmake/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | a711531b7f13b7da16fa1f25d7c5737a423d4a126465dc9e6689a0f043fcc1aa |
| ports/vcpkg-cmake/vcpkg-port-config.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | f0a30f77c8f5e3ac40436fe2518a61ad067f2955c7ef3be6d6a0ca4b81cd2a45 |
| ports/vcpkg-cmake/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 8440a1df2b85bf8fa426a62666392bb1bbd6e1d80b54c8adc74bc32b99c35ece |
| ports/vcpkg-cmake/vcpkg_cmake_build.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | fa16767e49103c845a02f4ac6d7ba331be3180e19e8f4157a12e9cd22123cf7c |
| ports/vcpkg-cmake/vcpkg_cmake_configure.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 2ccf0cddce8fd52ce1d5ed8b2323c53bfda69e4aecd2d6d62fad6bdcf06c2319 |
| ports/vcpkg-cmake/vcpkg_cmake_install.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 3ae7886dc8434fac6f1e61190cc355fdec5fbd4f60758e2de20423cf49c91369 |
| ports/vcpkg-cmake-config/copyright | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 04b60f99a43bfd7fefdc8364b24aac704a2160cef969b75ba6a38b62dc4c4b70 |
| ports/vcpkg-cmake-config/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 832b34e63f5af41ad1b2e4aa79c5bfa507a005b120b51548e674accc706837d7 |
| ports/vcpkg-cmake-config/vcpkg-port-config.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 72bc3093337e633bdd19fe5d4dd1f38ca1918def49608d676a9c98c686d38b1e |
| ports/vcpkg-cmake-config/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 480420178eb38f67a7825d5e6776776ea072bcd14b1839e0f495344a529d9f58 |
| ports/vcpkg-cmake-config/vcpkg_cmake_config_fixup.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 4866f6e995abcde8f9d7add69a3206205158119dbd0547be13076ae3c1456f6b |
| ports/vcpkg-cmake-get-vars/cmake-get-vars.cmake.in | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 2c9f7cdefba85c7a6df2e881888681e85fb4ab7593f1647ea9897d5c1df3ce66 |
| ports/vcpkg-cmake-get-vars/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 0a6c61926f6d1af5ed6e02b8df4dd8df81d3988a263c2849a38cef364e290e81 |
| ports/vcpkg-cmake-get-vars/vcpkg-port-config.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 4fd4c2e909bbdf069eb3c59b4b847b0b386cdb41840714e12b34b7eff41f9e22 |
| ports/vcpkg-cmake-get-vars/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | c63654032f0c0f79ffc9932cfade8a13d68fc607e823d3ea17cc4d24b4e76bac |
| ports/vcpkg-cmake-get-vars/vcpkg_cmake_get_vars.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | f80132758a6a7d0930697814c0fd2b719a06ee092bf60fab96d3d9cfef0e4c2b |
| ports/cmocka/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 74aa75b489dfe09a6576cb42680f7ac4512ce9594128c7df0dd4a26aa70f3f76 |
| ports/cmocka/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 28764a68d237f1ed37e10f304f0526cd43db8b0fc821eb58e9c2be1ce9934fa1 |
| ports/aom/aom-rename-static.diff | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 9bdf835bdf1a4a27ce4f41c4c84898d88d8aa12f341d014e5033d48ade232a9e |
| ports/aom/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | 193fe3aed9ac805afec2ef8ec75af23fb102437fd44fd9e7b72ba4c7665e1a7d |
| ports/aom/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | b4d7718f825fe4d5f729c720323d8de3eecaa6f5880148bb2791cb79480965a5 |
| ports/acl/portfile.cmake | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | e7f2e0504d6ec2e4eebd687386c7122687fdfe61e0bdb9e4676b11a549bf58c0 |
| ports/acl/vcpkg.json | github.com/microsoft/vcpkg at 99541cc939bf | MIT | copied byte for byte from a clone at that commit | b6dc27ab4c1c8737125b3868a00e7fa0a7d6c5c58ef0bce77dd366e8a5fc6623 |
