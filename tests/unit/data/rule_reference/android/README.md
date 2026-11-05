# Two signed Android packages, read by Google's tools

`full.apk` and `edge.apk` are Cordon's own packages: the manifests, resource tables and dex are written
by `tests/kits/androidkit.py` (`scripts/reference/build_android_fixtures.py`), with no third-party
bytes, and signed by apksigner with a throwaway key made for them (not kept). They hold the androguard
module's values to Android build-tools 35.0.0 (aapt2 2.19, apksigner 0.9) in the reference image
`cordon-android-ref:1`, recorded once on 2026-10-31:

    keytool -genkeypair -keystore test.jks -alias fx -keyalg RSA -keysize 2048 -validity 36500 \
        -dname "CN=Cordon Test, OU=QA, O=Cordon, L=London, ST=England, C=GB"
    apksigner sign --ks test.jks --v1-signing-enabled true --v2-signing-enabled true \
        --v3-signing-enabled false --min-sdk-version 21 --out full.apk full-unsigned.apk
    apksigner sign --ks test.jks --v1-signing-enabled false --v2-signing-enabled true \
        --v3-signing-enabled false --min-sdk-version 24 --out edge.apk edge-unsigned.apk
    aapt2 dump badging X.apk > X.badging.txt
    aapt2 dump xmltree --file AndroidManifest.xml X.apk > X.xmltree.txt
    apksigner verify -v --print-certs [--min-sdk-version 24] X.apk > X.certs.txt

| file | signed | bytes | sha256 |
|---|---|---|---|
| `full.apk` | v1 (META-INF/FX.RSA) and v2 | 12679 | 7f773da2943f67beaa3b0d7db56fab3ba0c31cd76b1818a69413a5db76b8c6e5 |
| `edge.apk` | v2 only | 8339 | ef6bd66aa93211bc249ab098bdd6db2dafad23c9eccaa4086b611af8460ffe73 |

`full.apk` has every value the module reads: SDK levels, two requested and one declared permission, an
`@string` label, a launcher activity named `.Main`, an activity named without a dot, an alias, a
service, a receiver, and two URLs in the dex. `edge.apk` has no `uses-sdk`, a plain-text label, and a
disabled launcher activity before an enabled one.
