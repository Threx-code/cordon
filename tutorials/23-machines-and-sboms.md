# 23 · Machines and vendor SBOMs

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Not everything you run lives in a repository. A laptop or a CI runner has packages
installed outside any project, and software bought from a vendor arrives as a bill of
materials rather than source. Both are checked against the same intel as your code.

## A machine

```
   cordon-scanner scan --host /                       # the system
   cordon-scanner scan --host / --home "$HOME"        # and this user's own installs
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│  THE DISTRIBUTION                                                        │
│    dpkg · apk · rpm (sqlite and the legacy Berkeley DB) · pacman ·       │
│    portage                                                               │
│                                                                          │
│  LANGUAGE PACKAGES INSTALLED OUTSIDE ANY PROJECT                         │
│    Python    system, /usr/local, per-user site-packages, pipx            │
│    npm       the global node_modules                                     │
│    Ruby      gem specifications                                          │
│    Cargo     cargo install's record                                      │
│    Go        binaries in ~/go/bin, read for their build information      │
│    Homebrew  the Cellar                                                  │
│                                                                          │
│  THE RUNTIMES THEMSELVES                                                 │
│    Python, Node.js, Go, OpenJDK, Ruby, from the version files they ship  │
└──────────────────────────────────────────────────────────────────────────┘
```

Read from the metadata each installer leaves, with the same readers as a container
image, so a package is identified the same way on a machine and in an image. Nothing
is run: no `dpkg -l`, no `pip list`. The read is bounded by files, bytes and depth.

## A container image

The same readers, layer by layer, from a saved image:

```
   docker save app:1.4 -o app.tar
   cordon-scanner scan app.tar
```

OS packages from the final layer's database after whiteouts, runtimes, language
packages, jars, Go binaries, and the application's own files. Nothing in the image is
run. Measured against Syft on real images: [docs/08-ACCURACY.md](../docs/08-ACCURACY.md).

## A vendor's SBOM

```
   cordon-scanner scan vendor.cdx.json      # CycloneDX JSON, 1.2 to 1.6
   cordon-scanner scan vendor.spdx.json     # SPDX JSON, 2.2 and 2.3
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│  every component  ──►  known-malicious releases                          │
│                   ──►  known vulnerabilities (exploited ones: CRITICAL)  │
│  the vulnerabilities the vendor listed are kept beside the ones Cordon   │
│  finds, so the two can be compared                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

A document is validated before it is believed: an unsupported version, a component
with no name, a Package URL that does not parse or an edge to a component it does not
hold is reported and the scan marked incomplete, never guessed.

Useful in procurement: a supplier's SBOM checked before their software is installed,
and again whenever the intel changes.

Next: **[24 · Policy for every repository](24-policy-distribution.md)**.
