# Analysis verdict signature vectors

`verdict_p256_vectors.json` is shared with the repository that signs the verdicts, which pins the same file by its
SHA-256. It holds the verdict library's pinned golden records (format 3, 512 bytes), one public key (its private half
was dropped when the file was made), and signatures, some accepted and some that must be refused.

The rule both sides apply: a verdict is accepted if the record begins with `CVR3` and a version byte 3, and ECDSA over
P-256 with SHA-256 verifies the signature over the `domain` bytes followed by the 512-byte record, under `public_key`
(DER `SubjectPublicKeyInfo`, signature DER). `signature_ok` is the second part alone. One case is a format-2 record
with a good signature: the signature verifies and the verdict is still refused, because there is no way down to the old
format. Change the file only together with the signing repository's copy and both pins.
