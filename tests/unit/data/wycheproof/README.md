# Wycheproof test vectors

From Project Wycheproof (https://github.com/C2SP/wycheproof), commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`,
directory `testvectors_v1`, unmodified. Apache License 2.0 (`LICENSE` here).

They are the catalogue of known ways signature verifiers have been fooled (invalid curve points,
malleable and BER-encoded signatures, out-of-range values, padding tricks). Cordon's own
verifiers in `intel/provenance` run every vector in every file here.
