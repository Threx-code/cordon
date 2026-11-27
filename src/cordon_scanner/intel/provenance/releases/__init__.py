"""Verifying a release by the signature its publisher's platform put on it, against roots pinned in this package.

`cms` reads CMS SignedData and RFC 3161 time-stamps; `github_attestations` checks a GitHub Action's release attestation against GitHub's
own trusted root; `nuget_signature` checks a NuGet package's repository signature against DigiCert's roots."""
