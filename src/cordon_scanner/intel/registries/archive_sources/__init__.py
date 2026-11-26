"""The archive of a release, for every ecosystem whose registry publishes one: where it is, and the digest it must match.

One `ArchiveSource` per ecosystem says where a release's archive is (`locate`, from the registry's own documents) and which digests
the registry states for it; `ArchiveFetch` downloads it from the registry's own file hosts and returns it only when it matches every
digest stated. The release before one (`previous`) is read from the same release history the registry record is built from."""
