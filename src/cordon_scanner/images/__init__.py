"""Container images: the operating-system packages an image ships, read from the image itself.

An image tarball (`docker save`, `podman save`, or an OCI image layout packed as a tar) is a stack
of layer tarballs. The package manager's database -- dpkg's `status`, apk's `installed`, RPM's
`rpmdb.sqlite` -- is rewritten by any layer that installs or removes a package, and a later layer
can delete it with a whiteout. So the inventory is taken from the database as the final layer
leaves it, never from any one layer, and never by running anything in the image.
"""

from __future__ import annotations

__all__: list[str] = []
