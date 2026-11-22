"""HTTP client objects and the methods on them that send a request (group A (a)). Moved out of
`pyfacts.py` (its length limit); `pyfacts` folds `CLIENT_REQUESTS` into `PRIMITIVES` as egress."""

from __future__ import annotations

#: Constructors of an HTTP client object, and the methods on it that send a request. A request sent
#: through a client (`client = httpx.Client(); client.post(url, json=data)`, `with requests.Session()
#: as s`, `self._session = requests.Session()`) is a request as `requests.post` is: group A (a),
#: 2026-11-10, where 13 of 17 PyPI units sent what they gathered through one and no flow fact fired.
HTTP_CLIENTS: frozenset[str] = frozenset(
    {
        "requests.Session",
        "requests.session",
        "requests.sessions.Session",
        "httpx.Client",
        "httpx.AsyncClient",
        "urllib3.PoolManager",
        "urllib3.HTTPConnectionPool",
        "urllib3.HTTPSConnectionPool",
        "aiohttp.ClientSession",
    }
)
HTTP_CLIENT_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream",
     "urlopen"}
)  # fmt: skip

#: `<client>.<method>` for every client and request method: the dotted names a call resolves to.
CLIENT_REQUESTS: frozenset[str] = frozenset(
    f"{client}.{method}" for client in HTTP_CLIENTS for method in HTTP_CLIENT_METHODS
)

#: Libraries that put an object in a cloud store, and the methods of a bucket, blob or container that
#: do it. A store is somebody's server: `blob.upload_from_string(os.getenv(...))` sends the value to
#: whoever owns the bucket as `requests.post` sends it to a host. The receiver is rarely written down
#: (`bucket.blob(name).upload_from_string(...)`), so the method counts when the file imports one of
#: the libraries and not otherwise: `upload_file` is also what a web framework calls.
CLOUD_STORAGE_LIBRARIES: tuple[str, ...] = (
    "google.cloud.storage",
    "google.cloud",
    "boto3",
    "botocore",
    "boto",
    "azure.storage",
    "minio",
    "oss2",
    "qcloud_cos",
    "swiftclient",
    "b2sdk",
)
CLOUD_UPLOAD_METHODS: frozenset[str] = frozenset(
    {"upload_from_string", "upload_from_filename", "upload_from_file", "upload_blob", "put_object",
     "upload_file", "upload_fileobj", "fput_object", "put_blob", "upload_data", "put_object_from_file"}
)  # fmt: skip
CLOUD_UPLOADS: frozenset[str] = frozenset(f"cloud_storage.{m}" for m in CLOUD_UPLOAD_METHODS)

__all__ = [
    "CLIENT_REQUESTS",
    "CLOUD_STORAGE_LIBRARIES",
    "CLOUD_UPLOADS",
    "CLOUD_UPLOAD_METHODS",
    "HTTP_CLIENTS",
    "HTTP_CLIENT_METHODS",
]
