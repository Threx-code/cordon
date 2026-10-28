"""`--notify` on the command line: a failed gate notifies and keeps its exit code; a passing one sends
nothing; an unknown channel is a configuration error. The notifier itself is tests/unit/notify/."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner.notify.transport import HttpsTransport
from support import MALICIOUS, requires_malicious_corpus

SLACK = "https://hooks.slack.test/services/T/B/X"


class _Recorder:
    def __init__(self, status: int = 200) -> None:
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []
        self.status = status

    def __call__(self, url, body, headers):
        self.calls.append((url, body, dict(headers)))
        return self.status


class TestTheCommandLine:
    def _run(self, tmp_path: Path, monkeypatch, *extra: str) -> int:
        from cordon_scanner.cli.main import CommandLine

        return CommandLine.main(["scan", str(tmp_path), "--progress", "never", "-q", *extra])

    @requires_malicious_corpus
    def test_a_failed_gate_notifies_and_keeps_its_exit_code(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        (tmp_path / "setup.py").write_bytes(
            (MALICIOUS / "dropper-shell-python" / "setup.py").read_bytes()
        )
        sent = _Recorder(status=404)  # not retried: the test does not wait
        monkeypatch.setattr(HttpsTransport, "post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)

        code = self._run(tmp_path, monkeypatch, "--notify", "slack")

        assert code == 1
        assert len(sent.calls) == 1
        assert "notify slack failed: HTTP 404 from slack" in capsys.readouterr().err

    def test_a_passing_gate_sends_nothing(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
        sent = _Recorder()
        monkeypatch.setattr(HttpsTransport, "post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)

        assert self._run(tmp_path, monkeypatch, "--notify", "slack") == 0
        assert sent.calls == []

    def test_an_unknown_channel_is_a_config_error(self, tmp_path, monkeypatch) -> None:
        assert self._run(tmp_path, monkeypatch, "--notify", "pager") == 3
