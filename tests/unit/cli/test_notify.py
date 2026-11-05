"""`--notify` on the command line: a failed gate notifies and keeps its exit code; a passing one sends
nothing unless asked (`--notify-on passed`); channels and occasions may come from the config file,
never a URL; each delivery is recorded in the audit log, never its URL; `notify test` reports each
channel. The notifier itself is tests/unit/notify/."""

from __future__ import annotations

import json
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

    def test_a_passing_gate_notifies_when_asked(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
        sent = _Recorder()
        monkeypatch.setattr(HttpsTransport, "post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)

        code = self._run(tmp_path, monkeypatch, "--notify", "slack", "--notify-on", "passed")

        assert code == 0
        assert len(sent.calls) == 1
        assert b"passed its gate" in sent.calls[0][1]

    def test_an_unknown_occasion_is_a_config_error(self, tmp_path, monkeypatch) -> None:
        assert self._run(tmp_path, monkeypatch, "--notify", "slack", "--notify-on", "always") == 3


class TestTheConfigFile:
    def _run(self, tmp_path: Path, config: str) -> int:
        from cordon_scanner.cli.main import CommandLine

        (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / ".cordon.yaml").write_text(config, encoding="utf-8")
        return CommandLine.main(["scan", str(tmp_path), "--progress", "never", "-q"])

    def test_channels_and_occasions_come_from_the_file(self, tmp_path, monkeypatch) -> None:
        sent = _Recorder()
        monkeypatch.setattr(HttpsTransport, "post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)

        code = self._run(tmp_path, "version: 1\nnotify:\n  channels: [slack]\n  on: [passed]\n")

        assert code == 0
        assert len(sent.calls) == 1

    def test_a_url_in_the_file_is_refused_not_read(self, tmp_path, monkeypatch) -> None:
        sent = _Recorder()
        monkeypatch.setattr(HttpsTransport, "post", sent)

        code = self._run(tmp_path, f"version: 1\nnotify:\n  channels: [slack]\n  slack: {SLACK}\n")

        assert code == 3
        assert sent.calls == []


class TestTheAuditRecord:
    def test_each_delivery_is_recorded_and_never_its_url(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.cli.main import CommandLine

        (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
        audit = tmp_path.parent / f"{tmp_path.name}-audit.jsonl"
        monkeypatch.setattr(HttpsTransport, "post", _Recorder())
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)

        code = CommandLine.main(
            [
                "scan", str(tmp_path), "--progress", "never", "-q",
                "--notify", "slack", "--notify-on", "passed", "--audit-log", str(audit),
            ]
        )  # fmt: skip

        assert code == 0
        text = audit.read_text(encoding="utf-8")
        records = [json.loads(line) for line in text.splitlines()]
        notified = [r for r in records if r.get("event") == "notify"]
        assert [(r["channel"], r["ok"], r["attempts"]) for r in notified] == [("slack", True, 1)]
        assert notified[0]["delivery"]
        assert SLACK not in text and "hooks.slack.test" not in text


class TestTheTestCommand:
    def test_each_channel_is_sent_a_test_and_its_outcome_printed(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        from cordon_scanner.cli.main import CommandLine

        sent = _Recorder()
        monkeypatch.setattr(HttpsTransport, "post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)
        monkeypatch.chdir(tmp_path)

        assert CommandLine.main(["notify", "test", "slack"]) == 0
        assert len(sent.calls) == 1 and b"[test]" in sent.calls[0][1]
        assert "slack: delivered" in capsys.readouterr().out

    def test_a_channel_that_does_not_arrive_fails_the_command(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        from cordon_scanner.cli.main import CommandLine

        monkeypatch.setattr(HttpsTransport, "post", _Recorder(status=404))
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", SLACK)
        monkeypatch.chdir(tmp_path)

        assert CommandLine.main(["notify", "test", "slack"]) == 1
        assert "slack: not delivered: HTTP 404 from slack" in capsys.readouterr().out
