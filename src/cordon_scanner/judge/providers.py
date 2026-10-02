"""Model backends for the judge, on the standard library alone.

The design is Attest's provider layer (`attest.adapters.providers`), carried over without its
vendor SDKs: Cordon installs no third-party package, so each backend speaks its API's wire shape
over `urllib`. Kept from Attest because each one is a failure that would otherwise be silent:

* **An empty completion is an error, not an answer.** A truncated, filtered or refused response
  returned as an empty string would read as "nothing found".
* **A provider's refusal is not a transport failure.** A content filter or a safety decline
  raises `ProviderRefused`; retrying the same request on the same model declines again.
* **Sampling parameters are withheld from models that reject them.** Current reasoning models
  answer `temperature` with HTTP 400; an unknown Claude model is treated the same way, the cheap
  direction to be wrong in.
* **A deterministic provider** that dials nothing, so the judge is tested without a key or a
  network.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Protocol

TIMEOUT_SECONDS: Final = 90.0
LOCAL_TIMEOUT_SECONDS: Final = 300.0
"""A model on the developer's own machine, often on a CPU, takes minutes where a hosted API takes
seconds. `CORDON_JUDGE_TIMEOUT` overrides either."""
MAX_RESPONSE_BYTES: Final = 1 << 20
LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "host.docker.internal"})


class JudgeError(Exception):
    """The judge could not be asked. The message is safe to show and never holds a key."""


class ProviderUnavailable(JudgeError):
    """The backend is misconfigured or unreachable: a missing key, an unknown backend, a host
    that does not answer."""


class ProviderRefused(JudgeError):
    """The provider itself declined: a content filter or a safety refusal. The same request on
    the same model will decline again."""

    def __init__(self, message: str, *, category: str = "") -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class Completion:
    text: str
    provider: str
    model: str
    sampling: str
    """`fixed` when temperature zero was sent; `model-controlled` when the model sets its own."""


class Transport(Protocol):
    def __call__(
        self, url: str, body: dict[str, Any], headers: dict[str, str], timeout: float = ...
    ) -> dict[str, Any]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpTransport:
    """JSON over HTTP(S): no redirects, a bounded response, and errors that name the host only."""

    @staticmethod
    def post(
        url: str, body: dict[str, Any], headers: dict[str, str], timeout: float = TIMEOUT_SECONDS
    ) -> dict[str, Any]:
        from cordon_scanner.version import __version__

        parsed_url = urllib.parse.urlsplit(url)
        if parsed_url.scheme not in ("https", "http") or (
            parsed_url.scheme == "http" and parsed_url.hostname not in LOCAL_HOSTS
        ):
            raise ProviderUnavailable("a remote judge must be reached over https")
        request = urllib.request.Request(  # noqa: S310  (scheme checked above)
            url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"cordon-scanner/{__version__}",
                **headers,
            },
        )
        host = parsed_url.hostname
        try:
            with urllib.request.build_opener(_NoRedirect).open(
                request, timeout=timeout
            ) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise ProviderUnavailable(f"the judge at {host} answered {exc.code}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ProviderUnavailable(
                f"the judge at {host} could not be reached ({type(exc).__name__})"
            ) from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProviderUnavailable(f"the judge at {host} answered with too much")
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise ProviderUnavailable(f"the judge at {host} did not answer with JSON") from exc
        if not isinstance(parsed, dict):
            raise ProviderUnavailable(f"the judge at {host} did not answer with an object")
        return parsed


class ModelFamilies:
    """The weights family a model id names: Attest's vocabulary, used here to label verdicts.

    Weights, not vendors: Groq, Bedrock and Vertex all serve Llama. Resolution never guesses; an
    unrecognised id is labelled `unknown`.
    """

    _MARKERS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("gpt-oss", "gpt-oss"),
        ("gpt_oss", "gpt-oss"),
        ("claude", "claude"),
        ("llama", "llama"),
        ("mixtral", "mistral"),
        ("mistral", "mistral"),
        ("ministral", "mistral"),
        ("magistral", "mistral"),
        ("gemini", "gemini"),
        ("gemma", "gemma"),
        ("qwen", "qwen"),
        ("deepseek", "deepseek"),
        ("command", "command"),
        ("nova", "nova"),
        ("phi-", "phi"),
        ("phi3", "phi"),
        ("phi4", "phi"),
        ("kimi", "kimi"),
        ("grok", "grok"),
        ("gpt", "gpt"),
        ("o1-", "gpt"),
        ("o3-", "gpt"),
        ("o4-", "gpt"),
    )

    @classmethod
    def resolve(cls, model_id: str) -> str:
        candidate = model_id.lower()
        return next((family for marker, family in cls._MARKERS if marker in candidate), "unknown")


class ClaudeModels:
    """Which Claude models accept `temperature`, from Attest's catalogue. An id not listed is
    treated as setting its own sampling: withholding temperature costs default sampling, sending
    it to a model that refuses it fails the call."""

    ACCEPTS_SAMPLING: ClassVar[frozenset[str]] = frozenset(
        {"claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5"}
    )
    DEFAULT: ClassVar[str] = "claude-haiku-4-5"

    @classmethod
    def accepts_sampling(cls, model_id: str) -> bool:
        return any(
            model_id == known or model_id.startswith(known + "-") for known in cls.ACCEPTS_SAMPLING
        )


class BaseProvider:
    """One judge backend. Subclasses supply `NAME`, `DEFAULT_URL` and `_exchange`."""

    NAME: ClassVar[str] = "base"
    DEFAULT_URL: ClassVar[str] = ""
    MODEL_CONTROLLED_SAMPLING: ClassVar[tuple[str, ...]] = ("o1", "o3", "o4", "gpt-5", "reasoner")
    MAX_TOKENS: ClassVar[int] = 400

    def __init__(
        self,
        model: str,
        url: str,
        *,
        environ: dict[str, str] | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.environ = dict(os.environ if environ is None else environ)
        self._transport = transport or HttpTransport.post

    @property
    def timeout(self) -> float:
        """Seconds one call may take: longer for a local model, `CORDON_JUDGE_TIMEOUT` if set."""
        try:
            return max(1.0, float(self.environ["CORDON_JUDGE_TIMEOUT"]))
        except (KeyError, ValueError):
            return TIMEOUT_SECONDS if self.remote else LOCAL_TIMEOUT_SECONDS

    def _post(self, url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        return self._transport(url, body, headers, timeout=self.timeout)

    @property
    def remote(self) -> bool:
        """Whether text sent to this backend leaves the machine."""
        return (urllib.parse.urlsplit(self.url).hostname or "") not in LOCAL_HOSTS

    @property
    def label(self) -> str:
        return f"{self.NAME}:{self.model}" if self.model else self.NAME

    @property
    def family(self) -> str:
        return ModelFamilies.resolve(self.model or self.NAME)

    def _model_controls_sampling(self) -> bool:
        candidate = self.model.lower()
        return any(marker in candidate for marker in self.MODEL_CONTROLLED_SAMPLING)

    def _key(self, *names: str) -> str:
        for name in names:
            if self.environ.get(name):
                return self.environ[name]
        raise ProviderUnavailable(f"set {' or '.join(names)} to use the {self.NAME} judge")

    def complete(self, system: str, user: str) -> Completion:
        text = self._exchange(system, user)
        if not text.strip():
            raise JudgeError(
                f"{self.label} returned no text. An empty completion is a failed call, not "
                "an answer, and is not read as one."
            )
        return Completion(
            text=text,
            provider=self.NAME,
            model=self.model,
            sampling="model-controlled" if self._model_controls_sampling() else "fixed",
        )

    def _exchange(self, system: str, user: str) -> str:
        raise NotImplementedError


class ChatCompletionsProvider(BaseProvider):
    """The chat-completions wire shape: a protocol many servers speak, not one vendor's."""

    def _headers(self) -> dict[str, str]:
        return {}

    def _exchange(self, system: str, user: str) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "max_completion_tokens": self.MAX_TOKENS,
        }
        if not self._model_controls_sampling():
            payload["temperature"] = 0
            payload["seed"] = 0
        reply = self._post(f"{self.url}/chat/completions", payload, self._headers())
        choices = reply.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise JudgeError(f"{self.label} answered without a choice")
        choice = choices[0]
        if choice.get("finish_reason") == "content_filter":
            raise ProviderRefused(f"{self.label} filtered the request", category="content_filter")
        message = choice.get("message")
        return str(message.get("content") or "") if isinstance(message, dict) else ""


class OpenAIProvider(ChatCompletionsProvider):
    """OpenAI's API, or anything speaking its shape: vLLM, LM Studio, a corporate gateway.

    `CORDON_JUDGE_URL` (or `OPENAI_BASE_URL`) points it elsewhere; a local server needs no key.
    """

    NAME = "openai"
    DEFAULT_URL = "https://api.openai.com/v1"

    def _headers(self) -> dict[str, str]:
        if not self.remote and not (
            self.environ.get("CORDON_JUDGE_API_KEY") or self.environ.get("OPENAI_API_KEY")
        ):
            return {}
        return {"Authorization": f"Bearer {self._key('CORDON_JUDGE_API_KEY', 'OPENAI_API_KEY')}"}


class OllamaProvider(BaseProvider):
    """A local Ollama (`OLLAMA_HOST`, default 127.0.0.1:11434): nothing leaves the machine."""

    NAME = "ollama"
    DEFAULT_URL = "http://127.0.0.1:11434"

    def _exchange(self, system: str, user: str) -> str:
        reply = self._post(
            f"{self.url}/api/chat",
            {
                "model": self.model,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "seed": 0, "num_predict": self.MAX_TOKENS},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {},
        )
        message = reply.get("message")
        return str(message.get("content") or "") if isinstance(message, dict) else ""


class AnthropicProvider(BaseProvider):
    """Anthropic's Messages API (`ANTHROPIC_API_KEY`)."""

    NAME = "anthropic"
    DEFAULT_URL = "https://api.anthropic.com"

    def _model_controls_sampling(self) -> bool:
        return not ClaudeModels.accepts_sampling(self.model)

    def _exchange(self, system: str, user: str) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if not self._model_controls_sampling():
            payload["temperature"] = 0
        reply = self._post(
            f"{self.url}/v1/messages",
            payload,
            {
                "x-api-key": self._key("CORDON_JUDGE_API_KEY", "ANTHROPIC_API_KEY"),
                "anthropic-version": "2023-06-01",
            },
        )
        if reply.get("stop_reason") == "refusal":
            details = reply.get("stop_details")
            category = str(details.get("category", "")) if isinstance(details, dict) else ""
            raise ProviderRefused(f"{self.label} declined the request", category=category)
        return "".join(
            str(block.get("text", ""))
            for block in reply.get("content") or ()
            if isinstance(block, dict) and block.get("type") == "text"
        )


class CordonCloudProvider(BaseProvider):
    """Cordon Cloud's hosted judge, signed in with `cordon login` (contract:
    `schemas/cordon-judge-v1.schema.json`). The cloud runs the prompt; this sends the text."""

    NAME = "cordon-cloud"

    def __init__(self, model: str, url: str, **kwargs: Any) -> None:
        super().__init__(model, url, **kwargs)
        self.prompt_version = ""
        self.kind = ""
        self.path = ""
        self.text = ""

    @property
    def family(self) -> str:
        return "cordon-cloud"

    def _exchange(self, system: str, user: str) -> str:
        from cordon_scanner.cloud import CloudError, auth

        try:
            credentials = auth.CloudAuth.current(self.url)
        except CloudError as exc:
            raise ProviderUnavailable(str(exc)) from exc
        reply = self._post(
            f"{self.url}/v1/judge",
            {
                "prompt_version": self.prompt_version,
                "kind": self.kind,
                "path": self.path,
                "text": self.text,
            },
            {"Authorization": f"Bearer {credentials.access_token}"},
        )
        verdict = reply.get("verdict")
        return json.dumps(verdict) if isinstance(verdict, dict) else ""


class DeterministicProvider(BaseProvider):
    """Dials nothing and answers by rule, so the judge is tested without a model.

    Not a model: it calls text malicious when it contains `ignore all previous instructions`,
    quoting that phrase, and benign otherwise, and says it is synthetic in its reason.
    """

    NAME = "deterministic"
    TRIGGER: ClassVar[str] = "ignore all previous instructions"

    @property
    def remote(self) -> bool:
        return False

    @property
    def family(self) -> str:
        return "deterministic"

    def _exchange(self, system: str, user: str) -> str:
        found = self.TRIGGER in user.lower()
        start = user.lower().find(self.TRIGGER)
        digest = hashlib.sha256(user.encode("utf-8")).hexdigest()[:12]
        return json.dumps(
            {
                "verdict": "malicious" if found else "benign",
                "category": "instruction-override" if found else "other",
                "evidence": user[start : start + len(self.TRIGGER)] if found else "",
                "reason": f"synthetic verdict {digest}",
            }
        )


class ProviderFactory:
    """A backend from the operator's `--judge` value."""

    BACKENDS: ClassVar[dict[str, type[BaseProvider]]] = {
        "ollama": OllamaProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "cordon-cloud": CordonCloudProvider,
        "deterministic": DeterministicProvider,
    }

    @classmethod
    def from_spec(
        cls,
        spec: str,
        *,
        environ: dict[str, str] | None = None,
        transport: Transport | None = None,
    ) -> BaseProvider:
        """`ollama:<model>`, `openai:<model>`, `anthropic[:<model>]` or `cordon-cloud`."""
        env = dict(os.environ if environ is None else environ)
        name, _, model = spec.strip().partition(":")
        name = name.lower()
        backend = cls.BACKENDS.get(name)
        if backend is None:
            raise ProviderUnavailable(
                f"unknown judge {name!r}: use ollama:<model>, openai:<model>, anthropic or cordon-cloud"
            )
        if name in ("ollama", "openai") and not model:
            raise ProviderUnavailable(f"name the model: --judge {name}:<model>")
        if name == "ollama":
            url = env.get("OLLAMA_HOST") or OllamaProvider.DEFAULT_URL
            url = url if "://" in url else "http://" + url
        elif name == "openai":
            url = (
                env.get("CORDON_JUDGE_URL")
                or env.get("OPENAI_BASE_URL")
                or OpenAIProvider.DEFAULT_URL
            )
        elif name == "anthropic":
            url = env.get("CORDON_JUDGE_URL") or AnthropicProvider.DEFAULT_URL
            model = model or ClaudeModels.DEFAULT
        elif name == "cordon-cloud":
            from cordon_scanner.cloud import CloudEndpoint, CloudError

            try:
                url = CloudEndpoint.base_url(env.get("CORDON_CLOUD_URL"))
            except CloudError as exc:
                raise ProviderUnavailable(str(exc)) from exc
        else:
            url = "http://127.0.0.1"
        return backend(model, url, environ=env, transport=transport)


__all__ = [
    "AnthropicProvider",
    "BaseProvider",
    "ChatCompletionsProvider",
    "ClaudeModels",
    "Completion",
    "CordonCloudProvider",
    "DeterministicProvider",
    "HttpTransport",
    "JudgeError",
    "ModelFamilies",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderFactory",
    "ProviderRefused",
    "ProviderUnavailable",
    "Transport",
]
