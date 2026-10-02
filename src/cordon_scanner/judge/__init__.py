"""A language model, asked to judge the text a repository hands an agent. Opt-in, off by default.

Pattern rules match wordings someone wrote down; an attacker writes new ones, and on prose
addressed to an agent the patterns cannot be widened without flagging ordinary instructions. A
model reads meaning. `--judge` names one:

    --judge ollama:<model>        a local Ollama (OLLAMA_HOST, default 127.0.0.1:11434)
    --judge openai:<model>        an OpenAI-compatible API -- OpenAI, vLLM, LM Studio, a gateway
                                  (CORDON_JUDGE_URL or OPENAI_BASE_URL; OPENAI_API_KEY)
    --judge anthropic[:<model>]   Anthropic's API (ANTHROPIC_API_KEY)
    --judge cordon-cloud          Cordon Cloud's hosted judge (`cordon login`)

`providers` holds the backends, on the standard library alone; `review` the prompt, the verdict,
the cache and the budget. `detect/agent_judge.py` decides what text is judged and what a verdict
becomes.
"""

from cordon_scanner.judge.providers import (
    BaseProvider,
    JudgeError,
    ProviderFactory,
    ProviderRefused,
    ProviderUnavailable,
)
from cordon_scanner.judge.review import (
    DEFAULT_MAX_CALLS,
    PROMPT_VERSION,
    BudgetExhausted,
    Chunker,
    Judge,
    Prompt,
    Verdict,
    VerdictCache,
    VerdictParser,
)

__all__ = [
    "DEFAULT_MAX_CALLS",
    "PROMPT_VERSION",
    "BaseProvider",
    "BudgetExhausted",
    "Chunker",
    "Judge",
    "JudgeError",
    "Prompt",
    "ProviderFactory",
    "ProviderRefused",
    "ProviderUnavailable",
    "Verdict",
    "VerdictCache",
    "VerdictParser",
]
