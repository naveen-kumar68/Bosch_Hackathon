from pathlib import Path

from dotenv import dotenv_values

from guardian.llm.completion import (
    BudgetExceeded,
    CompletionClient,
    LLMOutputError,
    ProviderUnavailable,
    load_config,
)

_completion_client: CompletionClient | None = None

__all__ = [
    "BudgetExceeded",
    "CompletionClient",
    "LLMOutputError",
    "ProviderUnavailable",
    "complete",
    "configure_completion",
    "create_client",
    "create_completion_client",
]


def configure_completion(client: CompletionClient):
    """Install one run-scoped client; the lead supplies the same run budget key to all roles."""
    global _completion_client
    _completion_client = client


def create_completion_client(database: Path, *, env_file=Path(".env"), config_file=None):
    config, providers = load_config(config_file, env_file)
    return CompletionClient(database, providers, config)


def complete(role, messages, schema, budget_key):
    """Common role entry point. Configuration is explicit and never triggers a request."""
    if _completion_client is None:
        raise ProviderUnavailable("LLM client is not configured; use facts only")
    return _completion_client.complete(role, messages, schema, budget_key)


def create_client(env_file=Path(".env")):
    """Provider-configured client. Construction makes no network request."""
    from openai import OpenAI

    settings = dotenv_values(env_file) if env_file.exists() else {}
    if not all(settings.get(name) for name in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL")):
        raise ValueError("Judge provider settings missing in .env")
    if not settings["LLM_BASE_URL"].startswith("https://"):
        raise ValueError("Judge provider endpoint requires HTTPS")
    return OpenAI(
        api_key=settings["LLM_API_KEY"],
        base_url=settings["LLM_BASE_URL"],
        max_retries=0,
        timeout=60,
    )
