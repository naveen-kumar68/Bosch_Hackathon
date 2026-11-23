from pathlib import Path

from dotenv import dotenv_values


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
