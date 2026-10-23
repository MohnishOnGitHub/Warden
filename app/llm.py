"""Gemini wrapper: temperature 0, timeout, retries with backoff, optional fallback model.

Models come from env vars (AGENT_MODEL, FALLBACK_MODEL), never hardcoded. The API key
is read from GEMINI_API_KEY and never printed or logged.
"""
import os
import random
import time

import httpx
from dotenv import load_dotenv
from google import genai
from google.genai import errors, types

load_dotenv()

RETRY_CODES = {429, 503}
ATTEMPTS_PER_MODEL = 3
BACKOFF_BASE_S = 2.0
DEFAULT_TIMEOUT_S = 30.0


class LLMError(Exception):
    """The model could not be reached or refused the request. Callers fail closed."""


def _call(model, contents, config, timeout_s):
    client = genai.Client(
        api_key=os.getenv("GEMINI_API_KEY"),
        http_options=types.HttpOptions(timeout=int(timeout_s * 1000)),
    )
    return client.models.generate_content(model=model, contents=contents, config=config)


def _retryable(e):
    if isinstance(e, errors.APIError):
        return e.code in RETRY_CODES
    return isinstance(e, (httpx.TimeoutException, httpx.ConnectError))


def generate(contents, system_instruction, function_declarations, model=None, timeout_s=DEFAULT_TIMEOUT_S):
    """One model call. Retries 429/503 and timeouts with backoff, then tries FALLBACK_MODEL.

    Function calling is manual: the SDK never runs a tool for us.
    """
    primary = model or os.getenv("AGENT_MODEL")
    fallback = os.getenv("FALLBACK_MODEL")
    models = [m for m in (primary, fallback) if m]
    if not models:
        raise LLMError("AGENT_MODEL is not set")
    models = list(dict.fromkeys(models))  # drop a fallback equal to the primary

    config = types.GenerateContentConfig(
        temperature=0,
        system_instruction=system_instruction,
        tools=[types.Tool(function_declarations=function_declarations)] if function_declarations else None,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )

    last_error = None
    for name in models:
        for attempt in range(ATTEMPTS_PER_MODEL):
            try:
                return _call(name, contents, config, timeout_s)
            except Exception as e:
                if not _retryable(e):
                    raise LLMError(f"{type(e).__name__} from {name}") from e
                last_error = e
                if attempt < ATTEMPTS_PER_MODEL - 1:
                    time.sleep(BACKOFF_BASE_S * 2 ** attempt + random.uniform(0, 1))
    raise LLMError(f"All models failed: {type(last_error).__name__}") from last_error
