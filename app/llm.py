"""Gemini wrapper: temperature 0, timeout, retries with backoff, optional fallback model.

Models come from env vars (AGENT_MODEL, FALLBACK_MODEL), never hardcoded. The API key
is read from GEMINI_API_KEY and never printed or logged.
"""
import math
import os
import random
import time

import httpx
from dotenv import load_dotenv
from google import genai
from google.genai import errors, types

from app import replay

load_dotenv()

RETRY_CODES = {429, 503}
ATTEMPTS_PER_MODEL = 3
BACKOFF_BASE_S = 2.0
DEFAULT_TIMEOUT_S = 30.0
MIN_SERVER_DEADLINE_S = 10  # the Gemini API rejects shorter deadlines


class LLMError(Exception):
    """The model could not be reached or refused the request. Callers fail closed."""


def _now():
    return time.monotonic()


def _http_options(timeout_s):
    """Client side timeout of timeout_s, plus a server deadline of at least 10 seconds.

    The SDK copies HttpOptions.timeout into the X-Server-Timeout header, and the Gemini API
    rejects deadlines under 10 seconds with a 400. So we set the header ourselves: our client
    still gives up after timeout_s, the server is just allowed to keep working a little longer.
    """
    server_deadline = max(MIN_SERVER_DEADLINE_S, math.ceil(timeout_s))
    return types.HttpOptions(timeout=int(timeout_s * 1000), headers={"X-Server-Timeout": str(server_deadline)})


def _call(model, contents, config, timeout_s):
    """The one place a request leaves the process (or is answered from the replay cache)."""
    if replay.mode() == "play":
        return replay.lookup(model, contents, config)  # never touches the network
    global _last_call_end
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"), http_options=_http_options(timeout_s))
    try:
        response = client.models.generate_content(model=model, contents=contents, config=config)
    finally:
        _last_call_end = _now()
    if replay.mode() == "record":
        replay.store(model, contents, config, response)
    return response


# Spacing between real calls, for the free tier's rate limits. Off by default; the evaluation turns it on.
_min_interval_s = 0.0
_last_call_end = 0.0
_waited_s = 0.0  # total time spent waiting for a slot, so callers can subtract it from their timings


def set_min_interval(seconds):
    global _min_interval_s
    _min_interval_s = max(0.0, float(seconds))


def _wait_for_slot():
    """Sleep until min_interval has passed since the last real call. Not counted in any time budget."""
    if _min_interval_s <= 0 or replay.mode() == "play":
        return
    global _waited_s
    wait = _min_interval_s - (_now() - _last_call_end)
    if wait > 0:
        _waited_s += wait
        time.sleep(wait)


def waited_seconds():
    return _waited_s


def _retryable(e):
    if isinstance(e, errors.APIError):
        return e.code in RETRY_CODES
    return isinstance(e, (httpx.TimeoutException, httpx.ConnectError))


def generate(contents, system_instruction, function_declarations, model=None, timeout_s=DEFAULT_TIMEOUT_S,
             json_output=False, max_total_s=None, attempts_per_model=ATTEMPTS_PER_MODEL,
             backoff_base_s=BACKOFF_BASE_S):
    """One model call. Retries 429/503 and timeouts with backoff, then tries FALLBACK_MODEL.

    max_total_s is a hard budget for everything (attempts, backoff sleeps, fallback):
    when it runs out, LLMError is raised. Function calling is manual: the SDK never runs a tool for us.
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
        response_mime_type="application/json" if json_output else None,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )

    _wait_for_slot()
    deadline = None if max_total_s is None else _now() + max_total_s

    def remaining():
        return None if deadline is None else deadline - _now()

    last_error = None
    for name in models:
        for attempt in range(attempts_per_model):
            left = remaining()
            if left is not None and left <= 0:
                raise LLMError("Time budget exhausted") from last_error
            call_timeout = timeout_s if left is None else min(timeout_s, left)
            try:
                return _call(name, contents, config, call_timeout)
            except Exception as e:
                if not _retryable(e):
                    raise LLMError(f"{type(e).__name__} from {name}") from e
                last_error = e
                if attempt < attempts_per_model - 1:
                    pause = backoff_base_s * 2 ** attempt + random.uniform(0, backoff_base_s)
                    left = remaining()
                    if left is not None:
                        pause = min(pause, max(left, 0))
                    time.sleep(pause)
    raise LLMError(f"All models failed: {type(last_error).__name__}") from last_error


def ping(timeout_s=10.0):
    """Is Gemini reachable with our key? Fetches model metadata: no generation, so almost no quota."""
    model = os.getenv("AGENT_MODEL")
    if not model or not os.getenv("GEMINI_API_KEY"):
        raise LLMError("GEMINI_API_KEY or AGENT_MODEL is not set")
    try:
        client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"), http_options=_http_options(timeout_s))
        client.models.get(model=model)
    except Exception as e:
        raise LLMError(type(e).__name__) from e
