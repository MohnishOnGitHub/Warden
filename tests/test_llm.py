import httpx
import pytest
from google.genai import errors

from app import llm


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    sleeps = []
    monkeypatch.setattr(llm.time, "sleep", sleeps.append)
    monkeypatch.setenv("AGENT_MODEL", "primary")
    monkeypatch.delenv("FALLBACK_MODEL", raising=False)
    return sleeps


def api_error(code):
    cls = errors.ServerError if code >= 500 else errors.ClientError
    return cls(code, {"error": {"message": "x", "status": "X"}})


def scripted(monkeypatch, outcomes):
    """Replace the network call; each outcome is an exception to raise or a value to return."""
    calls = []

    def fake(model, contents, config, timeout_s):
        calls.append((model, config.temperature))
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(llm, "_call", fake)
    return calls


def test_retries_503_then_succeeds(monkeypatch, no_sleep):
    calls = scripted(monkeypatch, [api_error(503), api_error(429), "ok"])
    assert llm.generate("hi", "sys", None) == "ok"
    assert [m for m, _ in calls] == ["primary"] * 3
    assert len(no_sleep) == 2 and no_sleep[1] > no_sleep[0]  # backoff grows


def test_temperature_is_zero(monkeypatch):
    calls = scripted(monkeypatch, ["ok"])
    llm.generate("hi", "sys", None)
    assert calls[0][1] == 0


def test_non_retryable_error_fails_immediately(monkeypatch):
    calls = scripted(monkeypatch, [api_error(400), "ok"])
    with pytest.raises(llm.LLMError):
        llm.generate("hi", "sys", None)
    assert len(calls) == 1


def test_falls_back_to_fallback_model(monkeypatch):
    monkeypatch.setenv("FALLBACK_MODEL", "backup")
    calls = scripted(monkeypatch, [api_error(503)] * 3 + ["from backup"])
    assert llm.generate("hi", "sys", None) == "from backup"
    assert [m for m, _ in calls] == ["primary"] * 3 + ["backup"]


def test_no_fallback_configured_raises_after_retries(monkeypatch):
    calls = scripted(monkeypatch, [api_error(503)] * 3)
    with pytest.raises(llm.LLMError):
        llm.generate("hi", "sys", None)
    assert len(calls) == 3


def test_timeout_is_retried(monkeypatch):
    calls = scripted(monkeypatch, [httpx.ReadTimeout("slow"), "ok"])
    assert llm.generate("hi", "sys", None) == "ok" and len(calls) == 2


def test_missing_model_raises(monkeypatch):
    monkeypatch.delenv("AGENT_MODEL")
    with pytest.raises(llm.LLMError):
        llm.generate("hi", "sys", None)


# Time budget (used by the judge) ----------------------------------------------

def test_budget_allows_retry_and_fallback_within_time(monkeypatch):
    monkeypatch.setenv("FALLBACK_MODEL", "backup")
    calls = scripted(monkeypatch, [api_error(503), api_error(503), api_error(429), "from backup"])
    out = llm.generate("hi", "sys", None, max_total_s=6, attempts_per_model=2, backoff_base_s=0.5)
    assert out == "from backup"
    assert [m for m, _ in calls] == ["primary", "primary", "backup", "backup"]


def test_budget_exhaustion_raises_without_more_calls(monkeypatch):
    monkeypatch.setenv("FALLBACK_MODEL", "backup")
    clock = iter(range(0, 1000, 4))  # every clock read advances 4 seconds
    monkeypatch.setattr(llm, "_now", lambda: next(clock))
    calls = scripted(monkeypatch, [api_error(503)] * 10)
    with pytest.raises(llm.LLMError, match="budget"):
        llm.generate("hi", "sys", None, max_total_s=6, attempts_per_model=2)
    assert len(calls) < 4


def test_each_call_gets_at_most_the_remaining_budget(monkeypatch):
    timeouts = []

    def fake(model, contents, config, timeout_s):
        timeouts.append(timeout_s)
        return "ok"

    monkeypatch.setattr(llm, "_call", fake)
    llm.generate("hi", "sys", None, timeout_s=30, max_total_s=6)
    assert timeouts[0] <= 6


def test_json_mode_sets_mime_type(monkeypatch):
    seen = {}

    def fake(model, contents, config, timeout_s):
        seen["mime"] = config.response_mime_type
        seen["tools"] = config.tools
        return "ok"

    monkeypatch.setattr(llm, "_call", fake)
    llm.generate("hi", "sys", None, json_output=True)
    assert seen == {"mime": "application/json", "tools": None}


def test_short_client_timeout_still_sends_a_valid_server_deadline():
    # Regression: a 6s timeout became X-Server-Timeout: 6, which the Gemini API rejects (400, minimum 10s).
    short = llm._http_options(6)
    assert short.timeout == 6000 and short.headers["X-Server-Timeout"] == "10"
    long = llm._http_options(30)
    assert long.timeout == 30000 and long.headers["X-Server-Timeout"] == "30"
