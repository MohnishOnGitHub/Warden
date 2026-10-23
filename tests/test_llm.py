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
