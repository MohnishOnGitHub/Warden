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


def usage(prompt, candidates, thoughts=None):
    from google.genai import types
    return types.GenerateContentResponse(usage_metadata=types.GenerateContentResponseUsageMetadata(
        prompt_token_count=prompt, candidates_token_count=candidates, thoughts_token_count=thoughts))


def test_token_usage_is_counted_per_purpose(monkeypatch):
    monkeypatch.setenv("AGENT_MODEL", "primary")
    scripted(monkeypatch, [usage(100, 10, 5), usage(40, 4), usage(7, 1)])
    before = llm.usage_snapshot()
    llm.generate("hi", "sys", None)
    llm.generate("hi", "sys", None, purpose="judge")
    llm.generate("hi", "sys", None)
    after = llm.usage_snapshot()
    assert after["agent"][0] - before["agent"][0] == 107
    assert after["agent"][1] - before["agent"][1] == 16  # thinking tokens count as output
    assert after["judge"][0] - before["judge"][0] == 40 and after["judge"][1] - before["judge"][1] == 4


def test_a_response_without_usage_is_not_an_error(monkeypatch):
    monkeypatch.setenv("AGENT_MODEL", "primary")
    scripted(monkeypatch, ["plain string, no usage_metadata"])
    before = llm.usage_snapshot()
    assert llm.generate("hi", "sys", None) == "plain string, no usage_metadata"
    assert llm.usage_snapshot() == before


def test_a_404_is_a_config_error_with_its_status_and_is_not_retried(monkeypatch, no_sleep):
    monkeypatch.setenv("AGENT_MODEL", "no-such-model")
    monkeypatch.delenv("FALLBACK_MODEL", raising=False)
    calls = scripted(monkeypatch, [api_error(404)])
    with pytest.raises(llm.LLMConfigError) as e:
        llm.generate("hi", "sys", None)
    assert (e.value.status, e.value.cause_type, len(calls)) == (404, "ClientError", 1)


def test_other_failures_keep_status_and_type_but_are_not_config_errors(monkeypatch, no_sleep):
    monkeypatch.setenv("AGENT_MODEL", "primary")
    monkeypatch.delenv("FALLBACK_MODEL", raising=False)
    scripted(monkeypatch, [api_error(503)] * 3)
    with pytest.raises(llm.LLMError) as e:
        llm.generate("hi", "sys", None)
    assert not isinstance(e.value, llm.LLMConfigError) and (e.value.status, e.value.cause_type) == (503, "ServerError")
    scripted(monkeypatch, [httpx.ReadTimeout("slow")] * 3)
    with pytest.raises(llm.LLMError) as e:
        llm.generate("hi", "sys", None)
    assert (e.value.status, e.value.cause_type) == (None, "ReadTimeout")


class FakeModels:
    def __init__(self, known):
        self.known, self.asked = known, []

    def get(self, model):
        self.asked.append(model)
        if model not in self.known:
            raise api_error(404)


def fake_client(monkeypatch, known):
    models = FakeModels(known)
    monkeypatch.setattr(llm.genai, "Client", lambda **kw: type("C", (), {"models": models})())
    return models


def test_check_models_names_the_wrong_variable(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("AGENT_MODEL", "good")
    monkeypatch.setenv("JUDGE_MODEL", "gemini-3.8-flash-lite")
    monkeypatch.delenv("FALLBACK_MODEL", raising=False)
    fake_client(monkeypatch, {"good"})
    with pytest.raises(llm.LLMConfigError, match="JUDGE_MODEL=gemini-3.8-flash-lite") as e:
        llm.check_models()
    assert "AGENT_MODEL" not in str(e.value) and "k" != str(e.value)


def test_check_models_passes_when_all_names_exist_and_ignores_other_errors(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("AGENT_MODEL", "a")
    monkeypatch.setenv("JUDGE_MODEL", "j")
    monkeypatch.setenv("FALLBACK_MODEL", "f")
    models = fake_client(monkeypatch, {"a", "j", "f"})
    llm.check_models()
    assert models.asked == ["a", "j", "f"]
    monkeypatch.setattr(models, "get", lambda model: (_ for _ in ()).throw(api_error(429)))
    llm.check_models()  # rate limited is not a configuration error


def test_check_models_without_a_key_does_nothing(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(llm.genai, "Client", lambda **kw: pytest.fail("no key, no call"))
    llm.check_models()
