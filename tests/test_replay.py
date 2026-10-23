import json

import pytest
from google.genai import types

from app import llm, replay

SIGNATURE = b"\x00\xff\x10thought-signature\xfe"


def fake_response(name="unlock_account", args=None):
    part = types.Part(function_call=types.FunctionCall(name=name, args=args or {"user_id": "priya.s"}),
                      thought_signature=SIGNATURE)
    return types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(role="model", parts=[part]))])


class FakeClient:
    """Stands in for genai.Client and counts real calls."""
    calls = 0

    def __init__(self, *a, **k):
        self.models = self

    def generate_content(self, model, contents, config):
        FakeClient.calls += 1
        return fake_response()


class ExplodingClient:
    def __init__(self, *a, **k):
        raise AssertionError("play mode must never create a network client")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("REPLAY_CACHE", str(tmp_path / "cache.json"))
    monkeypatch.delenv("REPLAY_MODE", raising=False)
    monkeypatch.setenv("AGENT_MODEL", "model-x")
    monkeypatch.delenv("FALLBACK_MODEL", raising=False)
    monkeypatch.setattr(llm.genai, "Client", FakeClient)
    FakeClient.calls = 0
    replay.reset_state()
    llm.set_min_interval(0)
    yield tmp_path / "cache.json"
    replay.reset_state()
    llm.set_min_interval(0)


def ask(contents="hello", system="be safe"):
    return llm.generate(contents, system, None)


def test_record_saves_each_call_and_still_uses_the_network(isolated, monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "record")
    ask()
    ask()
    assert FakeClient.calls == 2  # record never serves from the cache, so repeats are real samples
    assert len(json.loads(isolated.read_text(encoding="utf-8"))) == 1  # same request, same key
    assert not isolated.with_suffix(".tmp").exists()


def test_play_serves_the_recorded_response_with_no_network(isolated, monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "record")
    ask()
    replay.reset_state()
    monkeypatch.setenv("REPLAY_MODE", "play")
    monkeypatch.setattr(llm.genai, "Client", ExplodingClient)
    response = ask()
    call = response.function_calls[0]
    assert (call.name, dict(call.args)) == ("unlock_account", {"user_id": "priya.s"})
    # thought signatures must survive the JSON round trip byte for byte
    assert response.candidates[0].content.parts[0].thought_signature == SIGNATURE


def test_play_miss_raises_and_is_remembered_and_never_hits_the_network(monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "play")
    monkeypatch.setattr(llm.genai, "Client", ExplodingClient)
    with pytest.raises(llm.LLMError):
        ask("never recorded")
    assert len(replay.MISSES) == 1


def test_the_salt_keeps_repeated_runs_apart(monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "record")
    replay.set_salt("A1-1|off|1")
    ask()
    replay.reset_state()
    monkeypatch.setenv("REPLAY_MODE", "play")
    replay.set_salt("A1-1|off|1")
    assert ask().function_calls
    replay.set_salt("A1-1|off|2")
    with pytest.raises(llm.LLMError):
        ask()


def test_key_depends_on_the_whole_request():
    base = replay.request_key("m", [types.Content(role="user", parts=[types.Part.from_text(text="hi")])],
                              types.GenerateContentConfig(temperature=0, system_instruction="a"))
    same = replay.request_key("m", [types.Content(role="user", parts=[types.Part.from_text(text="hi")])],
                              types.GenerateContentConfig(temperature=0, system_instruction="a"))
    assert base == same
    for other in (
        replay.request_key("m2", [types.Content(role="user", parts=[types.Part.from_text(text="hi")])],
                           types.GenerateContentConfig(temperature=0, system_instruction="a")),
        replay.request_key("m", [types.Content(role="user", parts=[types.Part.from_text(text="hi!")])],
                           types.GenerateContentConfig(temperature=0, system_instruction="a")),
        replay.request_key("m", [types.Content(role="user", parts=[types.Part.from_text(text="hi")])],
                           types.GenerateContentConfig(temperature=0, system_instruction="b")),
    ):
        assert other != base


def test_string_contents_work_for_the_judge(monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "record")
    llm.generate("a judge prompt as plain text", "judge system", None, json_output=True)
    replay.reset_state()
    monkeypatch.setenv("REPLAY_MODE", "play")
    assert llm.generate("a judge prompt as plain text", "judge system", None, json_output=True).function_calls
    with pytest.raises(llm.LLMError):
        llm.generate("a different prompt", "judge system", None, json_output=True)


def test_no_mode_leaves_the_cache_alone(isolated):
    ask()
    assert FakeClient.calls == 1 and not isolated.exists()


def test_unknown_mode_values_are_ignored(isolated, monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "banana")
    ask()
    assert replay.mode() == "" and not isolated.exists() and FakeClient.calls == 1


def test_the_cache_is_a_plain_json_file_you_can_commit(isolated, monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "record")
    replay.set_salt("X|on|1")
    ask()
    entry = next(iter(json.loads(isolated.read_text(encoding="utf-8")).values()))
    assert entry["salt"] == "X|on|1" and entry["model"] == "model-x" and "candidates" in entry["response"]


# Spacing between real calls --------------------------------------------------------------------

def test_min_interval_waits_between_real_calls_and_counts_the_wait(monkeypatch):
    clock = [100.0]
    slept = []
    monkeypatch.setattr(llm, "_now", lambda: clock[0])
    monkeypatch.setattr(llm, "_last_call_end", -1000.0)  # no earlier call on this fake clock
    monkeypatch.setattr(llm.time, "sleep", lambda s: (slept.append(s), clock.__setitem__(0, clock[0] + s)))
    llm.set_min_interval(4)
    before = llm.waited_seconds()
    ask("one")
    clock[0] += 1.0  # only one second passed before the next call
    ask("two")
    assert slept == [pytest.approx(3.0)] and llm.waited_seconds() - before == pytest.approx(3.0)


def test_no_waiting_in_play_mode(monkeypatch):
    monkeypatch.setenv("REPLAY_MODE", "record")
    ask()
    replay.reset_state()
    monkeypatch.setenv("REPLAY_MODE", "play")
    monkeypatch.setattr(llm.time, "sleep", lambda s: pytest.fail("play mode must not sleep"))
    llm.set_min_interval(60)
    ask()
