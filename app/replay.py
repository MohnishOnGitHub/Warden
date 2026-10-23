"""Record and replay Gemini calls, so an evaluation can be repeated offline for free.

REPLAY_MODE=record  every real call is also saved to the cache file.
REPLAY_MODE=play    calls are answered from the cache with no network. A call that is not in the cache
                    raises ReplayMiss (and is remembered in MISSES): it is never sent to Gemini.
Anything else (or unset) leaves the cache alone.

The key is a hash of the model, the full request (system prompt, history, tools, settings) and a salt.
The evaluation sets a salt per run, so repeated runs of the same case stay separate samples. Because the
whole request is hashed, any change to a prompt or tool declaration makes old entries miss: re-record.
"""
import hashlib
import json
import os
from pathlib import Path

from google.genai import types

from app.db import ROOT

DEFAULT_CACHE_PATH = ROOT / "data" / "llm_cache.json"

MISSES = []  # keys of play-mode requests that were not in the cache (checked by the evaluation)
_salt = ""
_cache = None
_cache_path = None


class ReplayMiss(Exception):
    """Play mode was asked for a response that was never recorded."""


def mode():
    value = os.environ.get("REPLAY_MODE", "").strip().lower()
    return value if value in ("record", "play") else ""


def cache_path():
    return Path(os.environ.get("REPLAY_CACHE") or DEFAULT_CACHE_PATH)


def set_salt(salt):
    global _salt
    _salt = salt or ""


def _dump(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", exclude_none=True)
    return obj


def request_key(model, contents, config):
    payload = {
        "model": model,
        "salt": _salt,
        "contents": [_dump(c) for c in contents] if isinstance(contents, list) else _dump(contents),
        "config": _dump(config),
    }
    text = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load():
    """The cache as a dict, read once per cache file."""
    global _cache, _cache_path
    path = cache_path()
    if _cache is None or _cache_path != path:
        _cache = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        _cache_path = path
    return _cache


def reset_state():
    """Forget the in-memory cache, misses and salt (tests, or after the cache file changed)."""
    global _cache, _cache_path, _salt
    _cache, _cache_path, _salt = None, None, ""
    MISSES.clear()


def lookup(model, contents, config):
    key = request_key(model, contents, config)
    entry = _load().get(key)
    if entry is None:
        MISSES.append(key)
        raise ReplayMiss(f"No recorded response for request {key[:12]} (salt {_salt!r}). Re-record with REPLAY_MODE=record.")
    return types.GenerateContentResponse.model_validate_json(json.dumps(entry["response"]))


def store(model, contents, config, response):
    cache = _load()
    # JSON mode keeps bytes (thought signatures) intact as base64; python mode would not.
    cache[request_key(model, contents, config)] = {
        "salt": _salt, "model": model, "response": json.loads(response.model_dump_json(exclude_none=True)),
    }
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, sort_keys=True, indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)  # an interrupted run never leaves a half-written cache


def size():
    return len(_load())
