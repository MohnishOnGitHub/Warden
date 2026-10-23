"""The dashboard's only way to get data: the Warden HTTP API (never the database)."""
import os

import httpx

BASE_URL = os.environ.get("WARDEN_API_URL", "http://127.0.0.1:8000")
_client = None


class ApiError(Exception):
    """The API could not be reached, or answered with a server error."""


def _http():
    global _client
    if _client is None:
        _client = httpx.Client(base_url=BASE_URL, timeout=15)
    return _client


def get(path, **params):
    """GET and return the parsed JSON. Raises ApiError on a connection problem or any non-2xx answer."""
    try:
        r = _http().get(path, params=params or None)
    except httpx.HTTPError as e:
        raise ApiError(f"API not reachable at {BASE_URL} ({type(e).__name__})") from e
    if r.status_code >= 400:
        raise ApiError(f"{path} answered {r.status_code}: {_detail(r)}")
    return r.json()


def post(path, json=None):
    """POST and return (status_code, body). 4xx answers are returned, not raised: the UI shows them."""
    try:
        r = _http().post(path, json=json)
    except httpx.HTTPError as e:
        raise ApiError(f"API not reachable at {BASE_URL} ({type(e).__name__})") from e
    if r.status_code >= 500:
        raise ApiError(f"{path} answered {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        body = {}
    return r.status_code, body


def _detail(r):
    try:
        return r.json().get("detail", "")
    except ValueError:
        return ""
