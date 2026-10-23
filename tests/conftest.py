import json

import pytest

from app.db import ROOT, create_schema, get_connection
from app.warden import judge
from scripts.reset_db import load_seed


def judge_reply(verdict="ALLOW", risk_score=5, reason="Looks fine.", indicators=()):
    """A well-formed judge answer as the raw text the model would return."""
    return json.dumps({
        "verdict": verdict, "risk_score": risk_score, "reason": reason, "indicators": list(indicators),
    })


class FakeJudge:
    """Stands in for judge.call_model. Set .reply to a string, an exception to raise, or a callable."""

    def __init__(self):
        self.reply = judge_reply()
        self.calls = []

    def __call__(self, contents, system_instruction):
        self.calls.append((contents, system_instruction))
        reply = self.reply(contents) if callable(self.reply) else self.reply
        if isinstance(reply, Exception):
            raise reply
        return reply


@pytest.fixture(autouse=True)
def fake_judge(monkeypatch):
    """No test may reach the network: the judge is a benign fake unless a test changes it."""
    fake = FakeJudge()
    monkeypatch.setattr(judge, "call_model", fake)
    return fake


@pytest.fixture
def conn(tmp_path):
    """A fresh seeded database in a temp file, plus one NEW ticket (T1001) from priya.s."""
    c = get_connection(tmp_path / "test.db")
    create_schema(c)
    seed = json.loads((ROOT / "data" / "seed_directory.json").read_text(encoding="utf-8"))
    with c:
        load_seed(c, seed)
        c.execute("INSERT INTO tickets (ticket_id, requester_id, subject, body) VALUES ('T1001', 'priya.s', 's', 'b')")
    yield c
    c.close()
