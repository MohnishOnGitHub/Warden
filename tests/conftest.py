import json

import pytest

from app.db import ROOT, create_schema, get_connection
from scripts.reset_db import load_seed


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
