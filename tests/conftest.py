import os
import tempfile
from pathlib import Path

import pytest

_tmp = Path(tempfile.mkdtemp(prefix="onionlens-test-"))
os.environ["ONIONLENS_DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["ONIONLENS_RAW_DIR"] = str(_tmp / "raw")
os.environ["ONIONLENS_NER"] = "regex"
os.environ["ONIONLENS_AUTO_COLLECT"] = ""


@pytest.fixture(scope="session")
def loaded_db():
    from onionlens.db import init_db, session_scope
    from onionlens.pipeline import run_collector

    init_db()
    with session_scope() as s:
        stats = run_collector("demo", s, documents=120, victims=40)
    return stats
