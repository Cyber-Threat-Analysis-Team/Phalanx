import json
import shutil
from pathlib import Path

import pytest

from phalanx import pipeline
from phalanx.workspace import DEFAULT_DATA, Workspace

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def ws():
    return Workspace(DEFAULT_DATA)


@pytest.fixture(scope="session")
def tr52(ws):
    return pipeline.run(ws, "TR52")


@pytest.fixture
def tmp_ws(tmp_path):
    """Editable copy of the authored data; the large pinned sources are symlinked, not copied."""
    root = tmp_path / "data"
    shutil.copytree(DEFAULT_DATA, root, ignore=shutil.ignore_patterns("sources"))
    (root / "sources").symlink_to(DEFAULT_DATA / "sources", target_is_directory=True)

    def edit(rel, fn):
        p = root / rel
        obj = json.loads(p.read_text(encoding="utf-8"))
        obj = fn(obj) or obj
        p.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")

    def write(rel, obj):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")

    return root, edit, write
