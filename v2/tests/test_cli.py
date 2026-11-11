import pytest

from phalanx import cli
from phalanx.workspace import Workspace


def _drop(key):
    return lambda obj: {k: v for k, v in obj.items() if k != key}


@pytest.mark.parametrize("rel, key", [("scenarios/TR52/A.json", "attacker"), ("architectures/G-D53.json", "edges"),
                                      ("rules/evidence/TR52.json", "clauses")])
def test_malformed_file_exits_1_with_problems(tmp_ws, capsys, rel, key):
    root, edit, _ = tmp_ws
    edit(rel, _drop(key))
    assert cli.main(["--data", str(root), "validate", "--skip-sources"]) == 1
    assert key in capsys.readouterr().out


def test_legacy_csv_pin_checks_the_workspace_copy(tmp_ws):
    root, _, _ = tmp_ws
    csv = root / "legacy_v1" / "enisa_threats_tuple.csv"
    csv.write_text(csv.read_text(encoding="utf-8-sig").replace("Seizure of control", "Seizure of kontrol"), encoding="utf-8")
    assert any("enisa_threats_tuple.csv sha256 differs" in e for e in Workspace(root).validate(check_sources=False))


def test_metrics_command_runs(capsys):
    assert cli.main(["metrics", "TR52", "-s", "SI-TR52-B", "--runs", "2"]) == 0
