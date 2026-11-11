"""Comparison methods (plan v5 §14.3): B2 scenario-only rules, B0 definition,
EvaluationCell normalization."""
import pytest

from phalanx import baselines, evaluation, pipeline
from phalanx.workspace import Workspace


def _mr(bundle, si, technique):
    r = next(r for r in bundle["results"] if r["si"]["si_id"] == si)
    return next(m for m in r["mrs"] if m["technique"] == technique)


@pytest.fixture(scope="module")
def b2(ws):
    return pipeline.run(ws, "TR52", method="B2")


def test_b2_has_no_graph_output_and_satisfies_invariants(b2):
    assert b2["invariant_violations"] == []
    for r in b2["results"]:
        assert r["boundary_verdicts"] == [] and r["afg"]["crossings"] == {}
        for m in r["mrs"]:
            reach = next((c for c in m["checks"] if c["code"] == "reachability"), None)
            if reach:   # prep techniques stop before reachability
                assert "scenario-only" in reach["detail"] and "edge" not in reach["detail"]


def test_b2_still_checks_scenario_facts(b2):
    """Safe mode is an SI fact, not a graph fact: B2 must still leave IA-0010 open when it is unknown."""
    assert _mr(b2, "SI-TR52-B", "IA-0010")["root_facts"][-1] == "SI.platform_state.safe_mode"
    assert "SI.platform_state.safe_mode" not in _mr(b2, "SI-TR52-B'", "IA-0010")["root_facts"]


@pytest.mark.parametrize("protection, status, facts", [
    ({"E-TCUL": {"sdls_auth": False}, "E-RF": {"sdls_auth": True}}, "rejected", []),
    ({"E-TCUL": {"sdls_auth": False}, "E-RF": {"sdls_auth": False}}, None, []),
    ({"E-TCUL": {"sdls_auth": False}, "E-RF": {"sdls_auth": "unknown"}}, "unresolved",
     ["SI.protection_applied.E-RF.sdls_auth"]),
])
def test_b2_authority_reads_protection_without_choosing_an_edge(tmp_ws, protection, status, facts):
    root, edit, _ = tmp_ws
    edit("scenarios/TR52/C.json", lambda si: si.__setitem__("protection_applied", protection))
    m = _mr(pipeline.run(Workspace(root), "TR52", ["SI-TR52-C"], method="B2"), "SI-TR52-C", "IA-0008.01")
    auth = next(c for c in m["checks"] if c["code"] == "authority")
    assert auth["result"] == {"rejected": "fail", None: "pass", "unresolved": "unknown"}[status]
    if status:
        assert m["status"] == status
    assert [f for f in m["root_facts"] if f.startswith("SI.protection")] == facts


def test_b0_is_the_v1_mapping_for_every_scenario(ws):
    sis = ws.scenarios["TR52"]
    b0 = baselines.run_b0("TR52", sis, pinned_sha256=ws.manifest.entries["phalanx_v1"]["sha256"])
    assert b0["applicable"] and b0["v1_record"]["ttp_status"].startswith("PENDING")   # v1 engine emits none
    assert {tuple(r["techniques"]) for r in b0["results"]} == {("IA-0007", "EX-0013.01", "IMP-0002", "IMP-0003")}


def test_b0_unmapped_corpus_threat_is_applicable_but_empty_and_unknown_threat_is_not(ws):
    si = [{"si_id": "SI-X"}]
    assert baselines.run_b0("TR01", si)["applicable"] is True
    assert baselines.run_b0("TR01", si)["results"][0]["techniques"] == []
    assert baselines.run_b0("TR99", si)["applicable"] is False


def test_cells_distinguish_not_generated_from_not_applicable():
    rows = evaluation.cells({
        "B3": {"S": {"applicable": True, "decisions": {"T1": "accepted", "T2": "rejected"}}},
        "B0": {"S": {"applicable": True, "decisions": {"T3": "accepted"}}},
        "B1": {"S": {"applicable": False, "decisions": {}}},
    })
    got = {(r["method_id"], r["technique_id"]): r["normalized_outcome"] for r in rows}
    assert got[("B0", "T1")] == "not_generated"
    assert got[("B3", "T3")] == "not_generated"
    assert {got[("B1", t)] for t in ("T1", "T2", "T3")} == {"not_applicable"}
    con = evaluation.contrast(rows, "B3", "B1")
    assert con["pairs"] == {} and con["excluded_not_jointly_applicable"] == {"S": 3}


def test_frozen_universe_is_independent_of_method_output():
    """A technique in U that no method proposes is not_generated for all; proposals outside U are not cells."""
    outputs = {"B3": {"S": {"applicable": True, "decisions": {"T1": "accepted", "T9": "rejected"}}},
               "B0": {"S": {"applicable": True, "decisions": {"T1": "accepted"}}}}
    rows = evaluation.cells(outputs, universe={"S": ["T1", "T2"]})
    got = {(r["method_id"], r["technique_id"]): r["normalized_outcome"] for r in rows}
    assert got == {("B0", "T1"): "accepted", ("B0", "T2"): "not_generated",
                   ("B3", "T1"): "accepted", ("B3", "T2"): "not_generated"}
