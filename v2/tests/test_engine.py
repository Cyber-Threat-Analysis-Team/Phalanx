"""Behaviour of the decision engine on TR52 (plan v5 Phase 2 vertical slice)."""
import copy
import json

from phalanx import pipeline
from phalanx.workspace import Workspace

from conftest import FIXTURES


def test_reproduces_pilot_decisions(tr52):
    """Every decision, reason code, missing fact, flow, crossing, verdict and finding equals the TR52 pilot.
    When a rule change is intended, regenerate the fixture with `phalanx outcomes` and log the change."""
    golden = json.loads((FIXTURES / "tr52_pilot_outcomes.json").read_text(encoding="utf-8"))
    assert pipeline.outcomes(tr52) == golden["scenarios"]
    assert tr52["t1_baseline"] == golden["t1"]


def test_same_inputs_same_hash(ws, tr52):
    again = pipeline.run(Workspace(ws.root), "TR52")
    assert again["canonical_sha256"] == tr52["canonical_sha256"]


def test_tr52_satisfies_all_invariants(tr52):
    assert tr52["invariant_violations"] == []


def _by_id(bundle):
    return {r["si"]["si_id"]: r for r in bundle["results"]}


def test_scenario_changes_the_answer(tr52):
    """Same threat, different attacker: the valid-GS chain is accepted, the rogue-GS one is not."""
    r = _by_id(tr52)
    status = lambda sid, t: next(m["status"] for m in r[sid]["mrs"] if m["technique"] == t)
    assert status("SI-TR52-A", "IA-0007.02") == "accepted"
    assert status("SI-TR52-B", "IA-0007.02") == "rejected"
    assert status("SI-TR52-B", "IA-0008.01") == "rejected"      # SDLS on
    assert status("SI-TR52-C", "IA-0008.01") == "unresolved"    # SDLS unknown
    assert {v["edge"]: v["verdict"] for v in r["SI-TR52-A"]["boundary_verdicts"]}["E-TCUL"] == "crossed"
    assert {v["edge"]: v["verdict"] for v in r["SI-TR52-B"]["boundary_verdicts"]}["E-TCUL"] == "applicable"


def test_architecture_contrast_differs_only_where_tr52_has_no_asset(tr52):
    """G-D53 vs G-CONV: TR52 selects no asset on F1, so decisions agree and only the F1 edge disappears."""
    r = _by_id(tr52)
    d53, conv = r["SI-TR52-A"], r["SI-TR52-A-CONV"]
    strip = lambda res: {m["technique"]: (m["status"], m["reason_codes"]) for m in res["mrs"]}
    assert strip(d53) == strip(conv)
    v53 = {v["edge"]: v["verdict"] for v in d53["boundary_verdicts"]}
    vconv = {v["edge"]: v["verdict"] for v in conv["boundary_verdicts"]}
    assert set(v53) - set(vconv) == {"E-F1"}
    assert {k: v for k, v in v53.items() if k != "E-F1"} == vconv


def test_attacker_infrastructure_only_in_its_scenarios(tr52):
    r = _by_id(tr52)
    assert "E-RF" not in {v["edge"] for v in r["SI-TR52-A"]["boundary_verdicts"]}
    assert "E-RF" in {v["edge"] for v in r["SI-TR52-B"]["boundary_verdicts"]}


# ---- Gate B failure tests: removing a basis never leaves an acceptance in place (I6)

def test_removing_an_evidence_clause_unresolves_instead_of_accepting(ws):
    ev = copy.deepcopy(ws.evidence("TR52"))
    ev["clauses"]["ET-EV-03"]["techniques"].remove("IA-0007.02")
    a = _by_id(pipeline.run(ws, "TR52", ["SI-TR52-A"], evidence=ev))["SI-TR52-A"]
    m = next(m for m in a["mrs"] if m["technique"] == "IA-0007.02")
    assert m["status"] == "unresolved" and m["root_facts"] == ["ET-linked evidence"]
    # without the only accepted entry, nothing on board can be accepted either
    assert not [m for m in a["mrs"] if m["status"] == "accepted" and m["tactic"] in ("Execution", "Impact")]


def test_without_any_evidence_nothing_is_accepted(ws):
    ev = copy.deepcopy(ws.evidence("TR52"))
    ev["clauses"] = {}
    b = pipeline.run(ws, "TR52", evidence=ev)
    assert b["invariant_violations"] == []
    assert all(m["status"] != "accepted" for r in b["results"] for m in r["mrs"])


def test_forgetting_a_system_fact_turns_rejections_into_unresolved(tmp_ws):
    """B' differs from B only in safe_mode=False. Making it unknown again must reproduce B, not accept anything."""
    root, edit, _ = tmp_ws
    edit("scenarios/TR52/Bp.json", lambda si: si["platform_state"].update(safe_mode="unknown"))
    r = _by_id(pipeline.run(Workspace(root), "TR52"))
    bp, b = r["SI-TR52-B'"], r["SI-TR52-B"]
    assert [(m["technique"], m["status"], m["root_facts"]) for m in bp["mrs"]] == \
           [(m["technique"], m["status"], m["root_facts"]) for m in b["mrs"]]
    assert any("SI.platform_state.safe_mode" in m["root_facts"] for m in bp["mrs"])


def test_zero_candidates_reports_no_coverage_not_rejection(tmp_ws):
    """I11: a threat no generator reaches yields no decisions and a no_framework_coverage finding."""
    root, edit, write = tmp_ws
    edit("rules/techniques.json", lambda t: t.update(deprecation_successors=[], attacker_seeds={}))
    threat = json.loads((root / "threats/TR52.json").read_text())
    threat.update(id="TR99", name="Uncovered threat")
    threat.pop("crosswalk_key")
    write("threats/TR99.json", threat)
    si = json.loads((root / "scenarios/TR52/A.json").read_text())
    si.update(si_id="SI-TR99-A", threat="TR99")
    write("scenarios/TR99/A.json", si)
    b = pipeline.run(Workspace(root), "TR99")
    (res,) = b["results"]
    assert res["mrs"] == []
    assert [a["type"] for a in res["af"]] == ["no_framework_coverage"]
    assert b["invariant_violations"] == []
