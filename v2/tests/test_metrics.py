"""Metric scripts (protocol v0.3 §1.6, §2.3). Anchor recovery is exercised on synthetic fixtures only; the TR52
numbers pinned here are development/regression values, not validation results."""
import copy
import json

import pytest

from phalanx import metrics, pipeline
from phalanx.workspace import Workspace


# ------------------------------------------------------------------ 1. anchor recovery (synthetic only)

def test_anchor_recovery_counts_exact_accepted_ids_only():
    decisions = {"SI-X": {"IA-0007.02": "accepted", "EX-0003": "unresolved", "EX-0009": "rejected",
                          "IA-0004": "accepted", "PER-0003": "accepted"}}
    assertions = {"SI-X": ["IA-0007.02", "EX-0003", "EX-0009", "IA-0004.01", "EX-9999", "IA-0007.02"]}
    r = metrics.anchor_recovery(decisions, assertions)["SI-X"]
    # duplicate printed ID counted once; parent IA-0004 accepted does NOT credit child IA-0004.01
    assert (r["asserted"], r["accepted"]) == (5, 1)
    assert r["proportion"] == pytest.approx(0.2)
    assert r["accepted_ids"] == ["IA-0007.02"]
    assert r["not_recovered"] == {"EX-0003": "unresolved", "EX-0009": "rejected",
                                  "EX-9999": "not_generated", "IA-0004.01": "not_generated"}


def test_anchor_recovery_full_none_and_empty_and_unseen_si():
    full = metrics.anchor_recovery({"S": {"A-1": "accepted", "B-2": "accepted"}}, {"S": ["A-1", "B-2"]})["S"]
    assert full["proportion"] == 1.0 and full["not_recovered"] == {}
    none = metrics.anchor_recovery({"S": {"A-1": "rejected"}}, {"S": ["A-1"], "T": ["B-2"], "U": []})
    assert none["S"]["accepted"] == 0 and none["S"]["proportion"] == 0.0
    assert none["T"]["not_recovered"] == {"B-2": "not_generated"}        # SI the method never ran
    assert none["U"]["proportion"] is None                                 # no assertions: no rate
    assert list(none) == ["S", "T", "U"]                                   # per SI, never pooled


# ------------------------------------------------------------------ 2. constructed negatives

@pytest.fixture(scope="module")
def negs(ws):
    return metrics.constructed_negatives(ws, "TR52")


def _find(negs, si, t, kind):
    (n,) = [n for n in negs["negatives"] if (n["si"], n["technique"], n["kind"]) == (si, t, kind)]
    return n


def test_negative_flips_accepted_cell_to_non_accepted_under_b3(ws, tr52, negs):
    base = {(r["si"]["si_id"], m["technique"]): m["status"] for r in tr52["results"] for m in r["mrs"]}
    assert base[("SI-TR52-A", "IA-0007.02")] == "accepted"
    # deleting the credential rejects; deleting the evidence clause leaves it open, never accepted (I6)
    assert _find(negs, "SI-TR52-A", "IA-0007.02", "credential")["outcomes"]["B3"] == "rejected"
    assert _find(negs, "SI-TR52-A", "IA-0007.02", "evidence_clause")["outcomes"]["B3"] == "unresolved"
    # deleting the only entry edge removes the foothold of an on-board step in B3, which B2 cannot see
    foot = _find(negs, "SI-TR52-A", "EX-0003", "foothold_edge")
    assert foot["outcomes"]["B3"] == "rejected" and foot["outcomes"]["B2"] == "accepted"
    # every negative starts from a B3-accepted fixture
    assert all(base[(n["si"], n["technique"])] == "accepted" for n in negs["negatives"])


def test_negative_rates_and_b3_decomposition(negs):
    m = negs["methods"]
    assert negs["universe"]["fixtures"] == 30 and negs["universe"]["negatives"] == 114
    assert (m["B3"]["accepted"], m["B3"]["rejected"], m["B3"]["unresolved"]) == (0, 84, 30)
    assert m["B3"]["rate"] == 0.0 and m["B2"]["rate"] == pytest.approx(30 / 114)
    # B2 accepts exactly the deletions it cannot see: graph-only preconditions
    assert {k for k, v in m["B2"]["by_kind"].items() if v.get("accepted")} == \
           {"architecture_edge", "foothold_edge", "origin_residence"}
    # candidate-list baselines: not_generated stays in the denominator and is never relabelled
    b0 = m["B0"]
    assert b0["applicable"] == 114 and b0["accepted"] + b0["not_generated"] == 114 and b0["accepted"] == 6
    assert "rejected" not in b0 and "unresolved" not in b0


def test_negative_removes_exactly_one_precondition(ws):
    ctx = metrics._context(ws, "TR52")
    si, variant = ws.scenarios["TR52"][0], ws.architectures["G-D53"]
    assert si["si_id"] == "SI-TR52-A"
    before = json.dumps([si, variant, ctx["rules"].evidence], sort_keys=True)
    cases = {
        "credential": ({}, lambda a, b: a["attacker"]["credential"] == "none"),
        "selected_asset": ({"assets": ["bus_cdhs"]}, lambda a, b: "bus_cdhs" not in a["selected_asset_instances"]
                           and "bus_com" in a["selected_asset_instances"]),
        "architecture_edge": ({"edge": "E-TCUL"}, lambda a, b: "E-TCUL" not in {e["id"] for e in b["edges"]}
                              and len(b["edges"]) == len(variant["edges"]) - 1),
        "protection_flag": ({"edge": "E-TCUL", "flag": "sdls_auth"},
                            lambda a, b: "sdls_auth" not in a["protection_applied"]["E-TCUL"]
                            and "sdls_antireplay" in a["protection_applied"]["E-TCUL"]),
    }
    for kind, (args, ok) in cases.items():
        a, b, r = metrics.apply_deletion({"kind": kind, "args": args}, si, variant, ctx["rules"])
        assert ok(a, b), kind
    a, b, r = metrics.apply_deletion({"kind": "evidence_clause", "args": {"technique": "IA-0007.02"}}, si, variant,
                                     ctx["rules"])
    assert "IA-0007.02" not in {t for c in r.evidence["clauses"].values() for t in c["techniques"]}
    assert "IA-0007" in {t for c in r.evidence["clauses"].values() for t in c["techniques"]}
    assert before == json.dumps([si, variant, ctx["rules"].evidence], sort_keys=True)   # inputs untouched


def test_required_fact_deletion_is_read_as_unknown_not_accepted(tmp_ws):
    """A technique whose profile requires a platform fact: once that fact is deleted it must not stay accepted."""
    root, edit, _ = tmp_ws
    edit("rules/techniques.json", lambda t: t["overrides"]["EX-0003"].update(requires_fact={"platform_state.safe_mode": True})
         if "EX-0003" in t["overrides"] else t["overrides"].__setitem__("EX-0003", {"requires_fact": {"platform_state.safe_mode": True}}))
    edit("scenarios/TR52/A.json", lambda si: si["platform_state"].update(safe_mode=True))
    w = Workspace(root)
    n = metrics.constructed_negatives(w, "TR52", ["SI-TR52-A"])
    neg = _find(n, "SI-TR52-A", "EX-0003", "requires_fact")
    assert neg["args"] == {"path": "platform_state.safe_mode"}
    assert neg["outcomes"]["B3"] == "unresolved"       # absence is 'unknown' to the engine, never a pass


# ------------------------------------------------------------------ 3. directional pass

@pytest.fixture(scope="module")
def exps(ws):
    return metrics.load_expectations(ws, "TR52")


def _views(w, scenario_ids=None):
    return {m: metrics.view(pipeline.run(w, "TR52", scenario_ids, method=m)) for m in ("B3", "B2")}


def test_catalogue_is_well_formed_and_marked_non_preregistered(ws, exps):
    assert exps["status"] == "development; written after TR52 results were seen, not pre-registered"
    ids = [e["id"] for e in exps["expectations"]]
    assert len(ids) == len(set(ids))
    sis = {s["si_id"] for s in ws.scenarios["TR52"]}
    for e in exps["expectations"]:
        assert e["kind"] in ("MFT", "INV", "DIR") and e["id"].startswith(e["kind"])
        assert e["relation"] in exps["relations"] and set(e["methods"]) <= {"B3", "B2", "B0"}
        used = set(e.get("sis", [])) | set(e.get("pair", [])) | ({e["si"]} if "si" in e else set())
        assert used and used <= sis, e["id"]
        for t in e["techniques"] if isinstance(e.get("techniques"), list) else []:
            assert t in ws.catalog.techniques, (e["id"], t)


def test_unperturbed_tr52_passes_every_b3_expectation(ws, exps):
    out = metrics.directional_pass(exps, _views(ws))["methods"]
    assert out["B3"]["violations"] == [] and out["B3"]["passed"] == out["B3"]["evaluated"] == 21
    # B2 has no foothold check: the on-board DIR-02 cells stay accepted for the rogue GS (a real B2 defect)
    assert {v["expectation"] for v in out["B2"]["violations"]} == {"DIR-02"}
    assert {v["technique"] for v in out["B2"]["violations"]} == {"EX-0012.10", "IMP-0008", "PER-0004"}
    # graph-based expectations are not evaluated for B2, they are not failed
    assert out["B2"]["evaluated"] == 16 and out["B2"]["rate"] == pytest.approx(15 / 16)


def test_expectation_violation_detected_when_scenario_is_perturbed(tmp_ws, exps):
    root, edit, _ = tmp_ws
    edit("scenarios/TR52/A.json", lambda si: si["attacker"].update(credential="none"))   # valid GS loses its credential
    out = metrics.directional_pass(exps, _views(Workspace(root)))["methods"]["B3"]
    bad = {v["expectation"] for v in out["violations"]}
    assert {"MFT-01", "DIR-01", "MFT-07"} <= bad          # accepted -> rejected, accepted->rejected pair, no crossing
    assert out["passed"] < out["evaluated"] and out["rate"] < 1
    cell = next(v for v in out["violations"] if v["expectation"] == "MFT-01" and v["technique"] == "IA-0007.02")
    assert cell["got"] == "rejected"


def test_architecture_invariance_violation_detected(tmp_ws, exps):
    """A_CONV differing in more than the architecture (here: intended effect) must trip INV-01."""
    root, edit, _ = tmp_ws
    edit("scenarios/TR52/A_CONV.json", lambda si: si.update(intended_effect=["C"]))
    out = metrics.directional_pass(exps, _views(Workspace(root)))["methods"]["B3"]
    assert "INV-01" in {v["expectation"] for v in out["violations"]}
    assert "INV-02" not in {v["expectation"] for v in out["violations"]}      # boundary sets still differ only by F1


def test_candidate_list_baseline_is_scenario_blind(ws, exps):
    from phalanx import baselines
    b0 = baselines.run_b0("TR52", ws.scenarios["TR52"], pinned_sha256=ws.manifest.entries["phalanx_v1"]["sha256"])
    out = metrics.directional_pass(exps, {"B0": metrics.list_view(b0)})["methods"]["B0"]
    assert out["evaluated"] == 2 and out["passed"] == 0
    # IA-0007 is accepted for valid and rogue GS alike: no change where the pair demands one
    assert {"expectation": "DIR-01", "pair": ["SI-TR52-A", "SI-TR52-B"], "technique": "IA-0007",
            "got": ["accepted", "accepted"]} in out["violations"]


def test_expectation_on_unselected_scenario_is_not_evaluated_rather_than_failed(ws, exps):
    out = metrics.directional_pass(exps, {"B3": _views(ws, ["SI-TR52-A"])["B3"]})["methods"]["B3"]
    assert out["violations"] == []
    assert {e["expectation"] for e in out["not_evaluated"]} >= {"DIR-01", "INV-01"}
    assert out["evaluated"] == out["passed"] and out["evaluated"] < 21
    assert {"DIR-01", "INV-01"} <= {e["expectation"] for e in out["not_evaluated"]}
    both_missing = metrics.directional_pass(exps, {"B3": {}})["methods"]["B3"]
    assert both_missing["evaluated"] == 0 and both_missing["not_evaluated"]


def test_report_without_expectation_catalogue_is_not_applicable(tmp_ws):
    root = tmp_ws[0]
    (root / "expectations" / "TR52.json").unlink()
    out = metrics.report(Workspace(root), "TR52", runs=2)["directional_pass"]
    assert out["status"] == "not_applicable: no expectation catalogue for TR52" and out["methods"] == {}


def test_b0_in_pipeline_reads_the_workspace_legacy_copy(tmp_ws):
    root = tmp_ws[0]
    (root / "legacy_v1" / "enisa_threats_tuple.csv").unlink()
    with pytest.raises(FileNotFoundError):
        pipeline.compare(Workspace(root), "TR52")


# ------------------------------------------------------------------ 4. decision-record completeness

def test_completeness_is_one_on_the_engine_output(ws, tr52):
    c = metrics.completeness(tr52, ws.vocabulary)
    assert c["mrs"] == 688 and c["complete"] == 688 and c["proportion"] == 1.0 and c["incomplete"] == []


def test_completeness_below_one_when_a_field_is_stripped(ws, tr52):
    b = copy.deepcopy(tr52)
    mrs = {s: [m for r in b["results"] for m in r["mrs"] if m["status"] == s] for s in ("accepted", "rejected", "unresolved")}
    del mrs["rejected"][0]["provenance"]["catalog"]
    mrs["accepted"][0]["supporting_evidence"] = []
    mrs["unresolved"][0]["root_facts"] = []
    mrs["unresolved"][1]["reason_codes"] = ["not_a_frozen_code"]
    mrs["rejected"][1]["opposing_evidence"] = []
    mrs["accepted"][1]["provenance"]["scenario"] = "SI-OTHER"
    c = metrics.completeness(b, ws.vocabulary)
    assert c["complete"] == c["mrs"] - 6 and c["proportion"] < 1
    missing = {i["mr"]: i["missing"] for i in c["incomplete"]}
    assert missing[mrs["rejected"][0]["mr_id"]] == ["provenance"]
    assert missing[mrs["accepted"][0]["mr_id"]] == ["evidence"]
    assert missing[mrs["unresolved"][0]["mr_id"]] == ["evidence"]
    assert missing[mrs["unresolved"][1]["mr_id"]] == ["reason_code"]
    assert missing[mrs["rejected"][1]["mr_id"]] == ["evidence"]
    assert missing[mrs["accepted"][1]["mr_id"]] == ["provenance"]


# ------------------------------------------------------------------ 5. replay

def test_replay_detects_hash_difference_and_decision_flip(tr52):
    same = metrics.replay_stats([tr52, copy.deepcopy(tr52), copy.deepcopy(tr52)])
    assert same["hash_equal"] and same["decision_flips"] == 0 and same["flip_rate"] == 0.0
    other = copy.deepcopy(tr52)
    m = next(m for m in other["results"][0]["mrs"] if m["status"] == "accepted")
    m["status"] = "unresolved"
    other["canonical_sha256"] = pipeline.canonical_hash({k: v for k, v in other.items() if k != "canonical_sha256"})
    r = metrics.replay_stats([tr52, other, tr52])
    assert not r["hash_equal"] and r["decision_flips"] == 1
    assert r["flipped"] == [f"{other['results'][0]['si']['si_id']}/{m['technique']}"]
    with pytest.raises(ValueError):
        metrics.replay_stats([tr52])


def test_real_reruns_replay_identically(ws):
    rs = metrics.replay_stats([pipeline.run(Workspace(ws.root), "TR52", ["SI-TR52-A"]) for _ in range(3)])
    assert rs["hash_equal"] and rs["decision_flips"] == 0 and rs["machines"] == 1


# ------------------------------------------------------------------ 6. unresolved rate / no coverage

def test_unresolved_rate_matches_engine_counts_and_reports_no_coverage_separately(tr52, tmp_ws):
    u = metrics.unresolved_rate(tr52)
    assert u["mrs"] == 688 and u["unresolved"] == 259 and u["rate"] == pytest.approx(259 / 688)
    assert u["by_si"]["SI-TR52-A"] == {"mrs": 112, "unresolved": 46, "rate": pytest.approx(46 / 112)}
    assert u["no_framework_coverage"] == {"sis": 0, "of": 6, "si_ids": []}
    # an SI nothing covers: counted as no_framework_coverage, with no MR and therefore no unresolved/rejected
    root, edit, write = tmp_ws
    edit("rules/techniques.json", lambda t: t.update(deprecation_successors=[], attacker_seeds={}))
    threat = json.loads((root / "threats/TR52.json").read_text())
    threat.update(id="TR99", name="Uncovered threat")
    threat.pop("crosswalk_key")
    write("threats/TR99.json", threat)
    si = json.loads((root / "scenarios/TR52/A.json").read_text())
    si.update(si_id="SI-TR99-A", threat="TR99")
    write("scenarios/TR99/A.json", si)
    u = metrics.unresolved_rate(pipeline.run(Workspace(root), "TR99"))
    assert u["no_framework_coverage"] == {"sis": 1, "of": 1, "si_ids": ["SI-TR99-A"]}
    assert u["mrs"] == 0 and u["unresolved"] == 0 and u["rate"] is None


# ------------------------------------------------------------------ bundle

def test_report_bundles_all_six_deterministically(ws):
    a = metrics.report(ws, "TR52", runs=2)
    b = metrics.report(Workspace(ws.root), "TR52", runs=2)
    assert a == b and a["metrics_sha256"] == b["metrics_sha256"]
    assert a["anchor_recovery"]["status"].startswith("not_applicable")
    assert a["constructed_negatives"]["methods"]["B3"]["rate"] == 0.0
    assert a["directional_pass"]["methods"]["B3"]["rate"] == 1.0
    for m in ("B3", "B2"):
        assert a["decision_record_completeness"][m]["proportion"] == 1.0
        assert a["replay"][m]["hash_equal"] and a["replay"][m]["decision_flips"] == 0
        assert a["unresolved"][m]["no_framework_coverage"]["sis"] == 0
    assert a["hashes"]["B3"] == pipeline.run(ws, "TR52")["canonical_sha256"]
