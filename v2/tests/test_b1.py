"""B1 (published EMB3D crosswalk, descriptive benchmark) and B1b (keyword crosswalk, sensitivity analysis).
Protocol §1.6: the OPS-SAT fixture numbers are asserted; a disagreement is a finding, never a re-pin."""
import json

import pytest

from phalanx import baselines, pipeline
from phalanx.sources import Catalog


@pytest.fixture(scope="module")
def b1(ws):
    return baselines.run_b1(json.loads((ws.root / "anchors" / "opssat_emb3d.json").read_text(encoding="utf-8")),
                            ws.catalog)


def test_b1_reproduces_candidates_and_coverage(b1):
    assert b1["emitted"] == 46
    assert b1["asserted"] == 9 and b1["covered"] == 4
    assert b1["coverage"] == {"exact": 3, "parent_child": 1, "missed": 5}


@pytest.mark.xfail(strict=True, reason="the literal same-step counting rule counts 7 of 46 (15.2%), "
                                       "not the protocol's 8 (17.4%)")
def test_b1_protocol_counted_figure(b1):
    assert (b1["counted"], b1["precision"]) == (8, 0.1739)


def test_b1_counting_rule_is_same_step_only(b1):
    """EX-0009 is asserted in step 1 but emitted in steps 3 and 4: it counts in step 3 (parent of the step-3
    assertion EX-0009.02) and not in step 4, where nothing EX-0009-related is asserted."""
    step = {s["step"].split()[0]: s for s in b1["steps"]}
    assert "EX-0009" in step["3"]["counted"]
    assert "EX-0009" in step["4"]["candidates"] and "EX-0009" not in step["4"]["counted"]
    assert b1["counted"] == 7


def _cat(**techs):
    return Catalog("test", {tid: {"name": n, "tactic": "x", "description": d, "deprecated": dep, "emb3d": e}
                            for tid, (n, d, dep, e) in techs.items()})


def test_b1_parent_child_both_directions_and_unknown_tid():
    cat = _cat(**{"EX-0001": ("p", "", False, ["TID-1"]), "EX-0002.01": ("c", "", False, ["TID-1"]),
                  "EX-0003": ("u", "", False, ["TID-2"])})
    r = baselines.run_b1({"steps": [{"step": "s", "emb3d_tids": [{"tid": "TID-1"}, {"tid": "TID-9"}],
                                     "sparta_asserted": ["EX-0001.04", "EX-0002"]}]}, cat)
    assert r["steps"][0]["candidates"] == ["EX-0001", "EX-0002.01"]     # TID-9 maps to nothing; TID-2 not asked
    assert r["coverage"] == {"exact": 0, "parent_child": 2, "missed": 0}


def test_b1b_needs_every_label_word_and_skips_deprecated():
    cat = _cat(**{"A-0001": ("Jam the link", "seizure of control", False, []),
                  "A-0002": ("Control", "only control", False, []),
                  "A-0003": ("[DEPRECATED] Seize", "seizures and controls", True, []),
                  "A-0004": ("Hijack", "Seizures of Controls", False, [])})
    r = baselines.run_b1b({"id": "T", "name": "Seizure of control"}, [{"si_id": "S"}], cat)
    assert r["results"][0]["techniques"] == ["A-0001", "A-0004"]       # plural and case folded; partial fails


def test_compare_codes_b1_not_applicable_and_b1b_as_candidate_list(ws):
    res = pipeline.compare(ws, "TR52", ["SI-TR52-A"])
    by_method = {}
    for c in res["cells"]:
        by_method.setdefault(c["method_id"], set()).add(c["normalized_outcome"])
    assert by_method["B1"] == {"not_applicable"}
    assert by_method["B1b"] <= {"accepted", "not_generated"}
