"""Negative cases: each invariant detects the defect it exists for (protocol v0.3 I1-I12)."""
import copy

import pytest

from phalanx import invariants, selectors
from phalanx.workspace import Workspace


def _first(bundle, sid, status):
    r = next(r for r in bundle["results"] if r["si"]["si_id"] == sid)
    return r, next(m for m in r["mrs"] if m["status"] == status)


def _violations(bundle, ws):
    return invariants.check_bundle(bundle, ws.vocabulary, selectors.load_registry(ws), ws.architectures)


@pytest.mark.parametrize("mutate, code", [
    (lambda b: b["threat"].__setitem__("boundary_verdicts", []), "I1"),
    (lambda b: b["threat"]["projection"].__setitem__("applicable_boundary_roles", ["crossed"]), "I2"),
    (lambda b: _first(b, "SI-TR52-A", "accepted")[1]["checks"][-1].__setitem__("result", "unknown"), "I5"),
    (lambda b: _first(b, "SI-TR52-A", "unresolved")[1].__setitem__("status", "accepted"), "I6"),
    (lambda b: _first(b, "SI-TR52-A", "unresolved")[1].__setitem__("root_facts", []), "I6"),
    (lambda b: _first(b, "SI-TR52-A", "rejected")[1]["provenance"].pop("rules"), "I9"),
    (lambda b: _first(b, "SI-TR52-A", "rejected")[1]["reason_codes"].append("vibes"), "I12"),
    (lambda b: _first(b, "SI-TR52-B", "rejected")[0]["boundary_verdicts"][1].__setitem__("verdict", "crossed"), "I4"),
    (lambda b: _first(b, "SI-TR52-A", "accepted")[0].__setitem__("mrs", []), "I11"),
])
def test_invariant_catches_defect(ws, tr52, mutate, code):
    b = copy.deepcopy(tr52)
    mutate(b)
    assert any(v.startswith(code) for v in _violations(b, ws)), code


def test_authored_data_is_valid(ws):
    assert ws.validate() == []


@pytest.mark.parametrize("rel, mutate, needle", [
    # I10: unknown or deprecated SPARTA ids in authored rules
    ("rules/evidence/TR52.json", lambda e: e["clauses"]["ET-EV-03"]["techniques"].append("IA-9999"), "IA-9999 is not a SPARTA"),
    ("rules/techniques.json", lambda t: t["attacker_seeds"]["rogue_ground_station"].append("IMP-0002"), "IMP-0002 is deprecated"),
    # I1: a threat file cannot carry realized output
    ("threats/TR52.json", lambda t: t.__setitem__("boundary_verdicts", []), "Additional properties"),
    # cross-references
    ("scenarios/TR52/A.json", lambda s: s["selected_asset_instances"].__setitem__("bus_cdhs", "core"), "not on node core"),
    ("scenarios/TR52/A.json", lambda s: s.__setitem__("variant", "G-NONE"), "unknown variant"),
    ("architectures/G-D53.json", lambda g: g["edges"][0].__setitem__("role", "TB2"), "not in vocabulary.boundary_roles"),
])
def test_validation_rejects_bad_input(tmp_ws, rel, mutate, needle):
    root, edit, _ = tmp_ws
    edit(rel, mutate)
    errs = Workspace(root).validate(check_sources=False)
    assert any(needle in e for e in errs), errs


def test_evidence_clause_must_quote_the_threat_description(tmp_ws):
    root, edit, _ = tmp_ws
    edit("rules/evidence/TR52.json", lambda e: e["clauses"]["ET-EV-01"].update(clause="taking control of space assets by any means"))
    errs = Workspace(root).validate(check_sources=False)
    assert any("ET-EV-01" in e and "verbatim" in e for e in errs)


def test_crosswalk_key_without_a_workbook_row_fails_validation(tmp_ws):
    root, edit, _ = tmp_ws
    edit("threats/TR52.json", lambda t: t.update(crosswalk_key="Seizure of contrl"))
    errs = Workspace(root).validate(check_sources=False)
    assert any("crosswalk_key" in e for e in errs)


def test_threat_description_must_match_its_source_row(tmp_ws):
    """Evidence clauses quote the description; the description must in turn be the Annex C tuple cell."""
    root, edit, _ = tmp_ws
    edit("threats/TR52.json", lambda t: t.update(description=t["description"] + " Added by hand."))
    edit("rules/evidence/TR52.json", lambda e: None)
    errs = Workspace(root).validate(check_sources=False)
    assert any("description differs" in e for e in errs)
