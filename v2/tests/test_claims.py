"""SPARTA SV-* claims: a threat asserts SV statements; SPARTA's own related-to links supply candidates
(MAP-CG-05) and evidence; authored clauses take precedence; deprecated IMP links bridge to the live successors."""
import json

from phalanx import engine, pipeline
from phalanx.workspace import Workspace


def test_claimed_sv_generates_its_live_techniques_with_sv_evidence(ws):
    b = pipeline.run(ws, "TR54", ["SI-TR54-RF-OPEN"])
    mrs = {m["technique"]: m for m in b["results"][0]["mrs"]}
    linked = set(ws.catalog.sv["SV-IT-1"]["techniques"])
    live = {t for t in linked if not ws.catalog.is_deprecated(t)}
    assert live <= {t for t, m in mrs.items() if "MAP-CG-05" in m["generators"]}
    assert not any("MAP-CG-05" in mrs[t]["generators"] for t in linked - live if t in mrs)
    acc = mrs["IA-0008.01"]
    assert acc["status"] == "accepted" and acc["evidence_clause"] == "SV-IT-1"
    assert b["invariant_violations"] == []


def test_deprecated_impact_link_bridges_to_live_successors(ws):
    succ = ws.techniques["deprecation_successors"]
    links = engine.claim_links({"claims": [{"sv": "SV-AV-6", "quote": "q", "basis": "enisa_quote"}]}, ws.catalog, succ)
    assert set(succ) <= set(links)                       # SV-AV-6 relates only deprecated IMP-0002/3/4
    assert not any(ws.catalog.is_deprecated(t) for t in links)


def test_authored_clause_takes_precedence_over_claim(tmp_ws):
    root, edit, _ = tmp_ws
    edit("threats/TR52.json", lambda t: t.update(claims=[
        {"sv": "SV-MA-7", "quote": "overtaking control of the management segment to execute malicious commands",
         "basis": "enisa_quote"}]))
    m = {m["technique"]: m for m in pipeline.run(Workspace(root), "TR52", ["SI-TR52-A"])["results"][0]["mrs"]}
    assert m["IA-0007.02"]["evidence_clause"].startswith("ET-EV-")     # SV-MA-7 also links it; the clause wins


def test_claim_quote_and_sv_are_validated(tmp_ws):
    root, edit, _ = tmp_ws
    edit("threats/TR54.json", lambda t: t["claims"].extend([
        {"sv": "SV-IT-1", "quote": "not in the ENISA text", "basis": "enisa_quote"},
        {"sv": "SV-XX-9", "quote": "Spoofing", "basis": "enisa_quote"},
        {"sv": "SV-MA-6", "quote": "Spoofing", "basis": "enisa_quote"},
        {"sv": "SV-AC-1", "quote": "anything", "basis": "analyst_asserted"}]))
    errs = " | ".join(Workspace(root).validate(check_sources=False))
    assert "quote is not a verbatim part" in errs
    assert "SV-XX-9" in errs and "SV-MA-6: SPARTA relates no technique" in errs
    assert "needs an author" in errs
