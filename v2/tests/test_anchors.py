"""Anchor re-resolution (protocol v0.3 §1.5): every printed anchor ID checked against SPARTA v4.0.1;
problems flagged, never silently mapped. The fixture is the stored result; a change is a finding to log."""
import json

import pytest

from phalanx import anchors
from phalanx.workspace import Workspace

from conftest import FIXTURES


@pytest.fixture(scope="module")
def res(ws):
    return anchors.resolve(anchors.load(ws.root / "anchors" / "published_mappings.json"), ws.catalog)


def test_matches_stored_fixture(res):
    assert res == json.loads((FIXTURES / "anchor_resolution.json").read_text(encoding="utf-8"))


def _row(res, anchor, pid):
    return next(r for r in res["rows"] if r["anchor"] == anchor and r["printed_id"] == pid)


@pytest.mark.parametrize("anchor, pid, status, suggestion", [
    ("SPYCHAIN-2025", "IA-0009.0", "malformed", "IA-0009.02"),
    ("FROSETH-2024", "REC-0003", "label_mismatch", "RD-0003"),        # printed "Obtain Cyber Capabilities"
    ("FROSETH-2024", "IA-0004.01", "label_mismatch", "IA-0004"),      # granularity slip
    ("FROSETH-2024", "IMP-0002", "deprecated", None),
])
def test_known_defects_are_flagged_not_mapped(res, anchor, pid, status, suggestion):
    r = _row(res, anchor, pid)
    assert r["status"] == status and not r["usable_as_is"]
    assert r["printed_id"] == pid                       # the printed ID is kept as printed
    if suggestion:
        assert suggestion in r["suggestions"]


def test_protocol_counts(res):
    pa = res["per_anchor"]
    assert pa["FROSETH-2024"]["assertions"] == 9 and pa["FROSETH-2024"]["usable_as_is"] == 6
    assert pa["SPYCHAIN-2025"]["assertions"] == 17 and pa["SPYCHAIN-2025"]["by_status"]["deprecated"] == 4
    assert {a for a, c in pa.items() if c["gate_role"] == "native"} == \
        {"OPS-SAT-SPARTA", "FROSETH-2024", "SPYCHAIN-2025", "EAR-CH6-SPARTA"}
    assert res["descriptive_not_resolved"] == ["VIASAT-KA-SAT"]


def test_opssat_from_primary_source_differs_from_protocol(res):
    """Protocol §1.5 expects 10/11 OPS-SAT tokens and 16 of 20 pooled, taken from a secondary blog that misprints
    EX-0012.06 as EX-0007.02 and omits two IDs. The primary post (hyperlinked IDs) gives 12 executed IDs, all
    usable -> OPS-SAT + Frøseth = 18 of 21. Kept as a finding, not re-pinned."""
    pa = res["per_anchor"]
    assert (pa["OPS-SAT-SPARTA"]["assertions"], pa["OPS-SAT-SPARTA"]["usable_as_is"]) == (12, 12)
    assert _row(res, "OPS-SAT-SPARTA", "EX-0012.06")["raw_token"] == "/technique/EX-0012/06/"
    usable = pa["OPS-SAT-SPARTA"]["usable_as_is"] + pa["FROSETH-2024"]["usable_as_is"]
    total = pa["OPS-SAT-SPARTA"]["assertions"] + pa["FROSETH-2024"]["assertions"]
    assert (usable, total) == (18, 21)
    assert pa["OPS-SAT-SPARTA"]["not_executed_listed"] == 4          # EX-0012.08/.09, EXF-0003, IMP-0001


def test_secondary_transcription_reproduces_the_protocol_basis(res):
    """The protocol's 10/11 and 16/20 rest on the secondary blog; resolving that list gives 9 of 10 and,
    with Frøseth, 15 of 19. The gap to 18/21 comes from the source used, not from a missing token."""
    pa = res["per_anchor"]
    sec = pa["OPS-SAT-SPARTA-SECONDARY"]
    assert sec["gate_role"] == "secondary_transcription" and (sec["assertions"], sec["usable_as_is"]) == (10, 9)
    assert _row(res, "OPS-SAT-SPARTA-SECONDARY", "EX-0007.02")["status"] == "not_found"
    assert (sec["usable_as_is"] + pa["FROSETH-2024"]["usable_as_is"],
            sec["assertions"] + pa["FROSETH-2024"]["assertions"]) == (15, 19)


@pytest.mark.parametrize("anchor, pid, status", [
    ("FROSETH-2024", "REC-0005.04", "label_widened"),     # RF -> RF/Optical: scope changed
    ("FROSETH-2024", "DE-0009", "label_cosmetic"),        # "(CCD)" abbreviation added
    ("SPYCHAIN-2025", "EX-0002", "label_cosmetic"),       # "(PNT)" abbreviation added
    ("OPS-SAT-SPARTA", "PER-0002.02", "label_cosmetic"),  # word order only
])
def test_cosmetic_and_widened_labels_are_told_apart(res, anchor, pid, status):
    r = _row(res, anchor, pid)
    assert r["status"] == status and r["usable_as_is"]


def test_malformed_id_in_anchor_file_is_reported(tmp_ws):
    root, edit, _ = tmp_ws
    edit("anchors/published_mappings.json",
         lambda a: next(x for x in a["anchors"] if x["id"] == "EAR-CH6-SPARTA")["assertions"].append({"step": "x", "printed_id": "EX-12", "printed_label": None, "locator": "t"}))
    ws = Workspace(root)
    r = anchors.resolve(anchors.load(root / "anchors" / "published_mappings.json"), ws.catalog)
    assert _row(r, "EAR-CH6-SPARTA", "EX-12")["status"] == "malformed"


def test_linkage_rows_resolve_quote_their_sources_and_flag_tr52(ws):
    """Approved linkage (main links only): every ET exists in the Annex C tuple, its ENISA quote is part of that ET's
    description, the anchor quote occurs exactly once in the anchor's vault note, and TR52 links are flagged as tuned before linkage."""
    import csv
    import re as _re
    from phalanx.baselines import FRAMEWORK
    with open(FRAMEWORK / "enisa_threats_tuple.csv", encoding="utf-8-sig", newline="") as f:
        desc = {r["ID"]: _re.sub(r"\s+", " ", r["Threat Description (ENISA)"]).strip() for r in csv.DictReader(f)}
    d = json.loads((ws.root / "anchors" / "et_linkage.json").read_text(encoding="utf-8"))
    known = {a["id"] for a in anchors.load(ws.root / "anchors" / "published_mappings.json")["anchors"]}
    vault = ws.root.parents[3]
    has_vault = (vault / "research" / "notes").is_dir()
    for a in d["anchors"]:
        assert a["anchor_id"] in known and a["linkage"]
        for row in a["linkage"]:
            assert row["enisa_quote"] in desc[row["et_id"]], row["et_id"]
            assert row["rationale"] and row["tuned_before_linkage"] == (row["et_id"] == "TR52")
            note = vault / row["anchor_note"]
            if has_vault:
                assert note.exists(), row["anchor_note"]
                assert note.read_text(encoding="utf-8").count(row["anchor_quote"]) == 1, (a["anchor_id"], row["et_id"])

def _vault_notes(ws):
    vault = ws.root.parents[3]                                   # research workspace holding research/notes
    if not (vault / "research" / "notes").is_dir():
        pytest.skip("research vault not present on this machine")
    return vault


def test_every_transcribed_quote_locates_exactly_one_place_in_its_vault_note(ws):
    """Locators are verbatim quotes, not line numbers (note curation rewrites frontmatter and shifts lines).
    A quote must occur exactly once, so it cannot silently match a different row."""
    vault = _vault_notes(ws)
    bad = []
    for a in anchors.load(ws.root / "anchors" / "published_mappings.json")["anchors"]:
        if not a["assertions"]:
            continue
        text = (vault / a["vault_note"].split(" ")[0]).read_text(encoding="utf-8")
        bad += [(a["id"], s["quote"], text.count(s["quote"])) for s in a["assertions"] if text.count(s["quote"]) != 1]
    assert bad == []


def test_b1_input_quotes_lie_inside_their_step_section(ws):
    """TIDs repeat across steps (TID-307, TID-308 are in steps 2 and 4), so each is checked within its step."""
    vault = _vault_notes(ws)
    b1 = json.loads((ws.root / "anchors" / "opssat_emb3d.json").read_text(encoding="utf-8"))
    text = (vault / b1["vault_note"]).read_text(encoding="utf-8")
    bad = []
    for s in b1["steps"]:
        assert text.count(s["step_quote"]) == 1, s["step_quote"]
        start = text.index(s["step_quote"]) + len(s["step_quote"])
        nxt = text.find("**Step", start)
        section = text[start:nxt if nxt != -1 else None]
        quotes = [t["quote"] for t in s["emb3d_tids"]] + s["sparta_quotes"]
        bad += [(s["step"], q, section.count(q)) for q in quotes if section.count(q) != 1]
    assert bad == []
