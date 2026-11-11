"""Selector policy (protocol v0.3 §1.4) and invariant I8: broad ENISA selectors stay symbolic at ET level and
resolve only inside their documented scope, only against the SI's G."""
import collections
import copy
import csv
import hashlib
import json
from pathlib import Path

import pytest

from phalanx import invariants, pipeline, selectors
from phalanx.workspace import DEFAULT_DATA

V1_CSV = Path(__file__).resolve().parents[1] / "data" / "legacy_v1" / "enisa_threats_tuple.csv"
TTC = "Ground: TTC Ground (SLE/SDL protocol)"
BUS = "Space: BUS (CDHS/COM)"


@pytest.fixture(scope="module")
def reg(ws):
    return selectors.load_registry(ws)


def _si(ws, si_id):
    return next(s for s in ws.scenarios["TR52"] if s["si_id"] == si_id)


def _resolve(ws, reg, sels, si_id="SI-TR52-A", g=None):
    si = _si(ws, si_id)
    return selectors.resolve(sels, si, g or ws.architectures[si["variant"]], reg)


def _assets(block, i=0):
    return {a["asset"] for a in block["selectors"][i]["assets"]}


def _i8(block, reg, ws):
    return invariants.check_selector_resolution(block, reg, ws.architectures, "t")


# ------------------------------------------------------------------ the scope definitions

def test_registry_is_consistent(reg):
    assert selectors.validate_registry(reg) == []


def test_validate_registry_catches_defects(reg):
    bad = copy.deepcopy(reg)
    bad["selectors"][BUS]["components"][0]["class"] = "space.bus.nonexistent"
    bad["asset_classification"]["bus_com"]["classes"] = ["space.nope"]
    bad["selectors"]["Space: all assets"]["scope_basis"] = "assumed"      # assumed without a stated assumption
    errs = selectors.validate_registry(bad)
    assert len(errs) == 3 and any("nonexistent" in e for e in errs) and any("space.nope" in e for e in errs)


def test_class_scope_is_a_hierarchy_not_a_string_prefix():
    assert selectors.class_in_scope("space.bus.com", "space.bus")
    assert selectors.class_in_scope("space.bus.com", "space.bus.com")
    assert not selectors.class_in_scope("space.bus.comx", "space.bus.com")
    assert not selectors.class_in_scope("space.bus", "space.bus.com")        # a parent is not inside its child's scope


def test_selector_text_splitting_respects_brackets_and_inherits_segments():
    parts = selectors.split_selector_text(
        "Ground: Production (Document Management incl. Configuration Management System; Prototyping/IDE); "
        "Email servers, databases, OS; Ground & Space: SLE/SDL protocols")
    assert [p["segments"] for p in parts] == [["Ground"], ["Ground"], ["Ground", "Space"]]
    assert [p["segment_inherited"] for p in parts] == [False, True, False]
    assert parts[0]["clause"].endswith("Prototyping/IDE)")
    tagged = selectors.split_selector_text("Space: BUS (CDHS/COM) [satellite ops]; BUS (COM, antenna) [communications]")
    assert tagged[1]["segments"] == ["Space"] and tagged[1]["context"] == ["communications"]


@pytest.mark.skipif(not V1_CSV.exists(), reason="v1 prototype CSV not on this machine")
def test_registry_covers_exactly_the_58_enisa_threats(reg):
    raw = V1_CSV.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reg["source"]["sha256"]
    rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))
    assert len(rows) == 58 == reg["survey"]["threats"]
    seen = collections.defaultdict(list)
    for r in rows:
        for c in selectors.split_selector_text(r["A (affected assets)"]):
            seen[c["clause"]].append(r["ID"])
    assert set(seen) == set(reg["selectors"])
    assert {k: v["threats"] for k, v in reg["selectors"].items()} == dict(seen)
    forms = collections.Counter(v["form"] for v in reg["selectors"].values())
    assert dict(forms) == reg["survey"]["clauses_by_form"]
    assert len(seen) == reg["survey"]["distinct_clauses"]
    assert sorted({t for k, v in reg["selectors"].items() if v["form"] == "segment_wildcard" for t in v["threats"]}) \
        == reg["survey"]["wildcard_threats"]


def test_every_authored_threat_selector_has_a_documented_scope(ws, reg):
    for t in ws.threats.values():
        for s in t["affected_asset_selectors"]:
            assert s in reg["selectors"], s


# ------------------------------------------------------------------ resolution

def test_tr52_resolves_per_si_without_violations(ws, tr52):
    assert tr52["invariant_violations"] == []
    for r in tr52["results"]:
        block = r["selector_resolution"]
        assert block["state"] == "scoped_resolved", r["si"]["si_id"]
        assert [e["selector"] for e in block["selectors"]] == ws.threats["TR52"]["affected_asset_selectors"]
        assert block["si_selected"]["outside_resolved_scope"] == []
        # evidence names the node and the scope clause for every asset
        for e in block["selectors"]:
            for c in e["components"]:
                assert c["found"] and all(m["scope_clause"] == e["selector"] and m["node"] for m in c["matches"])


def test_tr52_bundle_records_registry_in_inputs(tr52):
    assert "data/selectors/enisa_asset_selectors.json" in tr52["inputs"]


def test_tr52_resolution_vs_hand_authored_candidate_assets(tr52):
    cmp = {r["si"]["si_id"]: r["selector_resolution"]["projection_comparison"] for r in tr52["results"]}
    conv = cmp["SI-TR52-A-CONV"]
    assert conv["agree"] and conv["resolved_assets"] == ["bus_cdhs", "bus_com", "ground_ttc"]
    # G-D53 also has a CDHS on the feeder satellite; the hand-authored candidate list does not name it
    d53 = cmp["SI-TR52-A"]
    assert d53["only_in_resolution"] == ["bus_cdhs_f"] and d53["only_in_candidate_assets"] == [] and not d53["agree"]
    assert all(c["only_in_candidate_assets"] == [] for c in cmp.values())


def test_b2_has_no_graph_so_selectors_stay_symbolic(ws):
    b2 = pipeline.run(ws, "TR52", method="B2")
    assert b2["invariant_violations"] == []
    for r in b2["results"]:
        block = r["selector_resolution"]
        assert block["state"] == "symbolic" and block["resolved_assets"] == []
        assert all(e["state"] == "symbolic" and e["assets"] == [] and e["scope"] for e in block["selectors"])


def test_symbolic_keeps_scope_and_resolves_nothing(reg):
    block = selectors.symbolic(["Space: all assets", "Space: not an ENISA clause"], reg)
    assert block["state"] == "symbolic" and block["resolved_assets"] == []
    known, unknown = block["selectors"]
    assert known["scope"][0]["class"] == selectors.WILDCARD and known["documented"]
    assert unknown["scope"] == [] and not unknown["documented"]
    with pytest.raises(ValueError):
        selectors.resolve([BUS], _si_stub("G-D53"), {"id": "G-CONV", "nodes": {}, "edges": []}, reg)


def _si_stub(variant):
    return {"si_id": "SI-X", "variant": variant, "selected_asset_instances": {}}


def test_wildcard_resolves_only_inside_its_segment_on_g_d53(ws, reg):
    space = _resolve(ws, reg, ["Space: all assets"])
    assert space["state"] == "scoped_resolved"
    assert _assets(space) == {"bus_cdhs", "bus_cdhs_f", "bus_com", "ran_du", "ran_cu"}
    assert {a["segment"] for a in space["selectors"][0]["assets"]} == {"Space"}
    ground = _resolve(ws, reg, ["Ground: all assets"])
    assert _assets(ground) == {"ground_moc", "ground_ttc", "fsw_update", "core_5gc", "integration_site"}
    # the adversary's station is a Ground asset by segment but never an affected asset
    comp = ground["selectors"][0]["components"][0]
    assert [x["asset"] for x in comp["excluded"]] == ["rogue_ttc"] and "rogue_ttc" not in _assets(ground)
    assert _i8(space, reg, ws) == [] and _i8(ground, reg, ws) == []


def test_wildcard_never_reaches_adversary_nodes_even_when_the_attacker_originates_there(ws, reg):
    si = copy.deepcopy(_si(ws, "SI-TR52-A"))
    si["attacker"]["origin_node"] = "rogue_gs"
    block = selectors.resolve(["Ground: all assets"], si, ws.architectures["G-D53"], reg)
    assert "rogue_ttc" not in _assets(block)


def test_named_class_selects_the_class_not_its_segment(ws, reg):
    block = _resolve(ws, reg, [BUS])
    assert _assets(block) == {"bus_cdhs", "bus_cdhs_f", "bus_com"}           # not ran_du: payload, not BUS
    ttc = _resolve(ws, reg, [TTC])
    assert _assets(ttc) == {"ground_ttc"}
    assert ttc["selectors"][0]["components"][0]["aspects_not_modelled_in_G"] == ["sle_sdl_protocol"]


def test_selector_with_missing_scope_is_unresolved(ws, reg):
    for sel in ("User: VSAT", "Human Resources: all assets", "User: all assets"):
        block = _resolve(ws, reg, [sel])
        assert block["state"] == "unresolved" and block["resolved_assets"] == []
        assert block["selectors"][0]["components"][0]["reason"]
    assert _i8(block, reg, ws) == []


def test_si_whose_g_lacks_the_scope_is_unresolved(ws, reg):
    g = copy.deepcopy(ws.architectures["G-D53"])
    g["nodes"] = {n: d for n, d in g["nodes"].items() if d["segment"] != "Space"}
    block = _resolve(ws, reg, [BUS, "Space: all assets"], g=g)
    assert block["state"] == "unresolved" and block["resolved_assets"] == []
    assert all(e["state"] == "unresolved" and e["assets"] == [] for e in block["selectors"])
    # one selector whose scope G represents, one it does not -> the SI is only partially resolved
    mixed = _resolve(ws, reg, ws.threats["TR52"]["affected_asset_selectors"], g=g)
    assert [e["state"] for e in mixed["selectors"]] == ["scoped_resolved", "unresolved"] and mixed["state"] == "partially_resolved"
    assert invariants.check_selector_resolution(mixed, reg, {"G-D53": g}, "t") == []


def test_partial_resolution_when_only_some_scope_is_represented(ws, reg):
    sel = "Space: BUS (CDHS & COM) & Payload (PDHS & PLCOM)"
    block = _resolve(ws, reg, [sel])
    e = block["selectors"][0]
    assert e["state"] == "partially_resolved" and block["state"] == "partially_resolved"
    found = {c["component"]: c["found"] for c in e["components"]}
    assert found == {"Space|space.bus.cdhs": True, "Space|space.bus.com": True,
                     "Space|space.payload.pdhs": False, "Space|space.payload.plcom": False}
    # ran_du/ran_cu are payload assets without a PDHS/PLCOM split: they must not be pulled into the subclasses
    assert _assets(block) == {"bus_cdhs", "bus_cdhs_f", "bus_com"}
    assert _i8(block, reg, ws) == []
    # the bare Payload parent class does cover them
    parent = _resolve(ws, reg, ["Space: BUS & Payload"])
    assert parent["state"] == "scoped_resolved" and {"ran_du", "ran_cu"} <= _assets(parent)


def test_protocol_only_selector_names_no_asset_and_stays_unresolved(ws, reg):
    block = _resolve(ws, reg, ["Ground & Space: SLE/SDL protocols"])
    assert block["state"] == "unresolved" and block["resolved_assets"] == []


def test_undocumented_selector_is_never_guessed(ws, reg):
    block = _resolve(ws, reg, ["Space: everything orbital"])
    e = block["selectors"][0]
    assert e["state"] == "unresolved" and not e["documented"] and e["assets"] == []
    assert _i8(block, reg, ws) == []


def test_resolution_is_deterministic_and_json_serializable(ws, reg):
    a, b = _resolve(ws, reg, [TTC, BUS]), _resolve(ws, reg, [TTC, BUS])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ------------------------------------------------------------------ I8

def _block(ws, reg, sels):
    return copy.deepcopy(_resolve(ws, reg, sels))


def _inject(block, i, asset, node, segment):
    entry = {"asset": asset, "node": node, "segment": segment, "scope_clause": block["selectors"][i]["selector"],
             "selected_by_si": False}
    block["selectors"][i]["assets"].append(entry)
    block["selectors"][i]["components"][0]["matches"].append({**entry, "component": block["selectors"][i]["components"][0]["component"]})
    block["resolved_assets"].append({"asset": asset, "node": node, "segment": segment, "selectors": [block["selectors"][i]["selector"]]})
    return block


@pytest.mark.parametrize("asset, node, segment", [
    ("ran_du", "sat_service", "Space"),          # right segment, wrong class (payload, not CDHS/COM)
    ("core_5gc", "core", "Ground"),              # right G, wrong segment
])
def test_i8_catches_expansion_outside_the_documented_scope(ws, reg, asset, node, segment):
    block = _inject(_block(ws, reg, [BUS]), 0, asset, node, segment)
    v = _i8(block, reg, ws)
    assert v and all(x.startswith("I8:") for x in v) and any("outside its documented scope" in x for x in v)


def test_i8_catches_adversary_node_inside_a_wildcard(ws, reg):
    block = _inject(_block(ws, reg, ["Ground: all assets"]), 0, "rogue_ttc", "rogue_gs", "Ground")
    v = _i8(block, reg, ws)
    assert any("adversary-side" in x for x in v)
    # without the graph the asset is class/segment-wise in scope; only the graph can tell it is adversary-side
    assert not any("adversary-side" in x for x in invariants.check_selector_resolution(block, reg, None, "t"))


def test_i8_catches_an_asset_claimed_from_the_wrong_node_or_segment(ws, reg):
    block = _inject(_block(ws, reg, [BUS]), 0, "bus_com", "gs_primary", "Space")
    assert any("is not in G-D53" in x for x in _i8(block, reg, ws))


def test_i8_catches_widened_scope_and_forged_state(ws, reg):
    widened = _block(ws, reg, [BUS])
    widened["selectors"][0]["scope"][0]["class"] = selectors.WILDCARD
    assert any("differs from its documented scope" in x for x in _i8(widened, reg, ws))
    forged = _block(ws, reg, ["Space: BUS (CDHS & COM) & Payload (PDHS & PLCOM)"])
    forged["selectors"][0]["state"] = "scoped_resolved"
    forged["state"] = "scoped_resolved"
    assert any("components found assets" in x for x in _i8(forged, reg, ws))
    leaky = selectors.symbolic([BUS], reg)
    leaky["selectors"][0]["assets"].append({"asset": "bus_com", "node": "sat_service", "segment": "Space"})
    assert any("yet lists assets" in x for x in _i8(leaky, reg, ws))


def test_i8_catches_resolution_of_an_undocumented_selector(ws, reg):
    block = _block(ws, reg, [BUS])
    block["selectors"][0]["selector"] = "Space: everything orbital"
    assert any("no documented scope" in x for x in _i8(block, reg, ws))


def test_i8_is_wired_into_check_bundle(ws, tr52, reg):
    bad = copy.deepcopy(tr52)
    r = next(r for r in bad["results"] if r["si"]["si_id"] == "SI-TR52-A")
    _inject(r["selector_resolution"], 1, "core_5gc", "core", "Ground")
    v = invariants.check_bundle(bad, ws.vocabulary, reg, ws.architectures)
    assert any(x.startswith("I8: SI-TR52-A:") for x in v)
    # the default registry is used when none is passed
    assert invariants.check_bundle(tr52, ws.vocabulary, reg, ws.architectures) == []
    dropped = copy.deepcopy(tr52)
    del dropped["results"][0]["selector_resolution"]
    assert any(x.startswith("I8:") and "no selector_resolution" in x
               for x in invariants.check_bundle(dropped, ws.vocabulary, reg, ws.architectures))


def test_pipeline_reports_a_resolver_that_escapes_its_scope(ws, monkeypatch):
    """If the resolver ever over-expands, pipeline.run surfaces it as an I8 violation instead of shipping it."""
    real = selectors.resolve

    def leaky(sels, si, g, registry, candidate_assets=None):
        block = real(sels, si, g, registry, candidate_assets)
        if g is not None:
            _inject(block, 1, "core_5gc", "core", "Ground")
        return block

    monkeypatch.setattr(selectors, "resolve", leaky)
    out = pipeline.run(ws, "TR52", ["SI-TR52-A"])
    assert [x for x in out["invariant_violations"] if x.startswith("I8:")]
