"""Schema coverage of real outputs, SI/ETP/G additions, G-CONV vs G-D53 differences, credential-only negative test."""
import collections

import jsonschema
import pytest

from phalanx import pipeline
from phalanx.workspace import Workspace, schema


def _validator(name):
    return jsonschema.Draft202012Validator(schema(name))


def test_every_af_finding_validates(tr52):
    v = _validator("attack_flow")
    kinds = set()
    for r in tr52["results"]:
        for a in r["af"]:
            assert not list(v.iter_errors(a)), a
            kinds.add(a["type"])
    assert {"unreachable", "missing_system_state"} <= kinds   # real outputs exercise more than one shape


@pytest.mark.parametrize("bad", [
    {"type": "unreachable"},                                    # detail missing
    {"type": "no_framework_coverage", "detail": "x", "mr_id": "MR-1"},  # no MR for non-generation (I11)
    {"type": "missing_system_state", "mr_id": "MR-1", "facts": []},
    {"type": "invented", "detail": "x"},
])
def test_af_schema_rejects(bad):
    assert list(_validator("attack_flow").iter_errors(bad))


def test_no_framework_coverage_finding_validates():
    assert not list(_validator("attack_flow").iter_errors({"type": "no_framework_coverage", "detail": "none proposed",
            "rule": "MAP-CHK-12", "rule_version": "0.1.0-draft"}))


@pytest.fixture(scope="module")
def compared(ws):
    return pipeline.compare(ws, "TR52")


def test_every_cell_validates_and_is_unique(compared):
    v = _validator("evaluation_cell")
    cells = compared["cells"]
    assert cells
    for c in cells:
        assert not list(v.iter_errors(c)), c
    keys = [(c["method_id"], c["si_id"], c["technique_id"]) for c in cells]
    assert len(keys) == len(set(keys))
    # each (si, technique) appears exactly once per method, so every method sees the same universe
    per = collections.defaultdict(collections.Counter)
    for m, si, t in keys:
        per[(si, t)][m] += 1
    methods = {m for m, _, _ in keys}
    for (si, t), c in per.items():
        assert set(c) == methods and set(c.values()) == {1}, (si, t, c)


@pytest.mark.parametrize("bad", [
    {"method_id": "B3", "si_id": "SI-X", "technique_id": "IA-0007", "normalized_outcome": "crossed"},
    {"method_id": "B3", "si_id": "SI-X", "technique_id": "IA-0007", "normalized_outcome": "accepted", "mr_id": "MR-1"},
    {"method_id": "B3", "si_id": "SI-X", "technique_id": "ia7", "normalized_outcome": "accepted"},
])
def test_cell_schema_rejects(bad):
    assert list(_validator("evaluation_cell").iter_errors(bad))


def test_authoring_aid_optional_null_or_complete(ws):
    v = _validator("scenario")
    si = dict(ws.scenarios["TR52"][0])
    assert not list(v.iter_errors(si))
    assert not list(v.iter_errors({**si, "authoring_aid": None}))
    aid = {"tool": "llm", "version": "1", "purpose": "draft label", "date": "2026-10-01"}
    assert not list(v.iter_errors({**si, "authoring_aid": aid}))
    assert list(v.iter_errors({**si, "authoring_aid": {k: x for k, x in aid.items() if k != "date"}}))
    assert list(v.iter_errors({**si, "authoring_aid": {**aid, "date": "yesterday"}}))


def test_threat_requires_derivation_provenance(ws):
    t = ws.threats["TR52"]
    assert t["projection"]["derivation_provenance"]["field"] == "L (lifecycle)"
    bad = {**t, "projection": {k: v for k, v in t["projection"].items() if k != "derivation_provenance"}}
    assert list(_validator("threat").iter_errors(bad))


def test_architecture_requires_domain_and_optionality(ws):
    g = ws.architectures["G-D53"]
    v = _validator("architecture")
    assert not list(v.iter_errors(g))
    import copy
    for mutate in (lambda x: x["nodes"]["core"].pop("security_domain"),
                   lambda x: x["edges"][0].pop("use_optionality"),
                   lambda x: x["edges"][0].update(use_optionality="sometimes"),
                   lambda x: x["nodes"]["core"].update(security_domain_basis="plausible")):   # must say source:/assumed:
        bad = copy.deepcopy(g)
        mutate(bad)
        assert list(v.iter_errors(bad))


def test_crossing_flag_must_match_endpoint_domains(tmp_ws):
    root, edit, _ = tmp_ws
    def flip(g):
        for e in g["edges"]:
            if e["id"] == "E-NG":
                e["crosses_security_domain"] = not e["crosses_security_domain"]

    edit("architectures/G-D53.json", flip)
    errs = Workspace(root).validate(check_sources=False)
    assert any("E-NG" in e and "crosses_security_domain" in e for e in errs)


def test_functions_must_cover_exactly_the_node_assets(tmp_ws):
    root, edit, _ = tmp_ws
    edit("architectures/G-D53.json", lambda g: g["nodes"]["core"]["functions"].clear())
    assert any("core" in e and "functions" in e for e in Workspace(root).validate(check_sources=False))


# ---- Phase 1 exit: F1/Ng/CN locations and security-domain membership differ between G-CONV and G-D53
def _edge(g, eid):
    return next((e for e in g["edges"] if e["id"] == eid), None)


def _host(g, asset):
    return [n for n, v in g["nodes"].items() if asset in v["assets"]]


def test_gconv_and_gd53_differ_in_f1_ng_core_locations_and_domain_membership(ws):
    conv, d53 = ws.architectures["G-CONV"], ws.architectures["G-D53"]
    # F1: internal to the satellite in G-CONV (no edge, one gNB asset); an ISL edge between two satellites in G-D53
    assert _edge(conv, "E-F1") is None
    assert _host(conv, "ran_gnb") == ["sat_service"] and _host(conv, "ran_du") == [] and _host(conv, "ran_cu") == []
    f1 = _edge(d53, "E-F1")
    assert (f1["src"], f1["dst"]) == ("sat_service", "sat_feeder")
    assert _host(d53, "ran_du") == ["sat_service"] and _host(d53, "ran_cu") == ["sat_feeder"]
    # Ng: leaves the service satellite in G-CONV, the feeder satellite (CU host) in G-D53
    assert _edge(conv, "E-NG")["src"] == "sat_service" and _edge(d53, "E-NG")["src"] == "sat_feeder"
    # CN endpoint is on the ground core node in both; the Ng link is space->ground in both
    assert _host(conv, "core_5gc") == _host(d53, "core_5gc") == ["core"]
    for g in (conv, d53):
        ng = _edge(g, "E-NG")
        assert (g["nodes"][ng["src"]]["segment"], g["nodes"][ng["dst"]]["segment"]) == ("Space", "Ground")
    # security-domain membership of the RAN functions differs: G-D53 puts DU and CU (F1 endpoints) in a domain, G-CONV the gNB
    member = lambda g: {a: n["security_domain"] for n in g["nodes"].values() for a in n["assets"]}
    mc, md = member(conv), member(d53)
    assert mc != md
    assert {"ran_du", "ran_cu"} <= set(md) - set(mc) and "ran_gnb" in set(mc) - set(md)
    # F1 stays inside one security domain (Zb): crossing flag false, use optional; Ng crosses (Za): mandatory
    assert f1["crosses_security_domain"] is False and f1["use_optionality"] == "optional"
    for g in (conv, d53):
        ng = _edge(g, "E-NG")
        assert ng["crosses_security_domain"] is True and ng["use_optionality"] == "mandatory"
    # what is NOT different must be visible too: the Ng crossing and core domain are identical under current data
    assert mc["core_5gc"] == md["core_5gc"]


def test_derived_crossings_follow_endpoint_domains(ws):
    for g in ws.architectures.values():
        for e in g["edges"]:
            same = g["nodes"][e["src"]]["security_domain"] == g["nodes"][e["dst"]]["security_domain"]
            assert e["crosses_security_domain"] is (not same), (g["id"], e["id"])
    # the rogue station is outside the operator's domain
    d53 = ws.architectures["G-D53"]
    assert next(e for e in d53["edges"] if e["id"] == "E-RF")["crosses_security_domain"] is True


# ---- Protocol §2.4: removing command authority alone changes the valid-GS decision
def test_credential_only_change_flips_authority_dependent_decisions(tmp_ws):
    root, edit, _ = tmp_ws
    base = {r["si"]["si_id"]: r for r in pipeline.run(Workspace(root), "TR52")["results"]}["SI-TR52-A"]
    edit("scenarios/TR52/A.json", lambda s: s["attacker"].update(credential="none"))  # returns None
    ws2 = Workspace(root)
    assert ws2.validate(check_sources=False) == []
    alt = {r["si"]["si_id"]: r for r in pipeline.run(ws2, "TR52")["results"]}["SI-TR52-A"]

    # the pair differs in exactly the credential
    diff = {k for k in base["si"] if base["si"][k] != alt["si"][k]}
    assert diff == {"attacker"}
    assert {k for k in base["si"]["attacker"] if base["si"]["attacker"][k] != alt["si"]["attacker"][k]} == {"credential"}
    assert base["si"]["attacker"]["origin_node"] == alt["si"]["attacker"]["origin_node"] == "gs_primary"
    assert base["si"]["protection_applied"] == alt["si"]["protection_applied"]

    b = {m["technique"]: m for m in base["mrs"]}
    a = {m["technique"]: m for m in alt["mrs"]}
    assert set(a) == set(b)                      # same candidate set: credentials do not change generation
    flipped = {t for t in b if b[t]["status"] != a[t]["status"]}

    def changed(t):
        return {cb["code"]: (cb["result"], ca["result"])
                for cb, ca in zip(b[t]["checks"], a[t]["checks"]) if cb["result"] != ca["result"]}

    authority_fail = {"authority": ("pass", "fail")}
    reach_unknown = {"reachability": ("pass", "unknown")}
    expected = {
        # the credential is what these steps need: authority fails, so they are rejected
        "IA-0007.02": ("accepted", "rejected", {**authority_fail, "evidence": ("pass", "not_applicable")}),
        "PER-0005": ("accepted", "rejected", {**authority_fail, **reach_unknown, "evidence": ("pass", "not_applicable")}),
        "DE-0011": ("unresolved", "rejected", {**authority_fail, **reach_unknown, "evidence": ("unknown", "not_applicable")}),
        "LM-0007": ("unresolved", "rejected", {**authority_fail, **reach_unknown, "evidence": ("unknown", "not_applicable")}),
        # downstream: with the accepted entry gone, the on-board foothold rests on an unresolved entry
        **{t: ("accepted", "unresolved", reach_unknown) for t in (
            "EX-0003", "EX-0005.01", "EX-0005.02", "EX-0009", "EX-0009.01", "EX-0009.02", "EX-0012.10",
            "IMP-0008", "IMP-0011", "IMP-0013", "PER-0004")},
    }
    assert {t: (b[t]["status"], a[t]["status"], changed(t)) for t in flipped} == expected
    # structure: every accepted Initial Access step that needed the credential (authority pass) is rejected now;
    # Initial Access steps still accepted never depended on it (authority not_applicable)
    auth = {t: next((c["result"] for c in b[t]["checks"] if c["code"] == "authority"), None) for t in b}
    gated = {t for t in b if b[t]["tactic"] == "Initial Access" and b[t]["status"] == "accepted" and auth[t] == "pass"}
    assert gated == {"IA-0007.02"} and a["IA-0007.02"]["status"] == "rejected"
    assert all(auth[t] == "not_applicable" for t in a if a[t]["tactic"] == "Initial Access" and a[t]["status"] == "accepted")
    for t in set(b) - flipped:                   # everything not gated on the credential is unchanged
        assert a[t]["status"] == b[t]["status"]
