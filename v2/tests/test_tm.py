"""Scenario engine of the threat-modeling showcase (phalanx.tm): computed paths, authority, door, chain, link-only."""
import pytest

from phalanx.tm import Model, boundaries, entry_paths, scenarios


def K(tech, role, code="K-ENABLE", enables="IMP-0011", **kw):
    return {"technique": tech, "role": role, "code": code, "enables": enables, **kw}


ROWS = [
    K("IA-0008.01", "entry"), K("IA-0007.02", "entry"), K("IA-0006", "entry"), K("IA-0009.03", "entry"),
    K("EX-0016.01", "execution", code="K-ACTION", enables=None),
    K("EX-0001.01", "execution"),
    K("LM-0003", "lateral"),
    {"technique": "IMP-0011", "role": "impact", "code": "K-EFFECT"},
    {"technique": "IMP-0013", "role": "impact", "code": "K-EFFECT"},
]


def model(rows, vectors):
    base = Model.load()

    class Fake(Model):
        def mapping(self, tid):
            return {"threat": tid, "vectors": [{"vector": v} for v in vectors], "rows": rows}
    return Fake(base.surface, base.live, base.index, base.adversary)


def pick(res, arch, vector, **want):
    pv = next(p for p in res["architectures"][arch] if p["vector"] == vector)
    out = [s for s in pv["scenarios"] if all((s["path"]["via"] if k == "via" else s[k]) == v for k, v in want.items())]
    assert len(out) == 1, (want, [(s["path"]["via"], s["credential"], s["setting"]) for s in pv["scenarios"]])
    sc = out[0]
    return {s["technique"]: s["removed"] for s in sc["steps"]}, sc


@pytest.fixture(scope="module")
def res():
    return scenarios(model(ROWS, ["rf_link", "ground", "hosted_payload", "user_terminal"]), "TRX")


def test_paths_follow_the_links_of_the_source_graph():
    m = Model.load()
    paths = {a: {v: [(tuple(p["via"]), p["reaches"]) for p in entry_paths(arch, o)] for v, o in m.surface["origins"].items()}
             for a, arch in m.surface["architectures"].items()}
    assert paths["G-CONV"]["hosted_payload"] == [(("NG", "HOST"), "sat_service.bus")]
    assert paths["G-D53"]["hosted_payload"] == [(("NG", "HOST-F"), "sat_feeder.bus"), (("NG", "F1-ISL", "HOST"), "sat_service.bus")]
    # source graph: the G-D53 feeder satellite has no TT&C link, so the mission's own ground reaches only the service bus
    assert {r for _, r in paths["G-D53"]["ground"]} == {"sat_service.bus"}
    assert (("SERVICE", "F1-ISL", "HOST-F"), "sat_feeder.bus") in paths["G-D53"]["user_terminal"]
    assert paths["G-CONV"]["crosslink"] == []


def test_transparent_relay_gives_no_route_from_the_radio_links_to_the_bus(res):
    m = Model.load()
    tp = m.surface["architectures"]["transparent"]
    paths = {v: [(tuple(p["via"]), p["reaches"]) for p in entry_paths(tp, o)] for v, o in m.surface["origins"].items()}
    # the payload relays Uu and is not a RAN interface: service-link and feeder attackers end at the payload
    assert paths["user_terminal"] == [(("SERVICE",), "sat_service.payload")]
    assert paths["feeder_rf"] == [(("FEEDER (rogue)",), "sat_service.payload")]
    # the MNO side reaches only the relay, where a hosted-payload entry does not apply
    pv = next(p for p in res["architectures"]["transparent"] if p["vector"] == "hosted_payload")
    assert pv["paths"] == [] and pv["scenarios"] == []
    # the mission's own TT&C path is the same as in G-CONV
    assert paths["ground"] == [(("SLE", "TC-UL"), "sat_service.bus"), (("UPD",), "sat_service.bus")]
    sub, sc = pick(res, "transparent", "user_terminal", credential="subscriber_valid")
    assert sc["reached"] == "sat_service.payload" and sc["functions_reached"] == []


def test_rogue_station_blocked_at_entry_when_sdls_on(res):
    off, sc_off = pick(res, "G-CONV", "rf_link", setting="off")
    on, sc_on = pick(res, "G-CONV", "rf_link", setting="on")
    assert off["IA-0008.01"] is None and sc_off["complete"]
    assert on["IA-0008.01"].startswith("authority") and on["IMP-0011"] is not None


def test_jamming_needs_only_the_link(res):
    on, sc = pick(res, "G-CONV", "rf_link", setting="on")
    assert on["EX-0016.01"] is None and on["IMP-0013"] is None and sc["complete"]


def test_credential_decides_the_ground_scenarios(res):
    keys, sc = pick(res, "G-CONV", "ground", via=["SLE", "TC-UL"], credential="mission_valid")
    assert keys["IA-0007.02"] is None and keys["EX-0001.01"] is None and sc["complete"]
    front_end, _ = pick(res, "G-CONV", "ground", via=["SLE", "TC-UL"], credential="none", setting="on")
    assert front_end["IA-0007.02"].startswith("authority")


def test_hosted_ran_door_needs_segregation_off(res):
    off, sc_off = pick(res, "G-CONV", "hosted_payload", setting="off")
    on, sc_on = pick(res, "G-CONV", "hosted_payload", setting="on")
    assert sc_off["reached"] == "sat_service.bus" and off["IMP-0011"] is None
    assert on["IA-0006"].startswith("authority") and sc_on["reached"] is None


def test_without_a_door_technique_the_attack_stops_at_the_ran_function():
    rows = [r for r in ROWS if r["technique"] != "IA-0006"]
    res = scenarios(model(rows, ["user_terminal"]), "TRX")
    steps, sc = pick(res, "G-CONV", "user_terminal", credential="subscriber_valid", setting="no_effect")
    assert sc["reached"] == "sat_service.gnb" and "no door technique" in sc["stopped_by"]
    assert steps["IMP-0011"].startswith("reachability")


def test_a_step_whose_enablers_are_removed_is_removed():
    rows = [K("IA-0007.02", "entry", enables="IMP-0011"), K("DE-0011", "evasion", enables="IMP-0011"),
            {"technique": "IMP-0011", "role": "impact", "code": "K-EFFECT"}]
    res = scenarios(model(rows, ["ground"]), "TRX")
    with_keys, _ = pick(res, "G-CONV", "ground", via=["SLE", "TC-UL"], credential="mission_valid")
    assert with_keys["DE-0011"] is None and with_keys["IMP-0011"] is None
    no_keys, _ = pick(res, "G-CONV", "ground", via=["SLE", "TC-UL"], credential="none", setting="off")
    assert no_keys["IA-0007.02"] is None and no_keys["DE-0011"].startswith("authority")
    assert no_keys["IMP-0011"] is None   # still enabled by the accepted entry
    rows[0] = K("IA-0007.02", "entry", enables="DE-0011")
    no_keys, _ = pick(scenarios(model(rows, ["ground"]), "TRX"), "G-CONV", "ground", via=["SLE", "TC-UL"], credential="none", setting="off")
    assert no_keys["IMP-0011"].startswith("chain")


def test_crosslink_lateral_needs_an_inter_satellite_link(res):
    conv, _ = pick(res, "G-CONV", "ground", via=["SLE", "TC-UL"], credential="mission_valid")
    d53, _ = pick(res, "G-D53", "ground", via=["SLE", "TC-UL"], credential="mission_valid")
    assert conv["LM-0003"].startswith("reachability") and d53["LM-0003"] is None


def test_encrypted_service_link_cannot_be_read_even_by_a_subscriber():
    rows = [K("IA-0009.03", "entry", enables="EXF-0003"), {"technique": "EXF-0003", "role": "exfiltration", "code": "K-ACTION"}]
    res = scenarios(model(rows, ["user_terminal"]), "TRX")
    on, _ = pick(res, "G-CONV", "user_terminal", credential="none", setting="on")
    off, sc = pick(res, "G-CONV", "user_terminal", credential="none", setting="off")
    sub, _ = pick(res, "G-CONV", "user_terminal", credential="subscriber_valid")
    assert on["EXF-0003"].startswith("authority") and off["EXF-0003"] is None and sc["complete"]
    assert sub["EXF-0003"].startswith("authority")   # own session keys do not open other users' traffic


def test_gnss_spoofing_needs_no_telecommand_but_its_outcome_needs_a_link_action():
    rows = [{"technique": "EX-0014.04", "role": "execution", "code": "K-ACTION"},
            {"technique": "IMP-0013", "role": "impact", "code": "K-EFFECT"}]
    res = scenarios(model(rows, ["rf_link"]), "TRX")
    gnss, sc = pick(res, "G-CONV", "rf_link", via=["GNSS-sat_service (rogue)"])
    assert gnss["EX-0014.04"] is None and sc["complete"]
    alone = scenarios(model(rows[1:], ["rf_link"]), "TRX")
    out, sc = pick(alone, "G-CONV", "rf_link", via=["TC-UL (rogue)"], setting="no_effect")
    assert out["IMP-0013"].startswith("chain") and not sc["complete"]


def test_ground_side_steps_need_an_attacker_on_the_ground_side(res):
    rows = [K("IA-0008.01", "entry", enables="EXF-0007"), {"technique": "EXF-0007", "role": "exfiltration", "code": "K-EFFECT"}]
    rf = scenarios(model(rows, ["rf_link"]), "TRX")
    steps, _ = pick(rf, "G-CONV", "rf_link", via=["TC-UL (rogue)"], setting="off")
    assert steps["IA-0008.01"] is None and steps["EXF-0007"].startswith("reachability")


def test_only_a_lead_decision_may_rest_on_a_reason_without_a_quote():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("tm_validate", Path(__file__).parents[1] / "tools" / "tm_validate.py")
    tv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tv)
    desc = "attackers seize control of the spacecraft through the ground segment"
    assert tv.vector_errors({"vector": "rf_link", "basis": "lead_decision", "reason": "analyst judgement"}, desc) == []
    assert tv.vector_errors({"vector": "rf_link", "basis": "lead_decision"}, desc) == ["no reason"]
    assert tv.vector_errors({"vector": "rf_link", "basis": "weak", "reason": "x"}, desc) == ["enisa_quote missing"]
    assert tv.vector_errors({"vector": "rf_link", "basis": "lead_decision", "reason": "x", "enisa_quote": "not in the text"}, desc) == ["enisa_quote not in source text"]
    assert tv.vector_errors({"vector": "ground", "basis": "lead_decision", "reason": "x", "credential": "mission_valid"}, desc) == []
    assert tv.vector_errors({"vector": "ground", "basis": "weak", "reason": "x", "enisa_quote": "through the ground segment",
                             "credential": "mission_valid"}, desc) == ["credential_quote missing"]
    assert tv.vector_errors({"vector": "rf_link", "basis": "lead_decision", "reason": "   "}, desc) == ["no reason"]


def test_complete_with_controls_on_counts_paths_without_controls_and_bypassed_controls():
    from phalanx.tm import _arch_view
    def view(*sc):
        return _arch_view({"scenarios": [dict(reached=None, accepted=0, path={"kinds": []}, steps=[], boundaries=[], **s) for s in sc]})["complete_on"]
    # no control on the path: every modelled control is (vacuously) on
    assert view({"setting": "none", "path_controls": [], "controls_on": [], "complete": True})
    # credential bypasses the only control: it is on and ineffective
    assert view({"setting": "bypassed", "path_controls": ["sdls"], "controls_on": ["sdls"], "complete": True})
    # complete only with the control off does not count
    assert not view({"setting": "off", "path_controls": ["sdls"], "controls_on": [], "complete": True},
                    {"setting": "on", "path_controls": ["sdls"], "controls_on": ["sdls"], "complete": False})


def test_link_only_outcome_on_an_uncontrolled_link_is_no_residual_difference():
    rows = [K("IA-0008", "entry", vectors=["feeder_rf"]), K("EX-0016", "execution", code="K-ACTION", enables=None),
            {"technique": "IMP-0013", "role": "impact", "code": "K-EFFECT"}]
    res = scenarios(model(rows, ["feeder_rf"]), "TRX")
    d = next(c for c in res["comparison"] if c["against"] == "transparent")
    assert "residual_differs" not in d["kinds"]


def test_g_d53_f1_isl_is_left_at_the_far_end_when_crossed_backwards():
    res = scenarios(model(ROWS, ["user_terminal"]), "TRX")
    pv = next(p for p in res["architectures"]["G-D53"])
    sub = [s for s in pv["scenarios"] if s["credential"] == "subscriber_valid" and s["path"]["via"] == ["SERVICE", "F1-ISL", "HOST-F"]]
    by = {s["setting"]: s for s in sub}
    # F1-ISL is defined cu → du but crossed du → cu; only HOST-F (segregation) stops the attacker at the CU
    assert by["only ipsec_f1 off"]["reached"] == "sat_feeder.cu" and "segregation" in by["only ipsec_f1 off"]["stopped_by"]
    assert by["on"]["reached"] == "sat_service.du" and "no_effect" not in by


def test_boundaries_follow_the_walk_direction_of_a_reversed_link():
    arch = {"nodes": {"a": {"operated_by": "x", "segment": "ground"}, "b": {"operated_by": "y", "segment": "space"}},
            "links": [{"id": "L", "from": "b", "to": "a", "kind": "feeder"}]}
    assert boundaries(arch, {"links": ["L"], "reaches": "b", "via": ["L"]}) == ["L: x→y (ground→space)"]


def test_a_blocked_entry_does_not_make_the_chains_differ():
    from phalanx.tm import _arch_view
    def view(*settings):
        sc = [dict(reached=None, accepted=0, path={"kinds": []}, boundaries=[], path_controls=[], controls_on=[], complete=False,
                   setting=st, steps=[{"technique": "IA-0008", "removed": None if st == "off" else "authority"}]) for st in settings]
        return _arch_view({"scenarios": sc})["chains"]
    assert view("off", "on") == view("off") == [("IA-0008",)]


def test_a_user_terminal_is_not_a_ground_side_attacker():
    rows = [K("IA-0009.03", "entry", enables="EXF-0007"), {"technique": "EXF-0007", "role": "exfiltration", "code": "K-EFFECT"}]
    steps, _ = pick(scenarios(model(rows, ["user_terminal"]), "TRX"), "G-CONV", "user_terminal", credential="none", setting="off")
    assert steps["EXF-0007"].startswith("reachability: needs an attacker on the ground side")


def test_validate_rejects_enables_cycles_and_survives_an_unknown_vector(tmp_path, monkeypatch):
    import importlib.util
    import json
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("tm_validate", Path(__file__).parents[1] / "tools" / "tm_validate.py")
    tv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tv)
    seen = {"A": {"enables": "B"}, "B": {"enables": ["C"]}, "C": {"enables": "A"}, "D": {"enables": "D"}, "E": {"enables": "A"}}
    assert tv._enables_cycle(seen, set(seen)) == ["A", "B", "C", "D"]
    desc = "attackers run code on the spacecraft"
    quote = {"sparta_quote": "run code on", "reason": "r", "code": "K-ENABLE"}
    mp = {"vectors": [{"vector": "nowhere", "enisa_quote": "run code on the spacecraft"}],
          "rows": [{"technique": "EX-1", "role": "entry", **quote, "enables": "EX-2"},
                   {"technique": "EX-2", "role": "execution", **quote, "enables": "EX-2"}]}
    for sub, name, data in (("mapping", "TRX", mp), ("candidates", "TRX", {"description": desc, "candidates": []})):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(tv, "TM", tmp_path)
    live = {t: {"tactic": "Execution", "name": t, "description": "run code on the target"} for t in ("EX-1", "EX-2")}
    errs = tv.validate("TRX", live, {"origins": {}}, {"TRX": {"category": "c"}}, {"overrides": {}, "default_adversarial_categories": ["c"]})
    assert any("EX-2: enables itself" in e for e in errs) and not any("Error" in e for e in errs)
