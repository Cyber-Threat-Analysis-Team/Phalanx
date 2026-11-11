import copy
import re

import pytest

from phalanx import registry
from phalanx.workspace import Workspace


@pytest.fixture(scope="module")
def reg():
    return registry.load()


@pytest.fixture
def r(reg):
    return copy.deepcopy(reg)


def rule(r, rid):
    return next(x for x in r["rules"] if x["id"] == rid)


def test_real_registry_is_consistent_with_real_data(reg, ws):
    assert registry.check(reg, ws) == []


def test_every_id_in_a_real_bundle_is_registered(reg, tr52):
    """What the engine actually emitted (generators, checks, AFG checks, reason codes) resolves in the registry."""
    ids = set(registry.by_id(reg))
    for res in tr52["results"]:
        for m in res["mrs"]:
            assert set(m["generators"]) <= ids
            for c in m["checks"]:
                assert registry.rule_for_reason_code(reg, c["code"]) in ids
        for k in res["afg"]:
            if k.startswith("check_"):
                assert k[len("check_"):] in ids


def test_duplicate_id_is_reported(r, ws):
    r["rules"].append(copy.deepcopy(rule(r, "MAP-CG-01")))
    assert any("duplicate id MAP-CG-01" in e for e in registry.check(r, ws))


def test_ambiguous_ids_differing_only_in_padding_or_case_are_reported(r, ws):
    extra = copy.deepcopy(rule(r, "MAP-CG-01"))
    extra["id"] = "MAP-CG-1"
    r["rules"].append(extra)
    legacy = copy.deepcopy(rule(r, "LEG-R01"))
    legacy["id"], legacy["aliases"] = "LEG-R001", []
    r["rules"].append(legacy)
    errs = registry.check(r, ws)
    assert any("ambiguous ids MAP-CG-01 and MAP-CG-1" in e for e in errs)
    assert any("ambiguous ids LEG-R01 and LEG-R001" in e for e in errs)


def test_alias_may_not_collide_with_an_id_or_another_rules_alias(r, ws):
    rule(r, "LEG-R02")["aliases"] = ["R1"]            # R1 belongs to LEG-R01
    rule(r, "LEG-R03")["aliases"] = ["MAP-CG-01"]
    errs = registry.check(r, ws)
    assert any("ambiguous alias R1" in e for e in errs)
    assert any("alias MAP-CG-01 collides" in e for e in errs)


def test_unknown_prefix_is_reported(r, ws):
    bad = copy.deepcopy(rule(r, "MAP-CG-01"))
    bad["id"] = "ET-EV-09"          # a data-row id style, not one of the nine protocol prefixes
    r["rules"].append(bad)
    errs = registry.check(r, ws)
    assert any("ET-EV-09: unknown prefix" in e for e in errs)


def test_prefix_field_must_match_id(r, ws):
    rule(r, "BX-CHK-01")["prefix"] = "AFG-CHK"
    assert any("BX-CHK-01: prefix field" in e for e in registry.check(r, ws))


def test_prefix_set_is_frozen_to_the_protocol_set(r, ws):
    r["prefixes"]["XX-GEN"] = "invented"
    assert any("prefixes" in e for e in registry.check(r, ws))


def test_unregistered_reason_code_in_vocabulary_is_reported(reg, tmp_ws):
    root, edit, _ = tmp_ws
    edit("rules/vocabulary.json", lambda v: v["reason_codes"].append("custody"))
    errs = registry.check(reg, Workspace(root))
    assert any("reason code custody" in e and "no registered MAP-CHK rule" in e for e in errs)


def test_registered_reason_code_missing_from_vocabulary_is_reported(reg, tmp_ws):
    root, edit, _ = tmp_ws
    edit("rules/vocabulary.json", lambda v: v["reason_codes"].remove("lifecycle"))
    errs = registry.check(reg, Workspace(root))
    assert any("MAP-CHK-07" in e and "lifecycle" in e for e in errs)


def test_two_rules_cannot_own_one_reason_code(r, ws):
    rule(r, "MAP-CHK-06")["reason_code"] = "target"
    assert any("reason code target is claimed by several rules" in e for e in registry.check(r, ws))


def test_dropping_a_registered_check_is_reported_as_unregistered_reason_code(r, ws):
    r["rules"] = [x for x in r["rules"] if x["id"] != "MAP-CHK-04"]
    errs = registry.check(r, ws)
    assert any("reason code authority" in e for e in errs)


def test_generator_in_vocabulary_must_be_registered_with_its_kind(r, ws, reg):
    rule(r, "MAP-CG-02")["generator_kind"] = "baseline"
    assert any("MAP-CG-02: registered kind" in e for e in registry.check(r, ws))
    r2 = copy.deepcopy(reg)
    r2["rules"] = [x for x in r2["rules"] if x["id"] != "MAP-CG-04"]
    errs = registry.check(r2, ws)
    assert any("MAP-CG-04" in e and "not registered" in e for e in errs)


def test_id_used_in_data_but_not_registered_is_reported(reg, tmp_ws):
    root, edit, _ = tmp_ws
    edit("threats/TR52.json", lambda t: t["projection"].update(lifecycle_rule="ET-P-LC-77 (undeclared)"))
    errs = registry.check(reg, Workspace(root))
    assert any("ET-P-LC-77 is used in data" in e and "threats/TR52.json" in e for e in errs)


def test_unregistered_evidence_clause_and_authority_rule_are_reported(reg, tmp_ws):
    root, edit, _ = tmp_ws
    edit("rules/evidence/TR52.json", lambda e: e["clauses"].update(
        {"ET-EV-06": {"clause": "x", "techniques": ["IA-0007"], "rationale": "semantic"}}))
    edit("rules/vocabulary.json", lambda v: v["authority_rules"].update({"tc_other": {"needs": "x", "credential": "c"}}))
    errs = registry.check(reg, Workspace(root))
    assert any("clauses.ET-EV-06 is not registered" in e for e in errs)
    assert any("authority_rules.tc_other is not registered" in e for e in errs)


def test_stale_data_row_is_reported(r, ws):
    rule(r, "MAP-CHK-09")["data_rows"]["ids"].append("ET-EV-99")
    assert any("ET-EV-99 does not exist in the data" in e for e in registry.check(r, ws))


def test_legacy_rule_must_be_crosswalked_exactly_once(r, ws):
    r["crosswalk"] = [row for row in r["crosswalk"] if "LEG-R04" not in row["legacy"]]
    r["crosswalk"].append(copy.deepcopy(next(row for row in r["crosswalk"] if "LEG-R02" in row["legacy"])))
    errs = registry.check(r, ws)
    assert any("LEG-R04: active legacy rule appears in 0" in e for e in errs)
    assert any("LEG-R02: active legacy rule appears in 2" in e for e in errs)


def test_active_current_rule_must_appear_in_the_crosswalk(r, ws):
    for row in r["crosswalk"]:
        row["current"] = [c for c in row["current"] if c != "CP-CHK-01"]
    assert any("CP-CHK-01: active rule absent from the crosswalk" in e for e in registry.check(r, ws))


@pytest.mark.parametrize("relation,legacy,current", [
    ("equivalent", ["LEG-R02", "LEG-R03"], ["MAP-CG-01"]),   # equivalent is 1 -> 1
    ("split", ["LEG-R02"], ["MAP-CG-01"]),                   # split needs >=2 successors
    ("merged", ["LEG-R02"], ["MAP-CG-01"]),                  # merged needs >=2 sources
    ("dropped", ["LEG-R02"], ["MAP-CG-01"]),                 # dropped has no successor
    ("new", ["LEG-R02"], ["MAP-CG-01"]),                     # new has no legacy
])
def test_relation_must_fit_its_shape(r, ws, relation, legacy, current):
    r["crosswalk"].append({"legacy": legacy, "relation": relation, "current": current, "delta": "x"})
    assert any(f"relation {relation} does not fit" in e for e in registry.check(r, ws))


def test_crosswalk_rejects_unknown_relation_unregistered_ids_and_missing_delta(r, ws):
    r["crosswalk"].append({"legacy": ["LEG-R99"], "relation": "renamed", "current": ["MAP-CG-99"]})
    errs = registry.check(r, ws)
    assert any("relation 'renamed'" in e for e in errs)
    assert any("LEG-R99 is not registered" in e for e in errs)
    assert any("MAP-CG-99 is not registered" in e for e in errs)
    assert any("missing semantic-delta note" in e for e in errs)


def test_every_legacy_rule_r1_to_r13_is_registered_and_crosswalked_once(reg, ws):
    by = registry.by_id(reg)
    assert {f"LEG-R{n:02d}" for n in range(1, 14)} <= set(by)
    rows = [i for c in reg["crosswalk"] for i in c["legacy"]]
    assert all(rows.count(f"LEG-R{n:02d}") == 1 for n in range(1, 14))


def test_prefix_of_and_token_scan():
    assert registry.prefix_of("LEG-R07") == "LEG-R"
    assert registry.prefix_of("ET-P-LC-01") == "ET-P"
    assert registry.prefix_of("ET-EV-01") is None
    assert registry.tokens_in("see check_AFG-CHK-01 and MAP-CG-02, not ET-EV-03 or SI-I-xx") == {"AFG-CHK-01", "MAP-CG-02"}
    assert re.fullmatch(r"[0-9a-f]{64}", registry.load()["legacy_source_sha256"])


def test_altered_legacy_engine_is_reported(reg, tmp_ws):
    root, _, _ = tmp_ws
    with open(root / "legacy_v1" / "ntn_threat_algorithm.py", "a", encoding="utf-8") as f:
        f.write("\n# altered\n")
    assert any("legacy_source_sha256" in e for e in registry.check(reg, Workspace(root)))


def test_rule_with_null_id_is_reported_not_raised():
    reg = copy.deepcopy(registry.load())
    reg["rules"].append({"id": None, "title": "x"})
    assert any("rule without a string id" in e for e in registry.check(reg, Workspace()))
