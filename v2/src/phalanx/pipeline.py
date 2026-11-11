"""Glue between the authored workspace and the pure engine: build inputs, run, hash, check invariants."""
from __future__ import annotations

import collections
import hashlib
import json

from . import engine, invariants, registry, selectors
from .workspace import Workspace


def canonical_hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def crosswalk_for(ws: Workspace, threat: dict) -> dict:
    key = threat.get("crosswalk_key")
    t1 = ws.crosswalk.for_threat(key) if key else {"workbook_rows": 0, "controls": [], "techniques": []}
    t1["control_titles"] = {c: {"title": ws.crosswalk.controls[c]["title"], "segment": ws.crosswalk.controls[c]["segment"]}
                            for c in t1["controls"]}
    return t1


# rules that produce the non-MR outputs (docs/rule_registry.json)
_VERDICT_RULE = {"crossed": "BX-CHK-01"}            # every other verdict comes from BC-GEN-01
_AF_RULE, _AFG_RULES = "MAP-CHK-12", ("AFG-CHK-01", "AFG-CHK-02", "AFG-CHK-03")


def _attach_rule_ids(body: dict, reg: dict) -> None:
    """Protocol §1.2: every derived output names the registered rule (and its version) that produced it."""
    rules = registry.by_id(reg)

    def tag(obj, rid):
        if rid not in rules:
            raise ValueError(f"rule {rid} is not in docs/rule_registry.json")
        obj["rule"], obj["rule_version"] = rid, rules[rid]["version"]

    ids = {}
    for r in body["results"]:
        for m in r["mrs"]:
            for c in m["checks"]:
                if c["code"] not in ids:
                    ids[c["code"]] = registry.rule_for_reason_code(reg, c["code"])
                    if ids[c["code"]] is None:
                        raise ValueError(f"check {c['code']} has no rule in docs/rule_registry.json")
                tag(c, ids[c["code"]])
        for v in r["boundary_verdicts"]:
            tag(v, _VERDICT_RULE.get(v["verdict"], "BC-GEN-01"))
        for a in r["af"]:
            tag(a, _AF_RULE)
        if r["afg"] is not None:
            r["afg"]["rules"] = {rid: rules[rid]["version"] for rid in _AFG_RULES}


def run(ws: Workspace, threat_id: str, scenario_ids: list[str] | None = None, evidence: dict | None = None,
        method: str = "B3") -> dict:
    """Run every scenario of a threat (or the named subset) with the full method (B3) or scenario-only (B2).
    `evidence` overrides the stored ET evidence clauses."""
    if threat_id not in ws.threats:
        raise KeyError(f"unknown threat {threat_id}; have {sorted(ws.threats)}")
    threat = ws.threats[threat_id]
    sis = ws.scenarios.get(threat_id, [])
    if scenario_ids:
        missing = set(scenario_ids) - {s["si_id"] for s in sis}
        if missing:
            raise KeyError(f"unknown scenario(s) {sorted(missing)} for {threat_id}")
        sis = [s for s in sis if s["si_id"] in scenario_ids]
    rules = engine.Rules(ws.vocabulary, ws.techniques, ws.evidence(threat_id) if evidence is None else evidence)
    provenance = {"threat": threat_id, "catalog": ws.catalog.version, "engine": engine.ENGINE_VERSION,
                  "rules": {"vocabulary": ws.vocabulary["version"], "techniques": ws.techniques["status"],
                            "evidence": (rules.evidence or {}).get("status", "none")}}
    reg = registry.load()
    provenance["rules"]["registry"] = reg["registry_version"]
    body = engine.run_threat(threat, sis, ws.architectures, rules, ws.catalog, crosswalk_for(ws, threat),
                             ws.v1_mapping(threat_id), provenance, method)
    _attach_rule_ids(body, reg)
    sel_registry = selectors.load_registry(ws)
    for r in body["results"]:
        # protocol §1.4: selectors resolve only against the selected SI and its G; B2 has no G, so it stays symbolic
        g = ws.architectures[r["si"]["variant"]] if method == "B3" else None
        r["selector_resolution"] = selectors.resolve(threat["affected_asset_selectors"], r["si"], g, sel_registry,
                                                     threat["projection"]["candidate_assets"])
    body["canonical_sha256"] = canonical_hash(body)
    body["inputs"] = ws.input_hashes()
    body["generated_by"] = {"engine": engine.ENGINE_VERSION}
    body["invariant_violations"] = invariants.check_bundle(body, ws.vocabulary, sel_registry, ws.architectures)
    return body


def outcomes(bundle: dict) -> dict:
    """Compact, diffable decision summary (used for regression fixtures and `phalanx outcomes`)."""
    out = {}
    for r in bundle["results"]:
        out[r["si"]["si_id"]] = {
            "decisions": {m["technique"]: [m["status"], m["reason_codes"], m["root_facts"]] for m in r["mrs"]},
            "attack_flow": r["afg"]["nodes"], "crossings": r["afg"]["crossings"],
            "boundary_verdicts": {v["edge"]: v["verdict"] for v in r["boundary_verdicts"]},
            "findings": dict(sorted(collections.Counter(a["type"] for a in r["af"]).items()))}
    return out


def summary(bundle: dict) -> list[dict]:
    rows = []
    for r in bundle["results"]:
        c = collections.Counter(m["status"] for m in r["mrs"])
        rows.append({"scenario": r["si"]["si_id"], "variant": r["si"]["variant"], "attacker": r["si"]["attacker"]["class"],
                     "candidates": len(r["mrs"]), "accepted": c["accepted"], "rejected": c["rejected"],
                     "unresolved": c["unresolved"],
                     "crossed": sorted(v["edge"] for v in r["boundary_verdicts"] if v["verdict"] == "crossed")})
    return rows


def compare(ws: Workspace, threat_id: str, scenario_ids: list[str] | None = None,
            universe: dict[str, list[str]] | None = None, universe_id: str | None = None) -> dict:
    """Run B3, B2, B0, B1 and B1b on the same scenarios and normalize them into EvaluationCells (plan v5 §14.3).
    B1 needs an EMB3D-side input, which development SIs do not have, so its cells are `not_applicable`.
    Without a frozen `universe` the cells use the development union and are diagnostic only."""
    from . import baselines, evaluation
    b3 = run(ws, threat_id, scenario_ids, method="B3")
    b2 = run(ws, threat_id, scenario_ids, method="B2")
    sis = [r["si"] for r in b3["results"]]
    b0 = baselines.run_b0(threat_id, sis, pinned_sha256=ws.manifest.entries["phalanx_v1"]["sha256"])
    b1b = baselines.run_b1b(ws.threats[threat_id], sis, ws.catalog)
    rows = evaluation.cells({"B3": evaluation.from_engine(b3), "B2": evaluation.from_engine(b2),
                             "B0": evaluation.from_b0(b0), "B1": evaluation.not_applicable(s["si_id"] for s in sis),
                             "B1b": evaluation.from_b0(b1b)}, universe)
    return {"threat": threat_id,
            "universe": universe_id or (evaluation.DEV_UNION if universe is None else "unnamed"),
            "diagnostic_only": universe is None,
            "hashes": {"B3": b3["canonical_sha256"], "B2": b2["canonical_sha256"]},
            "invariant_violations": {"B3": b3["invariant_violations"], "B2": b2["invariant_violations"]},
            "applicability": evaluation.APPLICABILITY,
            "b0": b0,
            "b1b": b1b,
            "counts": evaluation.counts(rows),
            "contrasts": {"B3_vs_B2": evaluation.contrast(rows, "B3", "B2"),
                          "B3_vs_B0": evaluation.contrast(rows, "B3", "B0"),
                          "B3_vs_B1b (sensitivity, uncorrected)": evaluation.contrast(rows, "B3", "B1b")},
            "cells": rows,
            "cells_sha256": canonical_hash(rows),
            "bundles": {"B3": b3, "B2": b2}}
