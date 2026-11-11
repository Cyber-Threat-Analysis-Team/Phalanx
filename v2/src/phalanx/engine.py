"""The decision engine (plan v5 §1.2, Pipeline B):

  (ET, ETP, G variant, SI, SPARTA v4.0.1)
      -> candidate techniques                                   (candidates)
      -> MR decisions with system-state reason codes + AF      (check, decide)
      -> AFG + boundary verdicts (crossed|applicable|adjacent|not_applicable)
      -> CPR control locations (listed, placement not yet adjudicated)

Pure functions over plain dicts: no file IO, no printing. The CLI and any later web front end call
`run_threat`; everything they need comes back in the bundle.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .sources import Catalog

ENGINE_VERSION = "0.1.0"
_ORDER = {"fail": 0, "unknown": 1, "pass": 2, "not_applicable": 3}
_FACT_RE = re.compile(r"SI\.[A-Za-z_]+(?:\.[A-Za-z0-9_\-]+)+")
EVIDENCE_FACT = "ET-linked evidence"
# an on-board step inherits this when the entry steps it depends on lack evidence; distinct from its own gap
ENTRY_EVIDENCE_GAP = "entry steps without ET-linked evidence"
ENTRY_EVIDENCE_FACT = "ET-linked evidence for the entry step"
METHODS = {"B3": "full method (ET/ETP + G + SI)", "B2": "scenario-only (ET/ETP + SI, no architecture graph)"}


@dataclass(frozen=True)
class Rules:
    vocabulary: dict
    techniques: dict
    evidence: dict | None          # ET evidence clauses for the threat being run

    def profile(self, tid: str, catalog: Catalog) -> dict:
        """Tactic default, then a target derived from structured SPARTA fields (the defence-in-depth layers of the
        SV statements that relate the technique), or, when an analyst-authored exact-id override exists, that override (never both).
        Parents never leak into sub-techniques. `source` records which layer set the target."""
        tactic = catalog.tactic(tid)
        p = dict(self.techniques["tactic_defaults"][tactic])
        source = "default"
        layer_map = self.techniques.get("derivation", {}).get("sv_layer_targets", {})
        override = self.techniques["overrides"].get(tid, {})
        derived = sorted({a for layer in catalog.techniques[tid].get("sv_layers", []) for a in layer_map.get(layer, [])})
        if override:                 # an analyst profile is kept whole, including the default target it accepted
            p.update(override)
            source = "analyst"
        elif derived and "target" in p:
            p["target"], source = derived, "derived"
        p["tactic"], p["source"] = tactic, source
        return p

    def evidence_index(self) -> dict[str, tuple[str, str]]:
        if not self.evidence:
            return {}
        return {t: (cid, c["clause"]) for cid, c in sorted(self.evidence["clauses"].items()) for t in c["techniques"]}


# ------------------------------------------------------------------ graph helpers

def instantiate(variant: dict, si: dict) -> dict:
    """Attacker-scoped nodes/edges exist only when the SI's attacker originates there."""
    origin = si["attacker"]["origin_node"]
    keep = {n for n, d in variant["nodes"].items() if d.get("scope") != "attacker" or n == origin}
    return {**variant, "nodes": {n: d for n, d in variant["nodes"].items() if n in keep},
            "edges": [e for e in variant["edges"] if e["src"] in keep and e["dst"] in keep]}


def edge_from(G: dict, origin: str, role: str, target_assets) -> dict | None:
    for e in G["edges"]:
        if e["src"] == origin and e["role"] == role and set(G["nodes"][e["dst"]]["assets"]) & set(target_assets):
            return e
    return None


def fact(si: dict, path: str):
    cur = si
    for part in path.split("."):
        cur = cur.get(part, "unknown") if isinstance(cur, dict) else "unknown"
    return cur


# ------------------------------------------------------------------ candidates

def claim_links(threat: dict, catalog: Catalog, successors: list[str]) -> dict[str, tuple[str, str]]:
    """Techniques SPARTA relates to the threat's claimed SV-* statements -> (SV id, quote). Deprecated techniques are
    dropped; when a claimed SV relates to a deprecated Impact technique, the declared live successors (MAP-CG-04)
    inherit that claim (Impact bridge). First claim in file order wins for each technique."""
    out: dict[str, tuple[str, str]] = {}
    for c in threat.get("claims", []):
        linked = catalog.sv[c["sv"]]["techniques"]
        for t in linked:
            if not catalog.is_deprecated(t):
                out.setdefault(t, (c["sv"], c["quote"]))
    for c in threat.get("claims", []):        # bridged support is weaker and labelled as such
        if any(catalog.is_deprecated(t) and t.startswith("IMP-") for t in catalog.sv[c["sv"]]["techniques"]):
            for t in successors:
                out.setdefault(t, (f"{c['sv']} via Impact bridge", c["quote"]))
    return out


def candidates(threat: dict, si: dict, rules: Rules, crosswalk_techniques, v1_techniques,
               claim_techniques=()) -> dict[str, set[str]]:
    """technique -> generators that proposed it."""
    gen: dict[str, set[str]] = {}

    def add(ids, g):
        for t in ids:
            gen.setdefault(t, set()).add(g)

    add(crosswalk_techniques, "MAP-CG-01")
    add(rules.techniques["attacker_seeds"].get(si["attacker"]["class"], []), "MAP-CG-02")
    add(v1_techniques, "MAP-CG-03")
    add(rules.techniques["deprecation_successors"], "MAP-CG-04")
    add(claim_techniques, "MAP-CG-05")
    return gen


# ------------------------------------------------------------------ the nine checks

def check(tid: str, p: dict, catalog: Catalog, si: dict, G: dict, rules: Rules, ev_index: dict,
          foothold) -> list[tuple[str, str, str]]:
    """Ordered (reason_code, result, detail). result in pass|fail|unknown|not_applicable."""
    res = []
    dep = catalog.is_deprecated(tid)
    res.append(("version", "fail" if dep else "pass",
                f"{catalog.version} marks it [DEPRECATED]" if dep else f"valid in {catalog.version}"))
    if p["kind"] == "prep":
        res.append(("behavior", "fail", rules.techniques["action_window"]))
        return res
    res.append(("behavior", "pass", f"{p['tactic']} within SI action window"))

    att = si["attacker"]
    if p["kind"] in ("entry", "ground"):
        ok = att["class"] in p.get("access", [])
        res.append(("access_position", "pass" if ok else "fail",
                    f"attacker {att['class']} {'in' if ok else 'not in'} required {p.get('access', [])}"))
    else:
        res.append(("access_position", "not_applicable", "on-board technique; position checked via reachability"))

    auth = p.get("authority", "none")
    rule = rules.vocabulary["authority_rules"].get(auth)
    if rule is None:
        res.append(("authority", "not_applicable", "no authority precondition"))
    elif "credential" in rule:
        ok = att.get("credential") == rule["credential"]
        res.append(("authority", "pass" if ok else "fail",
                    f"needs {rule['needs']}; attacker has {att.get('credential')}"))
    elif G is None:
        # B2 (scenario-only): no graph, so no edge is chosen; read every protection entry
        flag = rule["protection_flag"]
        vals = {eid: p_.get(flag, "unknown") for eid, p_ in sorted(si["protection_applied"].items())}
        # only unknown entries are written as SI.* paths, so root_facts names exactly the missing facts
        shown = ", ".join(f"SI.protection_applied.{eid}.{flag} = unknown" if v == "unknown" else f"{eid}.{flag} = {v}"
                          for eid, v in vals.items()) or "no protection entries"
        r = "fail" if any(v is True for v in vals.values()) else (
            "pass" if vals and all(v is False for v in vals.values()) else "unknown")
        res.append(("authority", r, f"needs {rule['needs']}; scenario-only: {shown}"))
    else:
        e = edge_from(G, att["origin_node"], rule["edge_role"], p.get("target", []))
        if e is None:
            res.append(("authority", "fail", f"no {rule['edge_role']} edge from {att['origin_node']} to a target asset"))
        else:
            flag = rule["protection_flag"]
            v = si["protection_applied"].get(e["id"], {}).get(flag, "unknown")
            r = {True: "fail", False: "pass"}.get(v, "unknown")
            res.append(("authority", r, f"needs {rule['needs']}; SI.protection_applied.{e['id']}.{flag} = {v}"))

    tgt = set(p.get("target", []))
    sel = set(si["selected_asset_instances"])
    res.append(("target", "pass" if tgt & sel else "fail", f"technique targets {sorted(tgt)}; SI selected {sorted(sel)}"))

    eff = p.get("effect")
    if eff == "enabling":
        res.append(("effect", "not_applicable", "enabling step"))
    else:
        ok = set(eff or []) & set(si["intended_effect"])
        res.append(("effect", "pass" if ok else "fail", f"technique effect {eff}; SI intended effect {si['intended_effect']}"))

    lc = p.get("lifecycle", [])
    res.append(("lifecycle", "pass" if si["realized_lifecycle"] in lc else "fail",
                f"realized lifecycle {si['realized_lifecycle']}; technique phases {lc}"))

    reach = []
    if G is None:
        reach.append(("not_applicable", "scenario-only: no architecture graph, path and foothold not assessed"))
    elif p["kind"] == "entry":
        role = p.get("traverses")
        e = edge_from(G, att["origin_node"], role, p.get("target", [])) if role else None
        reach.append(("pass", f"edge {e['id']} ({role}) from {att['origin_node']}") if e
                     else ("fail", f"no {role} edge from {att['origin_node']} to a target asset in {si['variant']}"))
    elif p["kind"] == "ground":
        node = G["nodes"][att["origin_node"]]
        ok = set(node["assets"]) & tgt and node["domain"] != "adversary"
        reach.append(("pass", f"attacker resides on mission ground node {att['origin_node']}") if ok
                     else ("fail", f"origin {att['origin_node']} is not mission ground infrastructure"))
    else:
        reach.append(foothold)
    for path, want in p.get("requires_fact", {}).items():
        v = fact(si, path)
        reach.append(("unknown", f"missing fact SI.{path} (needs {want})") if v == "unknown"
                     else (("pass" if v == want else "fail"), f"SI.{path} = {v}, needs {want}"))
    worst = min(reach, key=lambda x: _ORDER[x[0]])
    res.append(("reachability", worst[0], "; ".join(d for _, d in reach)))

    if any(r == "fail" for _, r, _ in res):
        res.append(("evidence", "not_applicable", "not assessed: candidate already fails a required check"))
    elif tid in ev_index:
        res.append(("evidence", "pass", f"{ev_index[tid][0]}: \"{ev_index[tid][1]}\""))
    else:
        res.append(("evidence", "unknown", "missing fact: no ET-linked evidence clause supports this technique"))
    return res


def root_facts(checks) -> list[str]:
    """Missing facts behind every 'unknown', including those inherited through the on-board foothold."""
    facts = set()
    for _, r, d in checks:
        if r == "unknown":
            facts.update(_FACT_RE.findall(d))
            if "no ET-linked evidence" in d:
                facts.add(EVIDENCE_FACT)
            if ENTRY_EVIDENCE_GAP in d:
                facts.add(ENTRY_EVIDENCE_FACT)
    return sorted(facts)


def decide(checks) -> tuple[str, list[str]]:
    """Any fail -> rejected; else any unknown -> unresolved; else accepted. Reason codes keep check order."""
    if any(r == "fail" for _, r, _ in checks):
        return "rejected", [c for c, r, _ in checks if r == "fail"]
    if any(r == "unknown" for _, r, _ in checks):
        return "unresolved", [c for c, r, _ in checks if r == "unknown"]
    return "accepted", []


# ------------------------------------------------------------------ one scenario

def run_scenario(threat: dict, si: dict, variant: dict, rules: Rules, catalog: Catalog, crosswalk: dict,
                 v1_techniques: list[str], provenance: dict) -> dict:
    G = instantiate(variant, si) if variant is not None else None   # None = scenario-only (B2)
    att = si["attacker"]
    claims = claim_links(threat, catalog, rules.techniques["deprecation_successors"])
    gen_of = candidates(threat, si, rules, crosswalk["techniques"], v1_techniques, claims)
    unknown = sorted(t for t in gen_of if t not in catalog.techniques)
    if unknown:
        raise ValueError(f"{si['si_id']}: candidates not in {catalog.version}: {unknown}")
    ev_index = {**claims, **rules.evidence_index()}      # an authored evidence clause takes precedence
    profiles = {t: rules.profile(t, catalog) for t in gen_of}
    mrs: dict[str, dict] = {}

    def make(t, foothold):
        ch = check(t, profiles[t], catalog, si, G, rules, ev_index, foothold)
        status, codes = decide(ch)
        ev = next((d for c, r, d in ch if c == "evidence"), "not assessed")
        return {"mr_id": f"MR-{si['si_id']}-{t}", "si_id": si["si_id"], "candidate_source": "sparta",
                "technique": t, "name": catalog.techniques[t]["name"], "tactic": profiles[t]["tactic"],
                "profile_source": profiles[t]["source"],
                "generators": sorted(gen_of[t]), "status": status, "reason_codes": codes,
                "checks": [{"code": c, "result": r, "detail": d} for c, r, d in ch],
                "root_facts": root_facts(ch),
                "relation": {"type": "undeclared (cross-abstraction seam; no set-theory type asserted)",
                             "rationale": "semantic",
                             "abstraction": "ENISA threat template (category-level) -> SPARTA technique (behavior-level)"},
                "evidence_clause": ev_index[t][0] if t in ev_index else None,
                "supporting_evidence": [ev] if t in ev_index and status != "rejected" else [],
                "opposing_evidence": [d for c, r, d in ch if r == "fail"],
                "provenance": {**provenance, "scenario": si["si_id"]}}

    # pass 1: steps that need no on-board foothold
    for t in sorted(gen_of):
        if profiles[t]["kind"] in ("entry", "ground", "prep"):
            mrs[t] = make(t, None)
    entries = [m for m in mrs.values() if profiles[m["technique"]]["kind"] == "entry"]
    acc = [m["technique"] for m in entries if m["status"] == "accepted"]
    unr = [m for m in entries if m["status"] == "unresolved"]
    if acc:
        foothold = ("pass", f"on-board foothold via accepted entry {', '.join(acc)}")
    elif unr:
        # inherit the entries' missing facts: their system-state facts and, if an entry lacks ET-linked evidence,
        # that gap too (otherwise an on-board step would be unresolved without naming why, I6)
        missing = sorted({f for m in unr for f in m["root_facts"] if f.startswith("SI.")})
        no_ev = [m["technique"] for m in unr if EVIDENCE_FACT in m["root_facts"]]
        foothold = ("unknown", "on-board foothold depends on unresolved entries "
                    f"{', '.join(m['technique'] for m in unr)} (system state: {'; '.join(missing) or 'none'})"
                    + (f"; {ENTRY_EVIDENCE_GAP}: {', '.join(no_ev)}" if no_ev else ""))
    else:
        foothold = ("fail", "no accepted or unresolved entry reaches the spacecraft in this SI")
    # pass 2: on-board steps
    for t in sorted(gen_of):
        if t not in mrs:
            mrs[t] = make(t, foothold)

    order = rules.vocabulary["tactic_order"]
    accepted = sorted((m for m in mrs.values() if m["status"] == "accepted"),
                      key=lambda m: ({"ground": 0, "entry": 1}.get(profiles[m["technique"]]["kind"], 2),
                                     order.index(m["tactic"]), m["technique"]))
    afg = attack_flow(accepted, profiles, G, si)
    verdicts = boundary_verdicts(G, si, threat, rules, afg["crossings"]) if G is not None else []
    cpr = [{"mr_id": m["mr_id"], "technique": m["technique"], "countermeasure": cid, "name": cname,
            "placement": "not_adjudicated"}
           for m in accepted for cid, cname in catalog.countermeasures.get(m["technique"], [])]
    return {"si": si, "mrs": [mrs[t] for t in sorted(mrs)], "afg": afg, "boundary_verdicts": verdicts,
            "cpr_sparta": cpr,
            "cpr_enisa_annex_d": [{"control_id": c, **crosswalk["control_titles"][c]} for c in crosswalk["controls"]],
            "af": findings(mrs, gen_of, accepted, att, rules)}


def attack_flow(accepted: list[dict], profiles: dict, G: dict, si: dict) -> dict:
    """AFG: accepted actions in order; a crossing is recorded only on an edge an accepted entry traverses (I4)."""
    att = si["attacker"]
    crossings: dict[str, list[str]] = {}
    for m in (accepted if G is not None else []):
        p = profiles[m["technique"]]
        if p["kind"] == "entry" and p.get("traverses"):
            e = edge_from(G, att["origin_node"], p["traverses"], p.get("target", []))
            if e:
                crossings.setdefault(e["id"], []).append(m["technique"])
    onboard_ok = all(profiles[m["technique"]]["kind"] != "onboard" for m in accepted) or bool(crossings)
    effect_steps = [m["technique"] for m in accepted if m["tactic"] == "Impact"
                    and isinstance(profiles[m["technique"]].get("effect"), list)
                    and set(profiles[m["technique"]]["effect"]) & set(si["intended_effect"])]
    if effect_steps:
        chk2 = f"pass: effect step(s) {', '.join(effect_steps)} realise intended effect {si['intended_effect']}"
    elif not accepted:
        chk2 = "not_applicable: no accepted chain"
    else:
        chk2 = f"FAIL: no accepted Impact step realises {si['intended_effect']}"
    return {"nodes": [m["technique"] for m in accepted],
            "edges": [{"from": a["technique"], "to": b["technique"]} for a, b in zip(accepted, accepted[1:])],
            "crossings": crossings,
            "check_AFG-CHK-01": ("not_applicable: scenario-only, no graph" if G is None else
                                 "pass: every on-board action is preceded by an accepted entry" if onboard_ok
                                 else "FAIL: on-board action without entry"),
            "check_AFG-CHK-02": chk2}


def boundary_verdicts(G: dict, si: dict, threat: dict, rules: Rules, crossings: dict) -> list[dict]:
    """Verdict per boundary edge, precedence crossed > applicable > adjacent > not_applicable (plan v5 §8.4).

    applicable: a selected asset terminates the edge, the edge is active in the realized lifecycle,
                and the edge plays a role the threat projection names.
    adjacent:   selected asset + active, but a role the threat does not name.
    The verdict is about the edge's role, not the paper boundary (TB1-TB5) it sits under.
    """
    sel_pairs = set(si["selected_asset_instances"].items())
    named_roles = set(threat["projection"]["applicable_boundary_roles"])
    out = []
    for e in G["edges"]:
        if e["role"] not in rules.vocabulary["boundary_roles"]:
            continue
        hits = sorted((a, n) for n in (e["src"], e["dst"]) for a in e["endpoint_assets"]
                      if (a, n) in sel_pairs and a in G["nodes"][n]["assets"])
        active = si["realized_lifecycle"] in e["active_lifecycle"]
        named = e["role"] in named_roles
        flags = {"crossed": e["id"] in crossings, "applicable": named and bool(hits) and active,
                 "adjacent": bool(hits) and active}
        v = next((k for k in ("crossed", "applicable", "adjacent") if flags[k]), "not_applicable")
        hit_txt = ", ".join(f"{a}@{n}" for a, n in hits)
        why = {"crossed": f"accepted action(s) {', '.join(crossings.get(e['id'], []))} traverse it",
               "applicable": f"threat names role {e['role']} and selected asset(s) {hit_txt} terminate it; "
                             "no accepted action traverses it (held)",
               "adjacent": f"selected asset(s) {hit_txt} terminate it; threat does not name role {e['role']}; "
                           "no accepted action traverses it",
               "not_applicable": (f"selected asset(s) {hit_txt} terminate it, but it is inactive in lifecycle "
                                  f"{si['realized_lifecycle']}" if hits else "no selected asset terminates it; no traversal")}[v]
        out.append({"edge": e["id"], "role": e["role"], "transition": e["transition"],
                    "figure_alias": e["figure_alias"], "figure_alias_basis": e["figure_alias_basis"],
                    "verdict": v, "basis": why, "provenance": e["provenance"]})
    return out


def findings(mrs: dict, gen_of: dict, accepted: list, att: dict, rules: Rules) -> list[dict]:
    """AF: assurance findings (missing facts, crosswalk gaps, unreachable goal)."""
    gens = rules.vocabulary["candidate_generators"]
    baseline = {g for g, d in gens.items() if d["kind"] == "baseline"}
    gap_sources = {g for g, d in gens.items() if d["kind"] in ("attacker_seed", "deprecation_successor")}
    af = []
    for t in sorted(mrs):
        m = mrs[t]
        if m["status"] == "unresolved":
            af.append({"type": "insufficient_evidence" if m["root_facts"] == [EVIDENCE_FACT] else "missing_system_state",
                       "mr_id": m["mr_id"], "facts": m["root_facts"]})
    for t in sorted(gen_of):
        if gen_of[t] & gap_sources and not gen_of[t] & baseline:
            added = ", ".join(sorted(gen_of[t] & gap_sources))
            af.append({"type": "candidate_inclusion_gap", "technique": t,
                       "detail": f"T1 crosswalk does not reach {t}; added by {added} "
                                 f"(attacker {att['class']} or deprecation successor)"})
    if not accepted:
        af.append({"type": "unreachable", "detail": "no technique accepted; no attack flow from this attacker position"})
    return af


# ------------------------------------------------------------------ one threat, all its scenarios

def run_threat(threat: dict, scenarios: list[dict], architectures: dict, rules: Rules, catalog: Catalog,
               crosswalk: dict, v1_techniques: list[str], provenance: dict, method: str = "B3") -> dict:
    """method B3 = full method; B2 = scenario-only (no architecture graph; plan v5 §14.3)."""
    if method not in METHODS:
        raise ValueError(f"method must be one of {sorted(METHODS)}")
    results = []
    for si in scenarios:
        gen = candidates(threat, si, rules, crosswalk["techniques"], v1_techniques,
                         claim_links(threat, catalog, rules.techniques["deprecation_successors"]))
        if not gen:
            # I11: zero candidates -> no_framework_coverage, no MR, never a silent "rejected"
            results.append({"si": si, "mrs": [], "afg": {"nodes": [], "edges": [], "crossings": {}},
                            "boundary_verdicts": [], "cpr_sparta": [], "cpr_enisa_annex_d": [],
                            "af": [{"type": "no_framework_coverage",
                                    "detail": "no generator proposed any candidate for this scenario"}]})
            continue
        variant = architectures[si["variant"]] if method == "B3" else None
        results.append(run_scenario(threat, si, variant, rules, catalog, crosswalk, v1_techniques,
                                    {**provenance, "method": method}))
    return {"method": method, "threat": threat, "t1_baseline": {"workbook_rows": crosswalk["workbook_rows"],
                                              "controls": len(crosswalk["controls"]),
                                              "techniques": len(crosswalk["techniques"])},
            "v1_mapping": v1_techniques, "results": results}
