"""Metric scripts for the primary evaluation vector (protocol v0.3 §1.6 and §2.3).

Every metric is a pure function of plain dicts; `report` runs the pipelines and bundles them. Nothing here
changes a decision: the module only measures the engine, never feeds back into it.

  anchor_recovery      per anchor SI: exact accepted count / proportion of asserted SPARTA IDs
  construct_negatives  precondition deletions for every B3-accepted cell; `constructed_negatives` re-runs them
  directional_pass     MFT / INV / DIR expectation catalogue evaluated on decision views
  completeness         MRs carrying reason code(s) + evidence + provenance
  replay_stats         hash equality and decision flips over repeated runs
  unresolved_rate      unresolved share and the `no_framework_coverage` SI count (always separate)

Everything reported on TR52 is a development/illustrative number: the expectation catalogue was written after
the TR52 results were seen, and no gate anchor is ever run through the engine here.
"""
from __future__ import annotations

import collections
import copy
import json
from pathlib import Path

from . import baselines, engine, evaluation, pipeline
from .workspace import Workspace

STATUS_NOTE = ("development / illustrative: {threat} scenarios are development SIs, the expectation catalogue was "
               "written after {threat} results were seen, and the negative universe is derived from B3 acceptances; "
               "none of this is a validation result")
CANDIDATE_LISTS = ("B0", "B1b")   # methods whose raw output is a technique list (every listed technique = accepted)
_RANK = {"accepted": 2, "unresolved": 1, "rejected": 0}
_PROVENANCE_KEYS = ("scenario", "threat", "rules", "catalog", "engine", "method")


# ============================================================ 1. anchor recovery

def anchor_recovery(decisions: dict[str, dict[str, str]], assertions: dict[str, list[str]]) -> dict:
    """Exact recovery per anchor SI: of the SPARTA IDs the anchor asserts (deduplicated, as printed), how many the
    method accepted under that very ID. A parent/child or label match is never credited. Not pooled across SIs
    (protocol §2.4: quality tiers are attributes, never pooled).
    decisions: {si: {technique: accepted|rejected|unresolved}}; a technique the method never proposed is
    reported `not_generated`. An SI without assertions has proportion None."""
    out = {}
    for si, asserted in sorted(assertions.items()):
        ids = list(dict.fromkeys(asserted))
        got = decisions.get(si, {})
        outcome = {t: got.get(t, "not_generated") for t in ids}
        acc = sorted(t for t, s in outcome.items() if s == "accepted")
        out[si] = {"asserted": len(ids), "accepted": len(acc),
                   "proportion": len(acc) / len(ids) if ids else None,
                   "accepted_ids": acc,
                   "not_recovered": {t: s for t, s in sorted(outcome.items()) if s != "accepted"}}
    return out


# ============================================================ 2. constructed negatives

CLOSED_WORLD = (
    "Closed world: the rule table (techniques.json profiles, vocabulary authority rules) and the SI/G inputs are "
    "the complete statement of what a technique needs. A negative deletes exactly one precondition that the B3 "
    "acceptance consumed, and it is a negative only because the rules say that precondition is required; it says "
    "nothing about the external world. Deletion semantics follow what the engine reads: a selected asset, an "
    "intended effect, an architecture edge or a node's hosted asset is removed (absence = not holding); the "
    "credential is set to 'none' (the vocabulary's own absence value); a protection flag or a required SI fact "
    "is removed (the engine reads absence as 'unknown'); an ET evidence clause is removed from the technique. "
    "Not deletable: the SPARTA version check, the attacker class (access_position) and the realized lifecycle "
    "(scalar identity facts; changing them is the contrastive-pair design, not a deletion); the on-board "
    "foothold is deleted only when every accepted entry traverses one common edge (otherwise the precondition "
    "is disjunctive and no single deletion is required). Universe basis (development): the techniques B3 "
    "accepted on each SI; plan v5 §14.3 requires a method-independent U, which is frozen only at Phase 4.")


def _context(ws: Workspace, threat_id: str) -> dict:
    threat = ws.threats[threat_id]
    rules = engine.Rules(ws.vocabulary, ws.techniques, ws.evidence(threat_id))
    prov = {"threat": threat_id, "catalog": ws.catalog.version, "engine": engine.ENGINE_VERSION,
            "rules": {"vocabulary": ws.vocabulary["version"], "techniques": ws.techniques["status"],
                      "evidence": (rules.evidence or {}).get("status", "none")}}
    return {"threat": threat, "rules": rules, "catalog": ws.catalog, "crosswalk": pipeline.crosswalk_for(ws, threat),
            "v1": ws.v1_mapping(threat_id), "provenance": prov, "architectures": ws.architectures}


def _del_path(si: dict, path: str) -> None:
    cur = si
    parts = path.split(".")
    for p in parts[:-1]:
        cur = cur.get(p)
        if not isinstance(cur, dict):
            return
    cur.pop(parts[-1], None)


def _foothold_edge(res: dict, G: dict, rules: engine.Rules, catalog) -> str | None:
    """The single edge every accepted entry traverses, else None (disjunctive foothold)."""
    edges = set()
    for m in res["mrs"]:
        if m["status"] != "accepted":
            continue
        p = rules.profile(m["technique"], catalog)
        if p["kind"] != "entry":
            continue
        e = engine.edge_from(G, res["si"]["attacker"]["origin_node"], p.get("traverses"), p.get("target", [])) \
            if p.get("traverses") else None
        if e is None:
            return None
        edges.add(e["id"])
    return next(iter(edges)) if len(edges) == 1 else None


def construct_negatives(bundle_b3: dict, ctx: dict) -> list[dict]:
    """One negative per (accepted B3 cell, precondition the acceptance relied on). Preconditions are read from
    the check results of the MR (what `decide` consumed) joined with the technique profile; see CLOSED_WORLD."""
    rules, catalog, vocab = ctx["rules"], ctx["catalog"], ctx["rules"].vocabulary
    negs = []
    for res in bundle_b3["results"]:
        si = res["si"]
        G = engine.instantiate(ctx["architectures"][si["variant"]], si)
        origin = si["attacker"]["origin_node"]
        foothold = _foothold_edge(res, G, rules, catalog)
        for m in res["mrs"]:
            if m["status"] != "accepted":
                continue
            t, p = m["technique"], rules.profile(m["technique"], catalog)
            chk = {c["code"]: c["result"] for c in m["checks"]}
            tgt = set(p.get("target", []))
            specs: list[tuple[str, dict, str]] = [("evidence_clause", {"technique": t},
                                                   f"ET evidence clause supporting {t}")]
            if chk.get("target") == "pass":
                w = sorted(tgt & set(si["selected_asset_instances"]))
                specs.append(("selected_asset", {"assets": w}, f"selected asset(s) {w}"))
            if chk.get("effect") == "pass":
                w = sorted(set(p["effect"]) & set(si["intended_effect"]))
                specs.append(("intended_effect", {"effects": w}, f"intended effect(s) {w}"))
            rule = vocab["authority_rules"].get(p.get("authority", "none"))
            if rule and chk.get("authority") == "pass":
                if "credential" in rule:
                    specs.append(("credential", {}, f"attacker credential {rule['credential']}"))
                else:
                    e = engine.edge_from(G, origin, rule["edge_role"], p.get("target", []))
                    if e:
                        specs.append(("protection_flag", {"edge": e["id"], "flag": rule["protection_flag"]},
                                      f"SI.protection_applied.{e['id']}.{rule['protection_flag']}"))
                        specs.append(("architecture_edge", {"edge": e["id"]}, f"architecture edge {e['id']}"))
            if chk.get("reachability") == "pass":
                if p["kind"] == "entry" and p.get("traverses"):
                    e = engine.edge_from(G, origin, p["traverses"], p.get("target", []))
                    if e:
                        specs.append(("architecture_edge", {"edge": e["id"]}, f"architecture edge {e['id']}"))
                elif p["kind"] == "ground":
                    w = sorted(set(G["nodes"][origin]["assets"]) & tgt)
                    specs.append(("origin_residence", {"node": origin, "assets": w},
                                  f"origin node {origin} hosting {w}"))
                elif p["kind"] == "onboard" and foothold:
                    specs.append(("foothold_edge", {"edge": foothold}, f"entry path edge {foothold}"))
                for path, want in p.get("requires_fact", {}).items():
                    if engine.fact(si, path) == want:
                        specs.append(("requires_fact", {"path": path}, f"SI.{path}"))
            seen = set()
            for kind, args, text in specs:
                key = (kind, json.dumps(args, sort_keys=True))
                if key in seen:
                    continue
                seen.add(key)
                negs.append({"si": si["si_id"], "technique": t, "kind": kind, "deleted": text, "args": args})
    return negs


def apply_deletion(neg: dict, si: dict, variant: dict, rules: engine.Rules) -> tuple[dict, dict, engine.Rules]:
    """Copy of (si, variant, rules) with exactly the negative's precondition removed."""
    si, variant = copy.deepcopy(si), copy.deepcopy(variant)
    kind, a = neg["kind"], neg["args"]
    if kind == "evidence_clause":
        ev = copy.deepcopy(rules.evidence)
        for c in ev["clauses"].values():
            c["techniques"] = [t for t in c["techniques"] if t != a["technique"]]
        rules = engine.Rules(rules.vocabulary, rules.techniques, ev)
    elif kind == "selected_asset":
        for k in a["assets"]:
            si["selected_asset_instances"].pop(k, None)
    elif kind == "intended_effect":
        si["intended_effect"] = [x for x in si["intended_effect"] if x not in a["effects"]]
    elif kind == "credential":
        si["attacker"]["credential"] = "none"
    elif kind == "protection_flag":
        si["protection_applied"][a["edge"]].pop(a["flag"], None)
    elif kind == "requires_fact":
        _del_path(si, a["path"])
    elif kind in ("architecture_edge", "foothold_edge"):
        variant["edges"] = [e for e in variant["edges"] if e["id"] != a["edge"]]
    elif kind == "origin_residence":
        node = variant["nodes"][a["node"]]
        node["assets"] = [x for x in node["assets"] if x not in a["assets"]]
    else:
        raise ValueError(f"unknown deletion kind {kind}")
    return si, variant, rules


def _run_negative(neg: dict, si: dict, ctx: dict, method: str) -> str:
    variant = ctx["architectures"][si["variant"]]
    si2, variant2, rules2 = apply_deletion(neg, si, variant, ctx["rules"])
    res = engine.run_scenario(ctx["threat"], si2, variant2 if method == "B3" else None, rules2, ctx["catalog"],
                              ctx["crosswalk"], ctx["v1"], {**ctx["provenance"], "method": method})
    return next(m["status"] for m in res["mrs"] if m["technique"] == neg["technique"])


def _rate(k: int, n: int):
    return k / n if n else None


def constructed_negatives(ws: Workspace, threat_id: str, scenario_ids: list[str] | None = None,
                          bundle_b3: dict | None = None) -> dict:
    """Run the same negative universe through B3, B2 and the candidate-list baselines.

    Rate = accepted negatives / applicable negatives (lower is better). B3 and B2 negatives are re-run
    scenarios (non-accepted splits into rejected | unresolved). Candidate-list methods ignore the scenario, so
    their outcome for a negative is their cell for (si, technique) coded by evaluation.cells: `accepted` if they
    list the technique, `not_generated` if applicable and not listed, `not_applicable` (outside the denominator)
    otherwise; not_generated is never relabelled rejected/unresolved."""
    ctx = _context(ws, threat_id)
    b3 = bundle_b3 or pipeline.run(ws, threat_id, scenario_ids, method="B3")
    sis = {r["si"]["si_id"]: r["si"] for r in b3["results"]}
    negs = construct_negatives(b3, ctx)
    for n in negs:
        si = sis[n["si"]]
        n["outcomes"] = {m: _run_negative(n, si, ctx, m) for m in ("B3", "B2")}

    universe: dict[str, list[str]] = {}
    for n in negs:
        universe.setdefault(n["si"], [])
        if n["technique"] not in universe[n["si"]]:
            universe[n["si"]].append(n["technique"])
    lists = {"B0": baselines.run_b0(threat_id, list(sis.values()), framework=ws.root / "legacy_v1",
                                    pinned_sha256=ws.manifest.entries["phalanx_v1"]["sha256"]),
             "B1b": baselines.run_b1b(ctx["threat"], list(sis.values()), ws.catalog)}
    cells = evaluation.cells({m: evaluation.from_b0(b) for m, b in lists.items()}, universe) if universe else []
    coded = {(c["method_id"], c["si_id"], c["technique_id"]): c["normalized_outcome"] for c in cells}
    for n in negs:
        for m in CANDIDATE_LISTS:
            n["outcomes"][m] = coded[(m, n["si"], n["technique"])]

    methods: dict = {}
    for m in ("B3", "B2"):
        c = collections.Counter(n["outcomes"][m] for n in negs)
        methods[m] = {"negatives": len(negs), "accepted": c["accepted"], "rejected": c["rejected"],
                      "unresolved": c["unresolved"], "rate": _rate(c["accepted"], len(negs)),
                      "by_kind": _by_kind(negs, m)}
    for m in CANDIDATE_LISTS:
        c = collections.Counter(n["outcomes"][m] for n in negs)
        app = len(negs) - c["not_applicable"]
        methods[m] = {"negatives": len(negs), "applicable": app, "accepted": c["accepted"],
                      "not_generated": c["not_generated"], "not_applicable": c["not_applicable"],
                      "rate": _rate(c["accepted"], app), "by_kind": _by_kind(negs, m)}
    methods["B1b"]["role"] = "sensitivity analysis, exploratory, outside the confirmatory family"
    return {"closed_world_assumption": CLOSED_WORLD,
            "universe": {"basis": "development: B3-accepted cells x relied-on preconditions",
                         "fixtures": sum(len(v) for v in universe.values()), "negatives": len(negs),
                         "by_kind": dict(sorted(collections.Counter(n["kind"] for n in negs).items())),
                         "by_si": {s: sum(1 for n in negs if n["si"] == s) for s in sorted(universe)}},
            "applicability": {m: evaluation.APPLICABILITY.get(m) for m in ("B3", "B2", "B0", "B1b")},
            "methods": methods, "negatives": negs}


def _by_kind(negs: list[dict], method: str) -> dict:
    out: dict = {}
    for n in negs:
        o = n["outcomes"][method]
        c = out.setdefault(n["kind"], collections.Counter())
        c["n"] += 1
        c[o] += 1
    return {k: dict(sorted(c.items())) for k, c in sorted(out.items())}


# ============================================================ 3. directional pass (MFT / INV / DIR)

def load_expectations(ws: Workspace, threat_id: str) -> dict:
    return json.loads((ws.root / "expectations" / f"{threat_id}.json").read_text(encoding="utf-8"))


def view(bundle: dict) -> dict:
    """Decision view of a B2/B3 bundle: {si: {"decisions": {t: {status, reason_codes, root_facts}},
    "boundary": {edge: verdict} | None (B2 has no graph)}}."""
    graph = bundle["method"] == "B3"
    return {r["si"]["si_id"]: {
        "decisions": {m["technique"]: {"status": m["status"], "reason_codes": m["reason_codes"],
                                       "root_facts": m["root_facts"]} for m in r["mrs"]},
        "boundary": {v["edge"]: v["verdict"] for v in r["boundary_verdicts"]} if graph else None}
        for r in bundle["results"]}


def list_view(b: dict) -> dict:
    """View of a candidate-list baseline: only `accepted` is ever produced; no reasons, no boundary."""
    return {r["si_id"]: {"decisions": {t: {"status": "accepted", "reason_codes": [], "root_facts": []}
                                       for t in r["techniques"]}, "boundary": None} for r in b["results"]}


class _NotEvaluable(Exception):
    pass


def _status(v: dict, si: str, t: str, collapse: bool) -> str:
    if si not in v:
        raise _NotEvaluable(si)
    s = v[si]["decisions"].get(t, {}).get("status", "not_generated")
    return ("accepted" if s == "accepted" else "not_accepted") if collapse else s


def _targets(exp: dict, v: dict, sis: list[str]) -> list[str]:
    ts = exp["techniques"]
    if ts != "all":
        return ts
    for s in sis:
        if s not in v:
            raise _NotEvaluable(s)
    return sorted(set.intersection(*(set(v[s]["decisions"]) for s in sis)))


def _collapse_set(x, collapse: bool):
    xs = x if isinstance(x, list) else [x]
    return sorted({("accepted" if s == "accepted" else "not_accepted") if collapse else s for s in xs})


def _check(exp: dict, v: dict, collapse: bool) -> list[dict]:
    rel = exp["relation"]
    bad: list[dict] = []

    def viol(**kw):
        bad.append({"expectation": exp["id"], **kw})

    if rel == "status_is":
        want = _collapse_set(exp["status"], collapse)
        for si in exp["sis"]:
            for t in exp["techniques"]:
                got = _status(v, si, t, collapse)
                dec = v[si]["decisions"].get(t, {})
                if got not in want:
                    viol(si=si, technique=t, expected=want, got=got)
                elif exp.get("reason_codes") and not set(exp["reason_codes"]) <= set(dec.get("reason_codes", [])):
                    viol(si=si, technique=t, expected_reason_codes=exp["reason_codes"],
                         got_reason_codes=dec.get("reason_codes", []))
                elif exp.get("root_facts") and not set(exp["root_facts"]) <= set(dec.get("root_facts", [])):
                    viol(si=si, technique=t, expected_root_facts=exp["root_facts"],
                         got_root_facts=dec.get("root_facts", []))
    elif rel == "boundary_verdict_is":
        si = exp["si"]
        if si not in v:
            raise _NotEvaluable(si)
        if v[si]["boundary"] is None:
            raise _NotEvaluable("no graph")
        got = v[si]["boundary"].get(exp["edge"], "absent")
        if got != exp["verdict"]:
            viol(si=si, edge=exp["edge"], expected=exp["verdict"], got=got)
    elif rel in ("status_equal", "status_changes", "not_less_permissive"):
        a, b = exp["pair"]
        for t in _targets(exp, v, [a, b]):
            sa, sb = _status(v, a, t, collapse), _status(v, b, t, collapse)
            if rel == "status_equal":
                ok = sa == sb
                if ok and exp.get("reasons") and not collapse:
                    ok = v[a]["decisions"].get(t, {}).get("reason_codes") == v[b]["decisions"].get(t, {}).get("reason_codes")
            elif rel == "status_changes":
                ok = sa in _collapse_set(exp["from"], collapse) and sb in _collapse_set(exp["to"], collapse)
            else:
                ok = _RANK.get(sa, -1) >= _RANK.get(sb, -1) if not collapse else (sa == "accepted" or sb != "accepted")
            if not ok:
                viol(pair=[a, b], technique=t, got=[sa, sb])
    elif rel == "root_facts_removed":
        a, b = exp["pair"]
        for si in (a, b):
            if si not in v:
                raise _NotEvaluable(si)
        for t in exp["techniques"]:
            fa = set(v[a]["decisions"].get(t, {}).get("root_facts", []))
            fb = set(v[b]["decisions"].get(t, {}).get("root_facts", []))
            for f in exp["facts"]:
                if f not in fa or f in fb:
                    viol(pair=[a, b], technique=t, fact=f, present_in_a=f in fa, present_in_b=f in fb)
    elif rel == "boundary_edges_differ_only_by":
        a, b = exp["pair"]
        for si in (a, b):
            if si not in v:
                raise _NotEvaluable(si)
            if v[si]["boundary"] is None:
                raise _NotEvaluable("no graph")
        ba, bb = v[a]["boundary"], v[b]["boundary"]
        only_a, only_b = sorted(set(ba) - set(bb)), sorted(set(bb) - set(ba))
        if only_a != sorted(exp["only_in_a"]) or only_b != sorted(exp["only_in_b"]):
            viol(pair=[a, b], only_in_a=only_a, only_in_b=only_b)
        for e in sorted(set(ba) & set(bb)):
            if ba[e] != bb[e]:
                viol(pair=[a, b], edge=e, verdicts=[ba[e], bb[e]])
    else:
        raise ValueError(f"unknown relation {rel} in {exp['id']}")
    return bad


def directional_pass(expectations: dict, views: dict[str, dict]) -> dict:
    """Evaluate the catalogue per method. An expectation lists the `methods` for which it is meaningful; it is
    evaluated there on the method's decision view (candidate-list methods collapse statuses to accepted /
    not_accepted, since they cannot express rejected vs unresolved). An expectation whose SI is missing from the
    view, or that needs a graph the method lacks, is not evaluated and listed under `not_evaluated` (outside the
    denominator). pass = no violation record; `violations` lists every failing cell.
    A violation proves a defect in the method as specified; a pass proves nothing about external correctness."""
    out: dict = {"status": expectations["status"], "catalogue": expectations["threat"], "methods": {}}
    for method, v in sorted(views.items()):
        collapse = method in CANDIDATE_LISTS
        passed, violations, skipped, evaluated = [], [], [], []
        for exp in expectations["expectations"]:
            if method not in exp["methods"]:
                continue
            try:
                bad = _check(exp, v, collapse)
            except _NotEvaluable as e:
                skipped.append({"expectation": exp["id"], "reason": f"not evaluable: {e}"})
                continue
            evaluated.append(exp["id"])
            (violations.extend(bad) if bad else passed.append(exp["id"]))
        by_kind = {}
        for exp in expectations["expectations"]:
            if exp["id"] in evaluated:
                c = by_kind.setdefault(exp["kind"], {"evaluated": 0, "passed": 0})
                c["evaluated"] += 1
                c["passed"] += exp["id"] in passed
        out["methods"][method] = {"evaluated": len(evaluated), "passed": len(passed),
                                  "rate": _rate(len(passed), len(evaluated)), "violation_count": len(violations),
                                  "violations": violations, "not_evaluated": skipped, "by_kind": by_kind}
    return out


# ============================================================ 4. decision-record completeness

def completeness(bundle: dict, vocabulary: dict) -> dict:
    """Share of MRs carrying (a) reason code(s), (b) evidence and (c) provenance; exact counts.

    reason code(s): rejected/unresolved -> non-empty `reason_codes`, all in the frozen vocabulary; accepted
      carries no failing code by construction, so its reason basis is the non-empty check list whose codes are
      all in the vocabulary and none fail or are unknown.
    evidence: accepted -> supporting_evidence; rejected -> opposing_evidence (the failed checks);
      unresolved -> root_facts (the named missing facts / evidence).
    provenance: scenario, threat, rules, catalog, engine and method present, scenario equal to the MR's SI."""
    vocab = set(vocabulary["reason_codes"])
    n = collections.Counter()
    incomplete = []
    for r in bundle["results"]:
        for m in r["mrs"]:
            s = m.get("status")
            codes = m.get("reason_codes") or []
            checks = m.get("checks") or []
            if s == "accepted":
                reason = bool(checks) and all(c.get("code") in vocab and c.get("result") in ("pass", "not_applicable")
                                              for c in checks) and not codes
                ev = bool(m.get("supporting_evidence"))
            else:
                reason = bool(codes) and set(codes) <= vocab
                ev = bool(m.get("opposing_evidence" if s == "rejected" else "root_facts"))
            prov = m.get("provenance") or {}
            pv = all(prov.get(k) for k in _PROVENANCE_KEYS) and prov.get("scenario") == m.get("si_id")
            n["mrs"] += 1
            n["reason_code"] += reason
            n["evidence"] += ev
            n["provenance"] += pv
            if reason and ev and pv:
                n["complete"] += 1
            else:
                incomplete.append({"mr": m.get("mr_id"), "missing": [k for k, ok in
                                                                     (("reason_code", reason), ("evidence", ev),
                                                                      ("provenance", pv)) if not ok]})
    return {"mrs": n["mrs"], "complete": n["complete"], "proportion": _rate(n["complete"], n["mrs"]),
            "with_reason_code": n["reason_code"], "with_evidence": n["evidence"],
            "with_provenance": n["provenance"], "incomplete": incomplete}


# ============================================================ 5. deterministic replay

def replay_stats(bundles: list[dict]) -> dict:
    """Hash equality and decision flips across repeated runs of the same inputs. A flip is a (si, technique)
    whose status differs between any two runs. Same machine only: the protocol's >=2-machine requirement is a
    separate replication this function cannot provide."""
    if len(bundles) < 2:
        raise ValueError("replay needs at least two runs")
    hashes = [b["canonical_sha256"] for b in bundles]
    seen: dict[tuple[str, str], set[str]] = {}
    for b in bundles:
        for r in b["results"]:
            for m in r["mrs"]:
                seen.setdefault((r["si"]["si_id"], m["technique"]), set()).add(m["status"])
    flips = sorted(f"{si}/{t}" for (si, t), s in seen.items() if len(s) > 1)
    return {"runs": len(bundles), "hashes": hashes, "hash_equal": len(set(hashes)) == 1,
            "decisions_compared": len(seen), "decision_flips": len(flips), "flip_rate": len(flips) / len(seen) if seen else 0.0,
            "flipped": flips, "machines": 1,
            "scope": "same machine only; the protocol's >=3 clean runs on >=2 machines is not exercised here"}


# ============================================================ 6. unresolved rate and no-coverage

def unresolved_rate(bundle: dict) -> dict:
    """Unresolved share of MRs, and (reported separately, neither an error nor a rejection) the number of SIs
    whose AF is `no_framework_coverage`."""
    by_si, tot, unr, nocov = {}, 0, 0, []
    for r in bundle["results"]:
        sid = r["si"]["si_id"]
        k = sum(1 for m in r["mrs"] if m["status"] == "unresolved")
        by_si[sid] = {"mrs": len(r["mrs"]), "unresolved": k, "rate": _rate(k, len(r["mrs"]))}
        tot, unr = tot + len(r["mrs"]), unr + k
        if any(a["type"] == "no_framework_coverage" for a in r["af"]):
            nocov.append(sid)
    return {"mrs": tot, "unresolved": unr, "rate": _rate(unr, tot), "by_si": by_si,
            "no_framework_coverage": {"sis": len(nocov), "of": len(bundle["results"]), "si_ids": nocov}}


# ============================================================ bundle

def report(ws: Workspace, threat_id: str, scenario_ids: list[str] | None = None, runs: int = 3) -> dict:
    """All six metrics for B3 and B2 (candidate-list baselines B0/B1b where meaningful: constructed negatives
    and directional pass). Deterministic: no timestamps; replay re-runs the pipeline on freshly loaded
    workspaces."""
    bundles = {m: pipeline.run(ws, threat_id, scenario_ids, method=m) for m in ("B3", "B2")}
    sis = [r["si"] for r in bundles["B3"]["results"]]
    lists = {"B0": baselines.run_b0(threat_id, sis, framework=ws.root / "legacy_v1", pinned_sha256=ws.manifest.entries["phalanx_v1"]["sha256"]),
             "B1b": baselines.run_b1b(ws.threats[threat_id], sis, ws.catalog)}
    # B1b is exploratory and no expectation lists it; B0 is evaluated on accepted / not_accepted only
    views = {m: view(b) for m, b in bundles.items()} | {"B0": list_view(lists["B0"])}
    if (ws.root / "expectations" / f"{threat_id}.json").exists():
        directional = directional_pass(load_expectations(ws, threat_id), views)
    else:
        directional = {"status": f"not_applicable: no expectation catalogue for {threat_id}", "catalogue": None,
                       "methods": {}}
    out = {"threat": threat_id, "scenarios": [s["si_id"] for s in sis], "status": STATUS_NOTE.format(threat=threat_id),
           "anchor_recovery": {"status": f"not_applicable: {threat_id} scenarios are development SIs without published anchor "
                                         "assertions; gate anchors are never run as development scenarios; "
                                         "recovery is tested on synthetic fixtures only"},
           "constructed_negatives": constructed_negatives(ws, threat_id, scenario_ids, bundles["B3"]),
           "directional_pass": directional,
           "decision_record_completeness": {m: completeness(b, ws.vocabulary) for m, b in bundles.items()}
           | {m: {"status": "not_applicable: a candidate list carries no decision record"} for m in lists},
           "replay": {m: replay_stats([pipeline.run(Workspace(ws.root), threat_id, scenario_ids, method=m)
                                       for _ in range(runs)]) for m in bundles},
           "unresolved": {m: unresolved_rate(b) for m, b in bundles.items()}
           | {m: {"status": "not_applicable: a candidate list has no unresolved outcome"} for m in lists},
           "hashes": {m: b["canonical_sha256"] for m, b in bundles.items()}}
    out["metrics_sha256"] = pipeline.canonical_hash(out)
    return out
