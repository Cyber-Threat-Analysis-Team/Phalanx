"""Validate the showcase data.

Usage: .venv/bin/python tools/tm_validate.py [TRxx ...]   per-file checks (no arguments: every file, plus the checks below)
       .venv/bin/python tools/tm_validate.py --cross        cross-threat consistency only
       .venv/bin/python tools/tm_validate.py --surface      attack-surface and adversary-role files only
Exit status 1 when anything fails.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TM = ROOT / "data" / "tm"
CODES = {"K-ACTION", "K-ENABLE", "K-EFFECT", "P-PREP", "D-OTHER", "D-UNDESCRIBED"}
KEEP = {"K-ACTION", "K-ENABLE", "K-EFFECT"}
ROLES = {"entry", "execution", "persistence", "evasion", "lateral", "exfiltration", "impact"}
TACTIC_ROLES = {"Initial Access": {"entry", "lateral"}, "Execution": {"execution"}, "Persistence": {"persistence"},
                "Defense Evasion": {"evasion"}, "Lateral Movement": {"lateral"}, "Exfiltration": {"exfiltration"},
                "Impact": {"impact"}}
PREP_TACTICS = {"Reconnaissance", "Resource Development"}
CREDENTIALS = {"mission_valid", "mno_valid", "subscriber_valid", "partner_valid"}
BASIS = {"quote", "weak", "lead_decision"}
FIT_KINDS = {"sparta_gap", "surface_gap"}
MAX_ADDED, MIN_QUOTE_WORDS, MAX_SAME_REASON = 5, 3, 2


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def load(name: str) -> dict:
    return json.loads((TM / name).read_text(encoding="utf-8"))


def role_of(adv: dict, index: dict, tid: str) -> str:
    if tid in adv["overrides"]:
        return adv["overrides"][tid]["role"]
    return "adversarial" if index[tid]["category"] in adv["default_adversarial_categories"] else "none"


def _enables(r: dict) -> list[str]:
    e = r.get("enables")
    return [e] if isinstance(e, str) else list(e or [])


def _quote(q: str | None, text: str, what: str) -> list[str]:
    q = norm(q)
    if not q:
        return [f"{what} missing"]
    if q not in text:
        return [f"{what} not in source text"]
    if len(q.split()) < MIN_QUOTE_WORDS:
        return [f"{what} shorter than {MIN_QUOTE_WORDS} words"]
    return []


def vector_errors(v: dict, desc: str) -> list[str]:
    """An origin (and the credential it gains) rests on a verbatim quote, or (basis lead_decision only) on the stated reason alone."""
    basis = v.get("basis", "quote")
    errs = [] if basis in BASIS else [f"basis must be one of {sorted(BASIS)}"]
    if not norm(v.get("reason")):
        errs.append("no reason")
    for field in ("enisa_quote",) + (("credential_quote",) if v.get("credential") else ()):
        if basis != "lead_decision" or v.get(field):
            errs += _quote(v.get(field), desc, field)
    return errs


def validate(tid: str, live: dict, surface: dict, index: dict, adv: dict) -> list[str]:
    errs: list[str] = []
    path = TM / "mapping" / f"{tid}.json"
    if not path.exists():
        return [f"{tid}: mapping file missing"]
    if role_of(adv, index, tid) != "adversarial":
        return [f"{tid}: mapping exists but the adversary role is {role_of(adv, index, tid)}"]
    cand = json.loads((TM / "candidates" / f"{tid}.json").read_text(encoding="utf-8"))
    m = json.loads(path.read_text(encoding="utf-8"))
    desc = norm(cand["description"])
    origins = surface["origins"]
    fit = m.get("no_sparta_fit")
    vecs = [v.get("vector") for v in m.get("vectors", [])]
    if fit:
        if not isinstance(fit, dict) or fit.get("kind") not in FIT_KINDS or not fit.get("reason"):
            errs.append(f"no_sparta_fit must be {{kind: {'|'.join(sorted(FIT_KINDS))}, reason}}")
        if vecs:
            errs.append("no_sparta_fit with vectors")
    elif not vecs:
        errs.append("no vectors")
    for v in m.get("vectors", []):
        if v.get("vector") not in origins:
            errs.append(f"unknown vector {v.get('vector')}")
        errs += [f"vector {v.get('vector')}: {e}" for e in vector_errors(v, desc)]
        if v.get("credential") and v["credential"] not in CREDENTIALS:
            errs.append(f"vector {v['vector']}: unknown credential {v['credential']}")
    entry_of = {v: set(origins[v]["entry"]) for v in vecs if v in origins}
    rows = m.get("rows", [])
    seen: dict[str, dict] = {}
    for r in rows:
        if r.get("technique") in seen:
            errs.append(f"{r.get('technique')}: duplicate row")
        seen[r.get("technique")] = r
    expected = {c["technique"] for c in cand["candidates"]} | set().union(*entry_of.values()) if entry_of else {c["technique"] for c in cand["candidates"]}
    for t in sorted(expected - set(seen)):
        errs.append(f"{t}: not coded")
    added = [t for t, r in seen.items() if r.get("sources") == ["analyst_added"]]
    if len(added) > MAX_ADDED:
        errs.append(f"{len(added)} analyst_added rows (max {MAX_ADDED})")
    for t in sorted(set(seen) - expected - set(added)):
        errs.append(f"{t}: not a candidate, not an entry technique of a chosen vector, not marked analyst_added")
    kept = {t for t, r in seen.items() if r.get("code") in KEEP}
    if fit and kept:
        errs.append(f"no_sparta_fit with kept rows {sorted(kept)}")
    for t, r in seen.items():
        code, where = r.get("code"), f"{t} ({r.get('code')})"
        if t not in live:
            errs.append(f"{t}: not a live SPARTA technique")
            continue
        if r.get("framework", "SPARTA") != "SPARTA":
            errs.append(f"{where}: framework {r.get('framework')} has no catalogue yet")
        if code not in CODES:
            errs.append(f"{where}: unknown code")
            continue
        if not r.get("reason"):
            errs.append(f"{where}: no reason")
        tactic = live[t]["tactic"]
        if t in added and code not in KEEP:
            errs.append(f"{where}: analyst_added rows must be keeps")
        if tactic in PREP_TACTICS and code in KEEP:
            errs.append(f"{where}: {tactic} may only be P-PREP or dropped")
        if code == "P-PREP":
            if tactic not in PREP_TACTICS:
                errs.append(f"{where}: P-PREP only for Reconnaissance/Resource Development")
            if not _enables(r) or not set(_enables(r)) <= kept:
                errs.append(f"{where}: enables must name kept techniques")
        if code in {"K-ACTION", "K-EFFECT"}:
            errs += [f"{where}: {e}" for e in _quote(r.get("enisa_quote"), desc, "enisa_quote")]
        if code in KEEP:
            errs += [f"{where}: {e}" for e in _quote(r.get("sparta_quote"), live[t]["description"], "sparta_quote")]
            role = r.get("role")
            if role not in ROLES:
                errs.append(f"{where}: role missing or unknown")
            elif role not in TACTIC_ROLES.get(tactic, ROLES) and not r.get("role_reason"):
                errs.append(f"{where}: role {role} differs from SPARTA tactic {tactic}; add role_reason")
            rv = r.get("vectors", vecs)
            if "vectors" in r and not rv:
                errs.append(f"{where}: empty vectors")
            for v in rv:
                if v not in vecs:
                    errs.append(f"{where}: vector {v} not chosen")
                elif role == "entry" and t not in entry_of[v]:
                    errs.append(f"{where}: entry role but not an entry technique of vector {v}")
                elif role != "entry" and t in entry_of[v]:
                    errs.append(f"{where}: entry technique of vector {v} must have role entry")
            if "link_only" in r and not r.get("link_only_reason"):
                errs.append(f"{where}: link_only override needs link_only_reason")
            if r.get("ground_side") and not r.get("ground_side_reason"):
                errs.append(f"{where}: ground_side needs ground_side_reason")
        if code == "K-ENABLE" and (not _enables(r) or not set(_enables(r)) <= kept):
            errs.append(f"{where}: enables must name kept techniques (one or a list)")
        if code == "D-OTHER":
            o = r.get("other_threat")
            if o not in index or o == tid:
                errs.append(f"{where}: other_threat must be another ENISA threat in enisa_index.json")
    enabled_by: dict[str, list[dict]] = {}
    for r in seen.values():
        if r.get("code") in KEEP:
            for t in _enables(r):
                enabled_by.setdefault(t, []).append(r)
    for t, en in enabled_by.items():
        r = seen.get(t)
        if not r or r.get("code") not in KEEP or r.get("role") == "entry":
            continue
        for v in r.get("vectors", vecs):
            if not any(v in e.get("vectors", vecs) for e in en):
                errs.append(f"{t}: kept for vector {v} but every step that enables it belongs to another vector")
    for reason, n in collections.Counter(norm(r.get("reason")) for r in rows).items():
        if reason and n > MAX_SAME_REASON:
            errs.append(f"same reason on {n} rows: {reason[:70]}")
    for v in vecs:
        if v in origins and not any(r.get("code") in KEEP and r.get("role") == "entry" and t in origins[v]["entry"]
                                    and v in r.get("vectors", vecs) for t, r in seen.items()):
            errs.append(f"vector {v}: no kept entry technique")
    return [f"{tid}: {e}" for e in errs]


def cross() -> int:
    """D-OTHER rows must point to a threat that keeps the technique."""
    maps = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((TM / "mapping").glob("TR*.json"))}
    kept = {t: {r["technique"] for r in m["rows"] if r["code"] in KEEP} for t, m in maps.items()}
    rows = [(t, r["technique"], r["other_threat"]) for t, m in maps.items() for r in m["rows"] if r["code"] == "D-OTHER"]
    bad = [(t, x, o) for t, x, o in rows if x not in kept.get(o, set())]
    print(f"D-OTHER rows {len(rows)}; target threat does not keep the technique: {len(bad)}")
    for t, x, o in bad:
        print(f"  {t} {x} -> {o}")
    return len(bad)


def surface_check(live: dict, surface: dict, index: dict, adv: dict) -> int:
    errs = []
    controls = surface["controls"]
    for aid, a in surface["architectures"].items():
        for l in a["links"]:
            for end in (l["from"], l["to"]):
                if end not in a["nodes"]:
                    errs.append(f"{aid} {l['id']}: unknown node {end}")
            if l.get("control") and l["control"] not in controls:
                errs.append(f"{aid} {l['id']}: unknown control {l['control']}")
    for o, spec in surface["origins"].items():
        for t in spec["entry"]:
            if t not in live or live[t]["tactic"] != "Initial Access":
                errs.append(f"origin {o}: {t} is not a live Initial Access technique")
    for key in ("link_only", "door", "lateral_crosslink", "reverse_door", "ground_side", "capture"):
        for t in surface[key]["techniques"]:
            if t not in live:
                errs.append(f"{key}: {t} not live")
    modelled = {t for spec in surface["origins"].values() for t in spec["entry"]} | set(surface["door"]["techniques"]) \
        | set(surface["reverse_door"]["techniques"])
    for t in (t for t, x in live.items() if x["tactic"] == "Initial Access"):
        if t not in modelled:
            errs.append(f"{t}: Initial Access technique in no origin and not listed in unmodelled_entry")
    for tid, o in adv["overrides"].items():
        if tid not in index:
            errs.append(f"adversary {tid}: unknown threat")
        elif o["role"] not in {"adversarial", "enabling", "none"}:
            errs.append(f"adversary {tid}: unknown role")
        elif norm(o.get("quote")) not in index[tid]["description"] or not o.get("quote"):
            errs.append(f"adversary {tid}: quote not in ENISA description")
    print("\n".join(errs) if errs else "surface and adversary files: ok")
    return len(errs)


def main(argv: list[str]) -> int:
    live, surface, index, adv = load("sparta_live.json"), load("attack_surface.json"), load("enisa_index.json"), load("adversary.json")
    if argv == ["--cross"]:
        return 1 if cross() else 0
    if argv == ["--surface"]:
        return 1 if surface_check(live, surface, index, adv) else 0
    ids = argv or sorted(p.stem for p in (TM / "mapping").glob("TR*.json"))
    bad = 0
    for tid in ids:
        errs = validate(tid, live, surface, index, adv)
        bad += bool(errs)
        print("\n".join(errs) if errs else f"{tid}: ok")
    if not argv:
        bad += cross() + surface_check(live, surface, index, adv)
        missing = [t for t in index if role_of(adv, index, t) == "adversarial" and not (TM / "mapping" / f"{t}.json").exists()]
        if missing:
            print("adversarial threats without a mapping:", " ".join(missing))
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
