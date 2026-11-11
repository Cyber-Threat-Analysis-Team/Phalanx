"""Markdown rendering of a run bundle. Presentation only: reads the bundle, computes nothing new."""
from __future__ import annotations

import collections

from .pipeline import summary


def _unresolved_split(mrs):
    """(system state only, state + own evidence gap, own evidence gap only, entry-evidence gap only, facts)."""
    state_only = both = ev_only = entry_only = 0
    facts = set()
    for m in mrs:
        if m["status"] != "unresolved":
            continue
        st = [f for f in m["root_facts"] if f.startswith("SI.")]
        ev = "ET-linked evidence" in m["root_facts"]
        facts.update(st)
        if st and ev:
            both += 1
        elif st:
            state_only += 1
        elif ev:
            ev_only += 1
        else:
            entry_only += 1
    return state_only, both, ev_only, entry_only, sorted(facts)


# kill-chain stages; order between stages follows the engine's gating (entry before on-board), order inside a
# stage is not asserted
_STAGES = [("Ground foothold", {"ground"}, None), ("Entry to the spacecraft", {"entry"}, None),
           ("On-board execution", None, {"Execution", "Defense Evasion", "Lateral Movement", "Exfiltration"}),
           ("Persistence", None, {"Persistence"}), ("Impact", None, {"Impact"})]


def _stage(m, kind_of):
    kind = kind_of.get(m["technique"])
    for name, kinds, tactics in _STAGES:
        if (kinds and kind in kinds) or (tactics and kind not in ("ground", "entry") and m["tactic"] in tactics):
            return name
    return "Other"


def _kill_chain(r) -> list[str]:
    """Accepted steps grouped by kill-chain stage (parent and sub-techniques on one row), with the boundary crossed
    and the supporting evidence; then the steps held back only by unknown scenario facts."""
    nodes = r["afg"]["nodes"]
    mrs = {m["technique"]: m for m in r["mrs"]}
    if not nodes:
        L = ["**Kill chain:** none — no technique is accepted for this scenario.", ""]
    else:
        crossing = {t: e for e, ts in r["afg"]["crossings"].items() for t in ts}
        # stage kind from how the engine reached the step: a ground step resides on a mission ground node,
        # an entry step traverses an edge from the attacker's origin; everything else needs the on-board foothold
        kind_of = {}
        for t in nodes:
            reach = next((c["detail"] for c in mrs[t]["checks"] if c["code"] == "reachability"), "")
            kind_of[t] = ("ground" if "mission ground node" in reach else
                          "entry" if reach.startswith("edge ") else None)
        groups: dict[str, dict[str, list[str]]] = {}
        for t in nodes:
            groups.setdefault(_stage(mrs[t], kind_of), {}).setdefault(t.split(".")[0], []).append(t)
        L = ["**Kill chain** (accepted steps by stage; the entry stage gates the on-board stages, order inside a "
             "stage is not asserted):", "",
             "| Stage | SPARTA technique(s) | Crosses boundary | Supported by |", "|---|---|---|---|"]
        for name, _, _ in _STAGES + [("Other", None, None)]:
            for parent, ts in groups.get(name, {}).items():
                ids = ", ".join(f"`{t}`" for t in ts)
                names = "; ".join(mrs[t]["name"] for t in ts)
                cross = ", ".join(sorted({crossing[t] for t in ts if t in crossing})) or "—"
                ev = ", ".join(sorted({mrs[t].get("evidence_clause") or "—" for t in ts}))
                L.append(f"| {name} | {ids} {names} | {cross} | {ev} |")
        L.append("")
    held = collections.defaultdict(list)
    for m in r["mrs"]:
        if m["status"] == "unresolved" and m["root_facts"] and all(f.startswith("SI.") for f in m["root_facts"]):
            held[tuple(sorted(m["root_facts"]))].append(m["technique"])
    if held:
        L += ["**Conditional steps** (unresolved only because these scenario facts are unknown):", ""]
        for facts, ts in sorted(held.items()):
            L.append(f"- {', '.join(f'`{f}`' for f in facts)}: {len(ts)} step(s) — {', '.join(sorted(ts))}")
        L.append("")
    return L


def render(bundle: dict) -> str:
    t = bundle["threat"]
    L = [f"# {t['id']} {t['name']} — run report", "",
         f"Canonical hash `{bundle['canonical_sha256']}` · engine {bundle['generated_by']['engine']}", "",
         f"> {t['description']}", "",
         f"T1 crosswalk: {bundle['t1_baseline']['workbook_rows']} workbook rows → {bundle['t1_baseline']['controls']} "
         f"ENISA controls → {bundle['t1_baseline']['techniques']} SPARTA techniques.", ""]
    if bundle["invariant_violations"]:
        L += ["## Invariant violations", ""] + [f"- {v}" for v in bundle["invariant_violations"]] + [""]
    L += ["## Outcome per scenario", "", "| Scenario | Variant | Attacker | Candidates | Accepted | Rejected | Unresolved | Crossed |",
          "|---|---|---|---|---|---|---|---|"]
    for s in summary(bundle):
        L.append(f"| {s['scenario']} | {s['variant']} | {s['attacker']} | {s['candidates']} | {s['accepted']} | "
                 f"{s['rejected']} | {s['unresolved']} | {', '.join(s['crossed']) or '—'} |")
    L.append("")
    for r in bundle["results"]:
        si = r["si"]
        L += [f"## {si['si_id']}: {si['label']}", ""]
        L += _kill_chain(r)
        acc = r["afg"]["nodes"]
        if acc:
            L += [f"{r['afg']['check_AFG-CHK-01']}; {r['afg']['check_AFG-CHK-02']}", ""]
        rej = collections.Counter(c for m in r["mrs"] if m["status"] == "rejected" for c in m["reason_codes"])
        if rej:
            L += ["**Rejected by check:** " + ", ".join(f"{k} {v}" for k, v in rej.items()), ""]
        so, both, ev, entry, facts = _unresolved_split(r["mrs"])
        if so + both + ev + entry:
            L += [f"**Unresolved:** {so} system state only, {both} system state + evidence gap, {ev} evidence gap only, "
                  f"{entry} only because the entry steps lack evidence. "
                  f"Unknown system facts: {', '.join(f'`{f}`' for f in facts) or '—'}", ""]
        if r["boundary_verdicts"]:
            L += ["| Edge | Role | Paper TB (figure alias) | Verdict | Basis |", "|---|---|---|---|---|"]
            for v in r["boundary_verdicts"]:
                alias = "/".join(v["figure_alias"]) or "—"
                if v["figure_alias"] and v["figure_alias_basis"].startswith("interpretation"):
                    alias += " (interp.)"
                L.append(f"| {v['edge']} | {v['role']} | {alias} | **{v['verdict']}** | {v['basis']} |")
            L.append("")
        af = collections.Counter(a["type"] for a in r["af"])
        L += ["**Findings:** " + ", ".join(f"{k} {v}" for k, v in sorted(af.items())), ""]
    return "\n".join(L)


def explain(bundle: dict, scenario: str, technique: str) -> str:
    r = next((r for r in bundle["results"] if r["si"]["si_id"] == scenario), None)
    if r is None:
        raise KeyError(f"no scenario {scenario} in bundle")
    m = next((m for m in r["mrs"] if m["technique"] == technique), None)
    if m is None:
        raise KeyError(f"{technique} was not a candidate in {scenario}")
    L = [f"{m['technique']} {m['name']} ({m['tactic']}) in {scenario}",
         f"status: {m['status']}" + (f"  reason codes: {', '.join(m['reason_codes'])}" if m["reason_codes"] else ""),
         f"proposed by: {', '.join(m['generators'])}", ""]
    w = max(len(c["code"]) for c in m["checks"])
    for c in m["checks"]:
        L.append(f"  {c.get('rule', ''):<10}  {c['code']:<{w}}  {c['result']:<14}  {c['detail']}")
    if m["root_facts"]:
        L += ["", "missing facts: " + ", ".join(m["root_facts"])]
    return "\n".join(L)
