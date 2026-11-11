"""ENISA Annex C asset selectors: symbolic at ET/ETP level, resolved only against the selected SI and G
(protocol v0.3 §1.4, invariant I8).

An ET carries `affected_asset_selectors`, e.g. "Space: BUS (CDHS/COM)" or "Ground: all assets". They are broad
on purpose and are never expanded at ET level. This module

  * reads the documented scope of every selector clause from data/selectors/enisa_asset_selectors.json
    (rule ET-P-SEL-01: segment + asset-class components; `assumed` wherever ENISA gives no definition);
  * resolves a selector list against ONE variant graph G for ONE SI (rule SI-I-SEL-01) and records, per
    component, which G assets matched and which clause they matched under.

States per selector (and, aggregated, per SI):
  symbolic           not resolved: no SI + G in play (ET level, or a method without a graph, B2)
  scoped_resolved    every scope component found at least one in-scope asset in G
  partially_resolved some components found assets, others name scope that G does not represent
  unresolved         nothing in G lies within the selector's scope (or the clause has no documented scope)

Scope rules (the guarantee I8 re-checks in invariants.py):
  * an asset resolves only if its node's segment is one the component names AND (unless the component is a
    segment wildcard) the asset's ENISA class is the component's class or a descendant of it;
  * attacker-scoped nodes (adversary infrastructure) are never affected assets and are only listed as `excluded`;
  * a clause missing from the registry is `unresolved`, never guessed;
  * qualifiers that name an attribute of an asset (antenna, SLE/SDL protocol) are `aspects`: they do not narrow
    the host asset and are recorded as `aspects_not_modelled_in_G`; protocol-only clauses name no asset and stay
    unresolved because G carries no protocol attribute.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

RULE_SCOPE = "ET-P-SEL-01"
RULE_RESOLVE = "SI-I-SEL-01"
REGISTRY_REL = "selectors/enisa_asset_selectors.json"
STATES = ("symbolic", "scoped_resolved", "partially_resolved", "unresolved")
WILDCARD = "*"

_PREFIX = re.compile(r"^((?:Ground|Space|User|Human [Rr]esources)(?: & (?:Ground|Space|User|Human [Rr]esources))*):\s*(.*)$")
_TAG = re.compile(r"\s*\[([^\]]*)\]\s*$")


# ------------------------------------------------------------------ registry

def load_registry(source) -> dict:
    """`source`: a Workspace (its file is then part of the provenance hashes), a data root, or a file path."""
    if hasattr(source, "root") and hasattr(source, "files"):
        p = Path(source.root) / REGISTRY_REL
        source.files[REGISTRY_REL] = p
    else:
        p = Path(source)
        p = p if p.suffix == ".json" else p / REGISTRY_REL
    return json.loads(p.read_text(encoding="utf-8"))


def _canon_segment(name: str) -> str:
    return "Human Resources" if name.lower() == "human resources" else name


def split_top(text: str, seps: tuple[str, ...]) -> list[str]:
    """Split on separators that sit outside every () and []."""
    out, cur, depth, i = [], "", 0, 0
    while i < len(text):
        ch = text[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        hit = next((s for s in seps if depth == 0 and text.startswith(s, i)), None)
        if hit:
            out.append(cur)
            cur, i = "", i + len(hit)
            continue
        cur += ch
        i += 1
    out.append(cur)
    return [x.strip() for x in out if x.strip()]


def split_selector_text(text: str) -> list[dict]:
    """Split ENISA's 'affected assets' cell into selector clauses (the strings an ET stores in
    `affected_asset_selectors`). ';' inside parentheses/brackets does not split; a clause without a segment
    prefix inherits the previous clause's segments. Returns [{clause, segments, segment_inherited, body, context}]."""
    out, prev = [], None
    for clause in split_top(text, (";",)):
        m = _PREFIX.match(clause)
        if m:
            segs = [_canon_segment(s.strip()) for s in m.group(1).split(" & ")]
            body, inherited = m.group(2), False
        elif prev:
            segs, body, inherited = prev, clause, True
        else:
            raise ValueError(f"first selector clause has no segment prefix: {clause!r}")
        tag = _TAG.search(body)
        context = [tag.group(1)] if tag else []
        body = _TAG.sub("", body)
        out.append({"clause": clause, "segments": segs, "segment_inherited": inherited, "body": body, "context": context})
        prev = segs
    return out


def class_in_scope(asset_class: str, scope_class: str) -> bool:
    """A class lies in a component's scope when it is the scope class or one of its descendants (dotted ids)."""
    return scope_class == WILDCARD or asset_class == scope_class or asset_class.startswith(scope_class + ".")


def validate_registry(reg: dict) -> list[str]:
    """Internal consistency of the scope definitions; empty list = consistent."""
    errs = []
    classes, segments = reg["classes"], reg["segments"]
    for cid, c in classes.items():
        if c["segment"] not in segments:
            errs.append(f"class {cid}: unknown segment {c['segment']}")
        if not cid.startswith(c["segment"].lower().replace(" ", "_") + "."):
            errs.append(f"class {cid}: id does not start with its segment")
        parent = cid.rsplit(".", 1)[0]
        if parent.count(".") >= 1 and parent not in classes:
            errs.append(f"class {cid}: parent class {parent} is not defined")
    for aid, a in reg["asset_classification"].items():
        for cid in a["classes"]:
            if cid not in classes:
                errs.append(f"asset {aid}: unknown class {cid}")
        if not a.get("basis"):
            errs.append(f"asset {aid}: no basis")
    for sel, d in reg["selectors"].items():
        if not d["components"]:
            errs.append(f"selector {sel!r}: no components")
        if d["scope_basis"] not in ("source", "assumed"):
            errs.append(f"selector {sel!r}: scope_basis must be source|assumed")
        if d["scope_basis"] == "assumed" and not d.get("assumptions"):
            errs.append(f"selector {sel!r}: assumed scope without a stated assumption")
        for comp in d["components"]:
            if not set(comp["segments"]) <= set(segments):
                errs.append(f"selector {sel!r}: component {comp['id']} names unknown segment")
            if comp["kind"] == "asset_class":
                cl = comp["class"]
                if cl != WILDCARD:
                    if cl not in classes:
                        errs.append(f"selector {sel!r}: component {comp['id']} class {cl} is not defined")
                    elif classes[cl]["segment"] not in comp["segments"]:
                        errs.append(f"selector {sel!r}: component {comp['id']} class {cl} lies outside its segments")
            elif comp["kind"] != "protocol_interface":
                errs.append(f"selector {sel!r}: component {comp['id']} has unknown kind {comp['kind']}")
    return errs


# ------------------------------------------------------------------ resolution

def segment_matches(registry: dict, comp: dict, node_segment: str | None) -> bool:
    """True when a G node segment is one of the architecture segments the component's ENISA segments denote."""
    return any(node_segment in registry["segments"][s]["g_segments"] for s in comp["segments"])


def aggregate_state(states: list[str]) -> str:
    """Block state from selector states: all equal stays that state; otherwise partially_resolved."""
    uniq = set(states)
    if not uniq:
        return "unresolved"
    if len(uniq) == 1:
        return next(iter(uniq))
    return "partially_resolved"


def scope_of(definition: dict) -> list[dict]:
    return [{k: c[k] for k in ("id", "kind", "segments", "class", "aspects", "text") if k in c}
            for c in definition["components"]]


def symbolic(selectors: list[str], registry: dict, reason: str = "no SI/G supplied") -> dict:
    """ET/ETP-level view: every selector keeps its documented scope and nothing is resolved."""
    entries = []
    for s in selectors:
        d = registry["selectors"].get(s)
        entries.append({"selector": s, "state": "symbolic", "documented": d is not None,
                        "scope_basis": d["scope_basis"] if d else None,
                        "scope": scope_of(d) if d else [], "components": [], "assets": []})
    return {"rule": RULE_RESOLVE, "scope_rule": RULE_SCOPE, "registry": registry["id"], "state": "symbolic",
            "reason": reason, "selectors": entries, "resolved_assets": []}


def resolve(selectors: list[str], si: dict | None, g: dict | None, registry: dict,
            candidate_assets: list[str] | None = None) -> dict:
    """Resolve `selectors` against G for the selected SI. Without both SI and G the result is symbolic."""
    if si is None or g is None:
        return symbolic(selectors, registry, "no SI/G supplied" if si is None and g is None else
                        "no architecture graph (scenario-only method)" if g is None else "no SI supplied")
    if g["id"] != si["variant"]:
        raise ValueError(f"{si['si_id']} is defined on {si['variant']} but was given graph {g['id']}")
    selected = set(si["selected_asset_instances"].items())
    entries, union = [], {}
    for s in selectors:
        d = registry["selectors"].get(s)
        if d is None:
            entries.append({"selector": s, "state": "unresolved", "documented": False, "scope_basis": None,
                            "scope": [], "components": [], "assets": [],
                            "reason": "no documented scope for this selector clause; nothing is guessed"})
            continue
        comps, assets = [], {}
        for comp in d["components"]:
            matches, excluded = _match(comp, g, registry, s, selected)
            ev = {"component": comp["id"], "found": bool(matches), "matches": matches, "excluded": excluded}
            if comp["kind"] == "protocol_interface":
                ev["reason"] = "protocol-only scope names no asset and G carries no protocol attribute on its edges"
            elif not matches:
                ev["reason"] = f"no asset of G lies in {'/'.join(comp['segments'])} segment scope " + \
                               ("(any asset)" if comp["class"] == WILDCARD else f"with class {comp['class']}")
            if comp.get("aspects"):
                ev["aspects_not_modelled_in_G"] = list(comp["aspects"])
            comps.append(ev)
            for m in matches:
                assets.setdefault(m["asset"], m)
        found = sum(c["found"] for c in comps)
        state = "scoped_resolved" if found == len(comps) else "partially_resolved" if found else "unresolved"
        entries.append({"selector": s, "state": state, "documented": True, "scope_basis": d["scope_basis"],
                        "scope": scope_of(d), "components": comps,
                        "assets": [{k: v for k, v in assets[a].items() if k not in ("component", "matched_class")}
                                   for a in sorted(assets)]})
        for a, m in assets.items():
            union.setdefault(a, {"asset": a, "node": m["node"], "segment": m["segment"], "selectors": []})
            union[a]["selectors"].append(s)
    state = aggregate_state([e["state"] for e in entries])
    resolved = [union[a] for a in sorted(union)]
    block = {"rule": RULE_RESOLVE, "scope_rule": RULE_SCOPE, "registry": registry["id"], "state": state,
             "variant": g["id"], "selectors": entries, "resolved_assets": resolved,
             "si_selected": _selected_report(si, {r["asset"] for r in resolved})}
    if candidate_assets is not None:
        block["projection_comparison"] = compare_candidates(block, candidate_assets)
    return block


def _match(comp: dict, g: dict, registry: dict, selector: str, selected: set) -> tuple[list, list]:
    """In-scope assets of G for one component, plus in-scope assets left out because they are adversary-side."""
    if comp["kind"] != "asset_class":
        return [], []
    classification = registry["asset_classification"]
    matches, excluded = [], []
    for nid in sorted(g["nodes"]):
        node = g["nodes"][nid]
        if not segment_matches(registry, comp, node["segment"]):
            continue
        for asset in sorted(node["assets"]):
            classes = classification.get(asset, {}).get("classes", [])
            if comp["class"] == WILDCARD:
                hit = WILDCARD
            else:
                hit = next((c for c in classes if class_in_scope(c, comp["class"])), None)
            if hit is None:
                continue
            if node.get("scope") == "attacker":
                excluded.append({"asset": asset, "node": nid,
                                 "reason": "attacker-scoped node: adversary infrastructure is not an affected asset"})
                continue
            matches.append({"asset": asset, "node": nid, "segment": node["segment"], "asset_classes": classes,
                            "matched_class": hit, "scope_clause": selector, "component": comp["id"],
                            "selected_by_si": (asset, nid) in selected})
    return matches, excluded


def _selected_report(si: dict, resolved: set[str]) -> dict:
    sel = si["selected_asset_instances"]
    return {"assets": sorted(sel), "inside_resolved_scope": sorted(a for a in sel if a in resolved),
            "outside_resolved_scope": sorted(a for a in sel if a not in resolved)}


def compare_candidates(block: dict, candidate_assets: list[str]) -> dict:
    """Resolution vs the hand-authored `projection.candidate_assets` (reported, never changed)."""
    res = {r["asset"] for r in block["resolved_assets"]}
    cand = set(candidate_assets)
    return {"candidate_assets": sorted(cand), "resolved_assets": sorted(res),
            "agreed": sorted(res & cand), "only_in_resolution": sorted(res - cand),
            "only_in_candidate_assets": sorted(cand - res), "agree": res == cand}
