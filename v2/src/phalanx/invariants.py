"""Output invariants (protocol v0.3 Phase 1: I1, I2, I5, I6, I8, I9, I11, I12; Phase 3 subset: I4).

Each check returns human-readable violations; an empty list means the bundle satisfies it.
I8 (wildcard scope) checks each result's `selector_resolution` block against the selector scope registry
(data/selectors/enisa_asset_selectors.json), never against what the block itself claims. I10 (identifiers) is an
input check in Workspace.validate. I1/I2 are enforced on input by threat.schema.json
(additionalProperties=false) and re-checked here on the bundle's threat record.
"""
from __future__ import annotations

import jsonschema

from . import selectors
from .workspace import schema

MANDATORY_PASS = ("version", "behavior", "target", "lifecycle", "reachability", "evidence")
PASS_OR_NA = ("access_position", "authority", "effect")
REALIZED_KEYS = {"mrs", "afg", "crossings", "boundary_verdicts", "cpr_sparta", "cpr_enisa_annex_d", "af"}


def check_selector_resolution(block: dict, registry: dict, architectures: dict | None = None, where: str = "") -> list[str]:
    """I8: resolution never yields an asset outside the selector's documented scope.
    The scope comes from `registry`, not from the block. With `architectures`, each asset is also checked
    against the graph it claims to come from (node exists, hosts the asset, is in the segment, is not adversary-side)."""
    v: list[str] = []
    tag = f"I8: {where}".rstrip() + ":" if where else "I8:"
    defs, classification = registry["selectors"], registry["asset_classification"]
    g = (architectures or {}).get(block.get("variant")) if architectures is not None else None

    def in_scope(a: dict, d: dict) -> bool:
        classes = classification.get(a.get("asset"), {}).get("classes", [])
        for comp in d["components"]:
            if comp["kind"] != "asset_class" or not selectors.segment_matches(registry, comp, a.get("segment")):
                continue
            if comp["class"] == selectors.WILDCARD or any(selectors.class_in_scope(c, comp["class"]) for c in classes):
                return True
        return False

    def asset_problems(a: dict, d: dict, name: str) -> list[str]:
        out = []
        if not in_scope(a, d):
            out.append(f"{tag} selector {name!r} resolved {a.get('asset')}@{a.get('node')} ({a.get('segment')}) "
                       "outside its documented scope")
        if g is not None:
            node = g["nodes"].get(a.get("node"))
            if node is None or a.get("asset") not in node["assets"] or node["segment"] != a.get("segment"):
                out.append(f"{tag} selector {name!r} asset {a.get('asset')}@{a.get('node')} is not in {block.get('variant')} "
                           f"segment {a.get('segment')}")
            elif node.get("scope") == "attacker":
                out.append(f"{tag} selector {name!r} resolved adversary-side asset {a.get('asset')}@{a.get('node')}")
        return out

    if block.get("state") not in selectors.STATES:
        v.append(f"{tag} block state {block.get('state')!r} is not one of {selectors.STATES}")
    union: set[tuple] = set()
    states = []
    for e in block.get("selectors", []):
        name, state = e.get("selector"), e.get("state")
        assets = e.get("assets", [])
        states.append(state)
        if state not in selectors.STATES:
            v.append(f"{tag} selector {name!r} state {state!r} is not one of {selectors.STATES}")
        d = defs.get(name)
        if d is None:
            if assets or state not in ("unresolved", "symbolic"):
                v.append(f"{tag} selector {name!r} has no documented scope but is {state} with {len(assets)} asset(s)")
            continue
        if e.get("scope") != selectors.scope_of(d):
            v.append(f"{tag} selector {name!r} carries a scope that differs from its documented scope")
        if state in ("symbolic", "unresolved") and assets:
            v.append(f"{tag} selector {name!r} is {state} yet lists assets")
        listed = set()
        for a in assets:
            v += asset_problems(a, d, name)
            listed.add((a["asset"], a["node"]))
        union |= {(x, n, name) for x, n in listed}
        comps = e.get("components", [])
        if state in ("scoped_resolved", "partially_resolved", "unresolved"):
            if [c.get("component") for c in comps] != [c["id"] for c in d["components"]]:
                v.append(f"{tag} selector {name!r} evidence does not cover exactly its documented components")
            from_evidence = set()
            for c in comps:
                for m in c.get("matches", []):
                    v += asset_problems(m, d, name)
                    from_evidence.add((m["asset"], m["node"]))
                if c.get("found") != bool(c.get("matches")):
                    v.append(f"{tag} selector {name!r} component {c.get('component')} found flag disagrees with its matches")
            if from_evidence != listed:
                v.append(f"{tag} selector {name!r} asset list differs from its component evidence")
            found = sum(bool(c.get("found")) for c in comps)
            expected = ("scoped_resolved" if found == len(d["components"]) else "partially_resolved" if found
                        else "unresolved")
            if state != expected:
                v.append(f"{tag} selector {name!r} is {state} but {found}/{len(d['components'])} components found assets")
    claimed = {(r.get("asset"), r.get("node"), s) for r in block.get("resolved_assets", []) for s in r.get("selectors", [])}
    if claimed != union:
        v.append(f"{tag} resolved_assets differ from the union of the selector assets")
    if states and block.get("state") != selectors.aggregate_state(states):
        v.append(f"{tag} block state {block.get('state')} disagrees with its selectors' states {sorted(set(states))}")
    return v


def check_bundle(bundle: dict, vocabulary: dict, selector_registry: dict, architectures: dict) -> list[str]:
    """`selector_registry` and `architectures` must come from the workspace that produced the bundle (I8)."""
    v: list[str] = []
    threat = bundle["threat"]
    # I1 / I2: the threat template owns no realized output and never says "crossed"
    leaked = REALIZED_KEYS & (set(threat) | set(threat.get("projection", {})))
    if leaked:
        v.append(f"I1: threat {threat['id']} carries realized output {sorted(leaked)}")
    mr_validator = jsonschema.Draft202012Validator(schema("decision"))
    if "crossed" in str(threat.get("projection", {})):
        v.append(f"I2: threat {threat['id']} projection emits 'crossed'")
    vocab = set(vocabulary["reason_codes"])
    # B2 (scenario-only) has no graph: reachability may be not_applicable
    mandatory = MANDATORY_PASS if bundle.get("method", "B3") == "B3" else tuple(c for c in MANDATORY_PASS if c != "reachability")
    pass_or_na = PASS_OR_NA if bundle.get("method", "B3") == "B3" else PASS_OR_NA + ("reachability",)
    for r in bundle["results"]:
        sid = r["si"]["si_id"]
        mrs = r["mrs"]
        # I11: zero candidates -> no_framework_coverage and no MR
        if not mrs and not any(a["type"] == "no_framework_coverage" for a in r["af"]):
            v.append(f"I11: {sid} has no decisions but no no_framework_coverage finding")
        if mrs and any(a["type"] == "no_framework_coverage" for a in r["af"]):
            v.append(f"I11: {sid} reports no_framework_coverage but has decisions")
        # I8: selector resolution stays inside the documented scope of each selector
        if "selector_resolution" not in r:
            v.append(f"I8: {sid} has no selector_resolution block")
        else:
            v += check_selector_resolution(r["selector_resolution"], selector_registry, architectures, sid)
        for m in mrs:
            where = f"{sid}/{m.get('technique')}"
            for e in mr_validator.iter_errors(m):
                v.append(f"schema: {where}: {e.message}")
            res = {c["code"]: c["result"] for c in m.get("checks", [])}
            # I12: reason codes and check codes come from the closed vocabulary
            bad = (set(m.get("reason_codes", [])) | set(res)) - vocab
            if bad:
                v.append(f"I12: {where} uses codes outside the vocabulary: {sorted(bad)}")
            if m.get("status") == "accepted":
                # I5: accepted needs every mandatory dimension and evidence
                for code in mandatory:
                    if res.get(code) != "pass":
                        v.append(f"I5: {where} accepted but {code} is {res.get(code, 'missing')}")
                for code in pass_or_na:
                    if res.get(code) not in ("pass", "not_applicable"):
                        v.append(f"I5: {where} accepted but {code} is {res.get(code, 'missing')}")
                if not m.get("supporting_evidence"):
                    v.append(f"I5: {where} accepted without supporting evidence")
            # I6: a missing mandatory fact can only yield unresolved (or rejected on another check)
            if any(r_ == "unknown" for r_ in res.values()) and m.get("status") == "accepted":
                v.append(f"I6: {where} accepted with an unknown check")
            if m.get("status") == "unresolved" and not m.get("root_facts"):
                v.append(f"I6: {where} unresolved without naming the missing fact")
            # I9: provenance keeps source, rule, version and scenario
            prov = m.get("provenance", {})
            for key in ("scenario", "threat", "rules", "catalog", "engine", "method"):
                if not prov.get(key):
                    v.append(f"I9: {where} provenance lacks {key}")
            if prov.get("scenario") != sid:
                v.append(f"I9: {where} provenance names scenario {prov.get('scenario')}")
        # I4: crossed requires an accepted action that traverses the edge
        accepted = {m["technique"] for m in mrs if m["status"] == "accepted"}
        crossings = r["afg"].get("crossings", {})
        for bv in r["boundary_verdicts"]:
            if bv["verdict"] == "crossed":
                walkers = crossings.get(bv["edge"], [])
                if not walkers or not set(walkers) <= accepted:
                    v.append(f"I4: {sid}/{bv['edge']} is crossed without an accepted traversing action")
        for eid, walkers in crossings.items():
            if not set(walkers) <= accepted:
                v.append(f"I4: {sid}/{eid} crossing lists non-accepted actions {sorted(set(walkers) - accepted)}")
    return v
