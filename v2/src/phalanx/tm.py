"""Threat-modeling showcase engine, v2.

Input per threat: the mapping data/tm/mapping/<TRxx>.json (access vectors + one code per SPARTA candidate). This module
never judges a technique; it places the kept techniques on the architecture and filters them per scenario.

Scenario = threat × architecture × access vector (attacker origin) × entry path × attacker credential × control setting.
- Entry paths are computed from the architecture links (attach rules in data/tm/attack_surface.json).
- An entry technique is accepted only on a path that contains its channel; if it injects traffic, the control on that
  link must be off or bypassed by the attacker's credential. It lands the attacker at the far end of that link.
- From the landing point the attacker moves along the rest of the path: a hosted→bus link needs a kept door technique
  and segregation off; an inter-satellite link needs a kept crosslink technique (LM-0003); any other controlled link
  needs the control off or a credential that bypasses it.
- Other kept steps: link-only steps need only the radio link (for origins that attack links, or an attacker inside a
  ground station on the radio path); capture steps fail on an encrypting link whose control is on; ground-side steps
  need an accepted entry; on-board steps need the bus reached; steps with a step-authority need TC access or a
  credential; a step that has enablers anywhere in the threat's mapping needs one of them accepted in this scenario.
Every removed step keeps its reason.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TM = ROOT / "data" / "tm"
ROLE_ORDER = ["entry", "execution", "persistence", "evasion", "lateral", "exfiltration", "impact"]
KEEP = {"K-ACTION", "K-ENABLE", "K-EFFECT"}
OUTCOME = {"impact", "exfiltration"}


@dataclass(frozen=True)
class Model:
    surface: dict
    live: dict
    index: dict
    adversary: dict

    @classmethod
    def load(cls) -> "Model":
        rd = lambda p: json.loads(p.read_text(encoding="utf-8"))
        return cls(rd(TM / "attack_surface.json"), rd(TM / "sparta_live.json"), rd(TM / "enisa_index.json"), rd(TM / "adversary.json"))

    def mapping(self, tid: str) -> dict | None:
        p = TM / "mapping" / f"{tid}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def role(self, tid: str) -> dict:
        """Adversary role: ENISA category by default, ENISA-quoted override where the description says otherwise."""
        if tid in self.adversary["overrides"]:
            return self.adversary["overrides"][tid]
        adv = self.index[tid]["category"] in self.adversary["default_adversarial_categories"]
        return {"role": "adversarial" if adv else "none", "reason": "ENISA category"}

    def step_authority(self, tech: str) -> str | None:
        auth = self.surface["step_authority"]
        return auth[tech] if tech in auth else auth.get(tech.split(".")[0])


# ------------------------------------------------------------------ entry paths

def _walk(arch: dict, node: str, via: list[str], seen: set[str], out: list[dict]) -> None:
    """Follow links from node to every satellite bus; once in space, stay in space; stop at the first bus.
    A space node with no onward link (a transparent relay payload) ends the path there."""
    nodes = arch["nodes"]
    onward = False
    for l in arch["links"]:
        if node not in (l["from"], l["to"]):
            continue
        nxt = l["to"] if l["from"] == node else l["from"]
        if nxt in seen or (nodes[node]["segment"] != "ground" and nodes[nxt]["segment"] == "ground"):
            continue
        if nodes[node]["segment"] == "space" and nodes[nxt]["segment"] == "user":
            continue
        onward = True
        step = via + [l["id"]]
        if nxt.endswith(".bus"):
            out.append({"links": step, "reaches": nxt})
        else:
            _walk(arch, nxt, step, seen | {nxt}, out)
    if not onward and nodes[node]["segment"] == "space" and not node.endswith(".bus"):
        out.append({"links": via, "reaches": node})


def entry_paths(arch: dict, origin: dict) -> list[dict]:
    """Entry paths of one attacker origin, computed from the architecture's links (never hand-listed)."""
    att, links = origin["attach"], {l["id"]: l for l in arch["links"]}
    out: list[dict] = []
    if "from_nodes" in att:
        for start in att["from_nodes"]:
            if start in arch["nodes"]:
                _walk(arch, start, [], {start}, out)
    elif att["rule"] == "rogue_on_links":
        for l in arch["links"]:
            if l["kind"] in att["link_kinds"]:
                tail: list[dict] = []
                if l["to"].endswith(".bus"):
                    tail = [{"links": [], "reaches": l["to"]}]
                else:
                    _walk(arch, l["to"], [], {l["from"], l["to"]}, tail)
                out += [{"links": [l["id"]] + t["links"], "reaches": t["reaches"], "rogue": l["id"]} for t in tail]
    elif att["rule"] == "across_isl":
        for l in (l for l in arch["links"] if l["kind"] == "isl"):
            for src, dst in ((l["from"], l["to"]), (l["to"], l["from"])):
                tail: list[dict] = []
                _walk(arch, dst, [], {src, dst}, tail)
                out += [{"links": [l["id"]] + t["links"], "reaches": t["reaches"], "from_satellite": src.split(".")[0]} for t in tail]
    elif att["rule"] == "proximity":
        out = [{"links": [], "reaches": n, "proximity": True} for n in arch["nodes"] if n.endswith(".bus")]
    for p in out:
        p["kinds"] = (["proximity"] if p.get("proximity") else []) + [links[i]["kind"] for i in p["links"]]
        p["via"] = ([f"{att['via_first']} → {att['from_nodes'][0]}"] if att.get("via_first") else []) + \
                   ([f"{p['links'][0]} (rogue)"] + p["links"][1:] if p.get("rogue") else list(p["links"])) + \
                   (["proximity"] if p.get("proximity") else [])
    return sorted(out, key=lambda e: (e["reaches"], e["via"]))


def _far_ends(plinks: list[dict], reaches: str) -> list[str]:
    """Node at which each path link is left: the node shared with the next link, the last link ends at the path's end.
    Links are walked in both directions, so this is not always the link's `to`."""
    ends = [l["to"] if l["to"] in (n["from"], n["to"]) else l["from"] for l, n in zip(plinks, plinks[1:])]
    return ends + [reaches] if plinks else []


def boundaries(arch: dict, path: dict) -> list[str]:
    """Operator changes along the path (node operated_by), including attacker → system at a rogue or proximity entry."""
    nodes, links = arch["nodes"], {l["id"]: l for l in arch["links"]}
    out = []
    if path.get("rogue"):
        out.append(f"{path['rogue']}: attacker→{nodes[links[path['rogue']]['to']]['operated_by']}")
    if path.get("proximity"):
        out.append(f"proximity: attacker→{nodes[path['reaches']]['operated_by']}")
    if any(v.startswith("partner connection") for v in path["via"]):
        out.append("partner connection: partner→mission_operator")
    if path.get("from_satellite"):
        first = links[path["links"][0]]
        near = first["to"] if first["from"].startswith(path["from_satellite"]) else first["from"]
        out.append(f"{first['id']}: neighbour satellite→{nodes[near]['operated_by']}")
    far = _far_ends([links[i] for i in path["links"]], path["reaches"])
    for i, lid in enumerate(path["links"]):
        l = links[lid]
        if path.get("rogue") == lid or (path.get("from_satellite") and lid == path["links"][0]):
            continue
        end = far[i]
        start = far[i - 1] if i else (l["from"] if end == l["to"] else l["to"])
        a, b = nodes[start]["operated_by"], nodes[end]["operated_by"]
        seg = nodes[start]["segment"] != nodes[end]["segment"]
        if a != b:
            out.append(f"{lid}: {a}→{b}" + (" (ground→space)" if seg else ""))
        elif seg:
            out.append(f"{lid}: ground→space ({a})")
    return out


# ------------------------------------------------------------------ scenario filter

def _bypass(m: Model, control: str, cred: str) -> bool:
    return m.surface["controls"][control]["bypassed_by"] == cred


def _evaluate(m: Model, arch: dict, origin: dict, path: dict, cred: str, on: set[str], rows: list[dict],
              kept_rows: list[dict]) -> dict:
    mine = {r["technique"] for r in rows}      # door / crosslink / reverse door must be kept for this attacker origin
    links = {l["id"]: l for l in arch["links"]}
    plinks = [links[i] for i in path["links"]]
    far = _far_ends(plinks, path["reaches"])
    blocked = lambda l: l.get("control") in on and not _bypass(m, l["control"], cred)
    steps: list[dict] = []
    land = None            # index in plinks after which the attacker stands (-1: before the first link)
    for r in rows:
        if r["role"] != "entry":
            continue
        spec = origin["entry"].get(r["technique"])
        why = None
        if spec is None:
            continue       # entry technique of another vector
        if spec["channel"] == "any":
            idx = -1
        elif spec["channel"] in path["kinds"]:
            idx = next(i for i, l in enumerate(plinks) if l["kind"] == spec["channel"]) if spec["channel"] != "proximity" else -1
            if spec.get("injects") and idx >= 0 and blocked(plinks[idx]):
                why = f"authority: {plinks[idx]['control']} on; needs {m.surface['controls'][plinks[idx]['control']]['bypassed_by'] or 'it off'}"
            if spec.get("injects") and spec["channel"] == "proximity" and "sdls" in on:
                why = "authority: sdls on; a rogue spacecraft's telecommands are not authenticated"
        else:
            why = f"reachability: this path has no {spec['channel']} link"
        steps.append({"technique": r["technique"], "role": "entry", "code": r["code"], "removed": why, "link_only": False})
        if why is None and spec["channel"] != "any":
            land = max(land if land is not None else -1, idx)
        elif why is None:
            land = land if land is not None else -2   # foothold on the ground side only
    reached, stop = None, None
    if land is not None and land >= -1:
        if path.get("proximity"):
            reached = path["reaches"]
        else:
            reached = far[land] if land >= 0 else None
            for i in range(land + 1, len(plinks)):
                l = plinks[i]
                if l["kind"] == "hosted" and not (set(m.surface["door"]["techniques"]) & mine):
                    stop = "no door technique (IA-0006/LM-0001) kept for this threat"
                elif l["kind"] == "hosted" and blocked(l):
                    stop = "segregation of the hosted RAN from the bus is on"
                elif l["kind"] == "isl" and not (set(m.surface["lateral_crosslink"]["techniques"]) & mine):
                    stop = "no crosslink technique (LM-0003) kept for this threat"
                elif l["kind"] != "hosted" and blocked(l):
                    stop = f"{l['control']} on; needs {m.surface['controls'][l['control']]['bypassed_by']}"
                if stop:
                    break
                reached = far[i]
    on_bus = bool(reached and reached.endswith(".bus"))
    entered = land is not None
    # ground-side steps need an attacker that starts on the ground side (a user terminal does not)
    ground_ok = entered and any(arch["nodes"].get(n, {}).get("segment") == "ground" for n in origin["attach"].get("from_nodes", []))
    # radio links the attacker can act on: its rogue link, its service link, or the TT&C link of a ground station it is in
    acts_on = set()
    if path.get("rogue"):
        acts_on.add(links[path["rogue"]]["kind"])
    if origin["link_attack"] and "service_link" in path["kinds"]:
        acts_on.add("service_link")
    if ground_ok and "tc_uplink" in path["kinds"]:
        acts_on.add("tc_uplink")
    link_only = m.surface["link_only"]["techniques"]
    for r in rows:
        if r["role"] == "entry":
            continue
        t, why = r["technique"], None
        kinds = set(link_only.get(t, ["tc_uplink", "feeder", "service_link", "gnss"] if r.get("link_only") else []))
        lo = r.get("link_only", t in link_only) and bool(kinds & acts_on)
        auth = m.step_authority(t)
        if auth == "tc":
            if "tc_uplink" not in path["kinds"]:
                why = "authority: sends telecommands; this path has no TT&C uplink"
            elif "sdls" in on and cred != "mission_valid":
                why = "authority: sends telecommands; sdls on and no mission keys"
        elif auth == "credential" and cred != "mission_valid":
            why = "authority: needs a mission-valid credential; attacker has none"
        if why is None and t in m.surface["lateral_crosslink"]["techniques"] and not any(l["kind"] == "isl" for l in arch["links"]):
            why = "reachability: no inter-satellite link in this architecture"
        if why is None and lo and t in m.surface["capture"]["techniques"]:
            enc = [l for l in plinks + ([links[path["rogue"]]] if path.get("rogue") else []) if l["kind"] in acts_on
                   and l.get("control") in on and m.surface["controls"][l["control"]]["encrypts"]
                   and m.surface["controls"][l["control"]].get("capture_bypassed_by") != cred]
            if enc:
                why = f"authority: {enc[0]['control']} encrypts the link; content cannot be read"
        if why is None:
            if lo:
                pass
            elif t in m.surface["ground_side"]["techniques"] or r.get("ground_side"):
                if not ground_ok:
                    why = "reachability: needs an attacker on the ground side with an accepted entry"
            elif not on_bus:
                why = "reachability: " + (stop or ("needs an accepted entry into the satellite" if entered else "no accepted entry step"))
        steps.append({"technique": t, "role": r["role"], "code": r["code"], "removed": why, "link_only": bool(lo)})
    link_actions = any(s["link_only"] and s["removed"] is None and s["role"] != "impact" for s in steps)
    for s in steps:      # a link-only impact needs an accepted link-only action (jam, flood, spoof, capture) in the same scenario
        if s["link_only"] and s["removed"] is None and s["role"] == "impact" and not link_actions and not on_bus:
            s["removed"] = "chain: no accepted link-level action produces this outcome"
    enablers: dict[str, set[str]] = {}
    for r in kept_rows:            # every kept row of the threat, any vector, any keep code
        if r.get("enables"):
            for target in ([r["enables"]] if isinstance(r["enables"], str) else r["enables"]):
                enablers.setdefault(target, set()).add(r["technique"])
    present = {s["technique"] for s in steps}
    changed = True
    while changed:          # a step whose enablers are all removed, or all belong to another origin, is removed too
        changed = False
        ok = {s["technique"] for s in steps if s["removed"] is None}
        for s in steps:
            en = enablers.get(s["technique"], set())
            if s["removed"] is None and en and not (en & ok) and s["role"] != "entry" and not s["link_only"]:
                s["removed"] = ("chain: every step that enables it is removed" if en & present
                                else "chain: the steps that enable it belong to another attacker origin")
                changed = True
    for s in steps:
        s["name"] = m.live[s["technique"]]["name"]
    host_links_on = [l for l in arch["links"] if l["kind"] == "hosted" and l["to"] == reached and blocked(l)]
    funcs = sorted(n for n, x in arch["nodes"].items() if reached and x.get("hosted_on") == reached) \
        if any(s["technique"] in m.surface["reverse_door"]["techniques"] and s["removed"] is None for s in steps) and not host_links_on else []
    steps.sort(key=lambda s: (ROLE_ORDER.index(s["role"]), s["technique"]))
    acc = [s for s in steps if s["removed"] is None]
    roles = {s["role"] for s in acc}
    got_in = "entry" in roles or any(s.get("link_only") for s in acc)
    return {"credential": cred, "controls_on": sorted(on), "steps": steps, "accepted": len(acc),
            "reached": reached if reached else ("ground" if entered else None), "stopped_by": stop, "functions_reached": funcs,
            "complete": got_in and bool(roles & OUTCOME)}


def _targets(row: dict) -> list[str]:
    e = row.get("enables")
    return [e] if isinstance(e, str) else list(e or [])


def scenarios(m: Model, tid: str) -> dict:
    mp = m.mapping(tid)
    if mp is None:
        return {"threat": tid, "mapped": False}
    if mp.get("no_sparta_fit"):
        return {"threat": tid, "mapped": True, "no_sparta_fit": mp["no_sparta_fit"], "vectors": [], "architectures": {}, "comparison": []}
    kept = [r for r in mp["rows"] if r["code"] in KEEP]
    prep = [r for r in mp["rows"] if r["code"] == "P-PREP"]
    vecs = [v["vector"] for v in mp["vectors"]]
    out: dict = {"threat": tid, "mapped": True, "vectors": mp["vectors"], "architectures": {}}
    for aid, arch in m.surface["architectures"].items():
        per_vec = []
        for v in mp["vectors"]:
            origin = m.surface["origins"][v["vector"]]
            rows = [r for r in kept if v["vector"] in r.get("vectors", vecs)]
            chans = {origin["entry"][r["technique"]]["channel"] for r in rows if r["role"] == "entry" and r["technique"] in origin["entry"]}
            specific = chans - {"any"}
            # a path is relevant when a kept entry technique of this vector uses one of its links (or only 'any' entries are kept)
            lo_kinds = {k for r in rows if r["role"] != "entry" for k in m.surface["link_only"]["techniques"].get(r["technique"], [])}
            paths = [p for p in entry_paths(arch, origin)
                     if (not specific or specific & set(p["kinds"])) or (p.get("rogue") and set(p["kinds"][:1]) & lo_kinds)]
            creds = list(dict.fromkeys(origin["credentials"] + ([v["credential"]] if v.get("credential") else [])))
            scen = []
            for p in paths:
                for cred in creds:
                    path_ctl = {l["control"] for l in arch["links"] if l["id"] in p["links"] and l.get("control")} | ({"sdls"} if p.get("proximity") else set())
                    ctl = sorted(c for c in path_ctl if not _bypass(m, c, cred))
                    if ctl:
                        settings = [("off", set()), ("on", set(ctl))] + ([(f"only {c} off", set(ctl) - {c}) for c in ctl] if len(ctl) > 1 else [])
                    else:
                        settings = [("bypassed" if path_ctl else "none", set())]
                    done = {}
                    for name, on in settings:
                        # controls the credential bypasses are on (that is what bypassing means); they still matter for capture
                        sc = _evaluate(m, arch, origin, p, cred, on | (path_ctl - set(ctl)), rows, kept)
                        acc = {s["technique"] for s in sc["steps"] if s["removed"] is None}
                        key = (frozenset(acc), sc["reached"], sc["complete"])
                        if name.startswith("only") and key in (done.get("on"), done.get("off")):
                            continue                      # single-control variant changes nothing
                        sc.update(path=p, boundaries=boundaries(arch, p), setting=name, path_controls=sorted(path_ctl),
                                  bypassed=sorted(path_ctl - set(ctl)), prep=sorted({r["technique"] for r in prep if set(_targets(r)) & acc}))
                        if name == "on" and key == done.get("off"):
                            scen[-1]["setting"] = "no_effect"   # the controls change nothing for this attacker
                            scen[-1]["controls_on"] = sorted(on | (path_ctl - set(ctl)))
                            done["on"] = key
                            continue
                        done[name] = key
                        scen.append(sc)
            per_vec.append({"vector": v["vector"], "paths": paths, "scenarios": scen,
                            **({"note": "no entry path for this attacker origin in this architecture"} if not paths else {})})
        out["architectures"][aid] = per_vec
    out["comparison"] = compare(out)
    return out


# ------------------------------------------------------------------ comparison

def _arch_view(per_vec: dict) -> dict:
    sc = per_vec["scenarios"]
    return {"reached": sorted({s["reached"] for s in sc if s["reached"] and s["accepted"]}),
            "paths": sorted({tuple(s["path"]["kinds"]) for s in sc}),
            # only runs where no control stops the attacker; a blocked entry would differ merely because a control exists
            "chains": sorted({tuple(x["technique"] for x in s["steps"] if x["removed"] is None) for s in sc
                              if s["setting"] in ("off", "none", "bypassed", "no_effect")}),
            # every modelled control on the path is on (none on the path, on, bypassed or without effect)
            "complete_on": any(s["complete"] for s in sc if set(s["path_controls"]) <= set(s["controls_on"])),
            "boundaries": sorted({b.split(": ", 1)[1] for s in sc for b in s["boundaries"]}),
            "controls": sorted({c for s in sc for c in s["controls_on"]})}


def compare(res: dict, base: str = "G-CONV") -> list[dict]:
    """Neutral, symmetric differences of every other architecture against the base, per access vector."""
    archs = list(res["architectures"])
    diffs = []
    for i, v in enumerate(res["architectures"][base]):
        for other in (a for a in archs if a != base):
            va, vb = v, res["architectures"][other][i]
            d = {"vector": va["vector"], "against": other, "kinds": [], "detail": {}}
            if bool(va["paths"]) != bool(vb["paths"]):
                d["kinds"].append(f"entry_only_in_{other if vb['paths'] else base}")
            if va["paths"] and vb["paths"]:
                A, B = _arch_view(va), _arch_view(vb)
                same_otherwise = all(A[k] == B[k] for k in ("paths", "chains", "boundaries", "controls"))
                if same_otherwise and A["reached"] != B["reached"]:
                    # same paths and chain, only more (or fewer) satellites of the same kind: follows from the satellite count
                    d["kinds"].append("satellite_count_only")
                    d["detail"]["reached"] = {base: A["reached"], other: B["reached"]}
                else:
                    for k in ("reached", "paths", "chains", "boundaries", "controls"):
                        if A[k] != B[k]:
                            d["kinds"].append(f"{k}_differ")
                            d["detail"][k] = {base: A[k], other: B[k]}
                if A["complete_on"] != B["complete_on"]:
                    d["kinds"].append("residual_differs")
                    d["detail"]["complete_with_controls_on"] = {base: A["complete_on"], other: B["complete_on"]}
            diffs.append(d)
    return diffs


def not_covered(m: Model) -> dict:
    """Live SPARTA techniques that no threat keeps or uses as preparation: proposed but unused, and never proposed."""
    used, seen = set(), set()
    for tid in m.index:
        for r in (m.mapping(tid) or {}).get("rows", []):
            seen.add(r["technique"])
            if r["code"] in KEEP or r["code"] == "P-PREP":
                used.add(r["technique"])
    return {"proposed_unused": sorted(seen - used), "never_proposed": sorted(set(m.live) - seen)}
