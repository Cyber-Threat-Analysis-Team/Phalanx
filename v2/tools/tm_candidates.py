"""Write the SPARTA candidate list for every adversarial ENISA threat (showcase; adversary role per data/tm/adversary.json).

Sources, each recorded per candidate:
  crosswalk  ENISA control workbook -> SafeMode -> SPARTA (pinned)
  sv:<ID>    SPARTA's related-to links from the SV-* statements the threat claims
  impact     SPARTA's live Impact techniques (all older IMP-* are deprecated)
  origin     every entry, door and crosslink technique of the attack-surface model (data/tm/attack_surface.json), so the
             architecture-sensitive techniques are judged for every threat, not only where the crosswalk proposed them

Also writes data/tm/sparta_live.json: every live technique with tactic, name and full description, for quoting.

Usage: .venv/bin/python tools/tm_candidates.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from phalanx import engine, pipeline
from phalanx.tm import Model
from phalanx.workspace import Workspace

IMPACT = [f"IMP-{i:04d}" for i in range(7, 15)]
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "tm"


def text(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def main() -> None:
    ws = Workspace()
    c = ws.catalog
    live = {t: {"tactic": c.tactic(t), "name": c.techniques[t]["name"], "description": text(c.techniques[t]["description"])}
            for t in sorted(c.techniques) if not c.is_deprecated(t)}
    (OUT / "sparta_live.json").write_text(json.dumps(live, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT / "candidates").mkdir(parents=True, exist_ok=True)
    model = Model.load()
    sf = model.surface
    origin_probe = sorted({t for o in sf["origins"].values() for t in o["entry"]} | set(sf["door"]["techniques"])
                          | set(sf["reverse_door"]["techniques"]) | set(sf["lateral_crosslink"]["techniques"]))
    for old in (OUT / "candidates").glob("TR*.json"):
        if model.role(old.stem)["role"] != "adversarial":
            old.unlink()
    summary = {}
    for tid, t in sorted(ws.threats.items()):
        if model.role(tid)["role"] != "adversarial":
            continue
        src: dict[str, list[str]] = {}
        for x in pipeline.crosswalk_for(ws, t)["techniques"]:
            if x in live:
                src.setdefault(x, []).append("crosswalk")
        for x, (sv, _quote) in engine.claim_links(t, c, []).items():
            src.setdefault(x, []).append(f"sv:{sv}")
        for x in IMPACT:
            src.setdefault(x, []).append("impact")
        for x in origin_probe:
            src.setdefault(x, []).append("origin")
        doc = {"threat": tid, "name": t["name"], "category": t["category"], "cia": t["cia"],
               "affected_assets": t["affected_asset_selectors"], "description": t["description"],
               "claims": [{"sv": k["sv"], "quote": k["quote"]} for k in t.get("claims", [])],
               "candidates": [{"technique": x, "tactic": live[x]["tactic"], "name": live[x]["name"], "sources": s}
                              for x, s in sorted(src.items())]}
        (OUT / "candidates" / f"{tid}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        summary[tid] = len(src)
    print(json.dumps(summary))
    print("threats", len(summary), "candidates", sum(summary.values()), "live techniques", len(live))


if __name__ == "__main__":
    main()
