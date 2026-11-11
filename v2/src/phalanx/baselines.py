"""Comparison methods other than the engine itself (plan v5 §14.3; protocol v0.3 §6.1).

B0 — legacy template projection = the PHALANX v1 prototype as shipped: the v1 Python
engine (`data/legacy_v1/ntn_threat_algorithm.py`, Pass 1 + Pass 2 over `data/legacy_v1/enisa_threats_tuple.csv`)
plus the hand-written SPARTA mapping in `data/legacy_v1/mappings.json`, which is how the v1 app obtains its
techniques. The Python engine itself emits no techniques (TTP is PENDING). Every listed technique is
normalized to `accepted`; B0 ignores the scenario, so every SI of a threat gets the same list.

B1 — published catalog crosswalk, descriptive benchmark: SPARTA v4.0.1's own EMB3D references used as a
candidate generator. Input: the EMB3D TIDs asserted per attack step for an SI; output: every SPARTA technique
whose EMB3D references contain one of the step's TIDs, all `accepted`. Applicable only where an EMB3D-side input
exists (the OPS-SAT SI). Anchor counting rule: a candidate counts when its ID equals, or is parent or child of,
an anchor-asserted ID for the same step. This is the precision of a property-unconditioned crosswalk used as a
generator, never a maintainer error.

B1b — keyword crosswalk, sensitivity analysis: a non-deprecated technique is emitted when every content word
of the ET label occurs as a whole word in the technique's name or description (case-insensitive; a trailing
plural "s" ignored; stopwords dropped). Applicable when the SI's ET has label text. Same for every SI of a threat.

B2 (scenario-only) and B3 (full) run in the engine: `pipeline.run(..., method="B2"|"B3")`.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from .sources import Catalog, sha256_file
from .workspace import DEFAULT_DATA

FRAMEWORK = DEFAULT_DATA / "legacy_v1"


def _load_v1(framework: Path):
    spec = importlib.util.spec_from_file_location("ntn_threat_algorithm_v1", framework / "ntn_threat_algorithm.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_b0(threat_id: str, scenarios: list[dict], framework: Path = FRAMEWORK, pinned_sha256: str | None = None) -> dict:
    v1 = _load_v1(framework)
    corpus = {r["id"]: r for r in v1.run(v1.load_rows(str(framework / "enisa_threats_tuple.csv")))}
    mapping_path = framework / "mappings.json"
    mapping_sha = sha256_file(mapping_path)
    if pinned_sha256 and mapping_sha != pinned_sha256:
        raise ValueError(f"{mapping_path} differs from the pinned v1 mapping (sha256 {mapping_sha[:12]}…)")
    entry = json.loads(mapping_path.read_text(encoding="utf-8")).get(threat_id, {})
    techniques = [s["id"] for s in entry.get("ttp", [])] if isinstance(entry, dict) else []
    record = corpus.get(threat_id)
    return {
        "method": "B0",
        "threat": threat_id,
        "applicable": record is not None,          # A_B0: the ET is in the legacy 58-record corpus
        "v1_record": None if record is None else {
            "nature": record["nature"], "rules": record["rules"], "ttp_status": record["ttp_status"],
            "segments": record["dS"], "trust_boundaries": record["dTB"], "lifecycle": record["dL"]},
        "inputs": {"legacy_v1/ntn_threat_algorithm.py": sha256_file(framework / "ntn_threat_algorithm.py"),
                   "legacy_v1/enisa_threats_tuple.csv": sha256_file(framework / "enisa_threats_tuple.csv"),
                   "legacy_v1/mappings.json": mapping_sha},
        "results": [{"si_id": si["si_id"], "techniques": techniques if record else []} for si in scenarios],
    }


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def _related(a: str, b: str) -> str | None:
    if a == b:
        return "exact"
    if _parent(a) == b or _parent(b) == a:
        return "parent_child"
    return None


def run_b1(emb3d_input: dict, catalog: Catalog) -> dict:
    """B1 on one SI whose EMB3D-side input is `emb3d_input` (see data/anchors/opssat_emb3d.json)."""
    by_tid: dict[str, set[str]] = {}
    for tid, t in catalog.techniques.items():
        for e in t["emb3d"]:
            by_tid.setdefault(e, set()).add(tid)
    steps, emitted, counted = [], 0, 0
    coverage = {"exact": 0, "parent_child": 0, "missed": 0}
    for s in emb3d_input["steps"]:
        cands = sorted(set().union(*(by_tid.get(t["tid"], set()) for t in s["emb3d_tids"])))
        asserted = s["sparta_asserted"]
        hits = [c for c in cands if any(_related(c, a) for a in asserted)]
        cov = {}
        for a in asserted:
            rel = {_related(c, a) for c in cands} - {None}
            cov[a] = "exact" if "exact" in rel else "parent_child" if rel else "missed"
            coverage[cov[a]] += 1
        emitted += len(cands)
        counted += len(hits)
        steps.append({"step": s["step"], "tids": [t["tid"] for t in s["emb3d_tids"]], "candidates": cands,
                      "counted": hits, "asserted_coverage": cov,
                      "deprecated_candidates": [c for c in cands if catalog.is_deprecated(c)]})
    asserted_n = sum(len(s["sparta_asserted"]) for s in emb3d_input["steps"])
    return {"method": "B1", "catalog": catalog.version, "steps": steps,
            "emitted": emitted, "counted": counted,
            "precision": round(counted / emitted, 4) if emitted else None,
            "asserted": asserted_n, "covered": coverage["exact"] + coverage["parent_child"], "coverage": coverage}


_STOP = {"a", "an", "and", "as", "at", "by", "for", "from", "in", "of", "on", "or", "the", "to", "via", "with"}


def _tokens(text: str) -> set[str]:
    return {w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w
            for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in _STOP}


def run_b1b(threat: dict, scenarios: list[dict], catalog: Catalog) -> dict:
    label = threat.get("name") or ""
    words = _tokens(label)
    techniques = sorted(tid for tid, t in catalog.techniques.items() if words and not t["deprecated"]
                        and words <= _tokens(f"{t['name']} {t['description']}"))
    return {"method": "B1b", "threat": threat["id"], "label": label, "keywords": sorted(words),
            "applicable": bool(words),
            "results": [{"si_id": si["si_id"], "techniques": techniques if words else []} for si in scenarios]}
