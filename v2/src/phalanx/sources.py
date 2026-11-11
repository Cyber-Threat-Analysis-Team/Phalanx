"""Pinned external inputs: manifest verification, the SPARTA v4.0.1 catalog, and the public
ENISA -> SPARTA crosswalk (T1 / MAP-CG-01).

T1 runs: ENISA threat -> ENISA STL control-framework workbook ("Threat based" sheet) -> ENISA control ids
-> SafeMode Space `enisa_control` edges -> SPARTA techniques. The workbook join reproduces
research/runs/scie-related-work-bef4c6/temp/enisa-stl-transitive-audit.py.
"""
from __future__ import annotations

import collections
import gzip
import hashlib
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass(frozen=True)
class Manifest:
    root: Path
    entries: dict

    @classmethod
    def load(cls, sources_dir: Path) -> "Manifest":
        data = json.loads((sources_dir / "manifest.json").read_text(encoding="utf-8"))
        return cls(sources_dir, data["sources"])

    def path(self, key: str) -> Path:
        return self.root / self.entries[key]["path"]

    def verify(self) -> dict[str, tuple[bool, str]]:
        """{source: (ok, actual_sha256)}; a missing file reports ok=False with an empty hash."""
        out = {}
        for key, e in self.entries.items():
            p = self.root / e["path"]
            actual = sha256_file(p) if p.exists() else ""
            out[key] = (actual == e["sha256"], actual)
        return out


# ---------------------------------------------------------------- SPARTA

@dataclass
class Catalog:
    """SPARTA techniques keyed by external id plus related-to countermeasures, and SPARTA's own space-vehicle
    threat statements (`SV-*`) with the techniques SPARTA relates to each (`related-to`, untyped)."""
    version: str
    techniques: dict[str, dict]
    countermeasures: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    sv: dict[str, dict] = field(default_factory=dict)

    def tactic(self, tid: str) -> str:
        return self.techniques[tid]["tactic"]

    def is_deprecated(self, tid: str) -> bool:
        return self.techniques[tid]["deprecated"]


def load_sparta(path: Path, version: str = "SPARTA v4.0.1") -> Catalog:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    tech, coa, svo = {}, {}, {}
    for o in bundle["objects"]:
        if o["type"] == "attack-pattern":
            tid = o["external_references"][0]["external_id"]
            (svo if tid.startswith("SV-") else tech)[tid] = o
        elif o["type"] == "course-of-action":
            coa[o["id"]] = o
    by_stix = {o["id"]: tid for tid, o in tech.items()}
    cms: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    for o in bundle["objects"]:
        if o["type"] == "relationship" and o["relationship_type"] == "related-to" \
                and o["source_ref"] in coa and o["target_ref"] in by_stix:
            c = coa[o["source_ref"]]
            cid = c["external_references"][0].get("external_id", c["name"])
            if re.match(r"CM\d{4}$", cid):
                cms[by_stix[o["target_ref"]]].append((cid, c["name"]))
    techniques = {
        tid: {"name": o["name"], "tactic": o["kill_chain_phases"][0]["phase_name"],
              "description": o.get("description", ""), "deprecated": o["name"].startswith("[DEPRECATED]"),
              # SPARTA's own EMB3D crosswalk (B1 input), kept literally: two refs are concatenated IDs
              "emb3d": sorted({re.search(r"TID-(\d+)", r["url"]).group(0) for r in o["external_references"]
                               if r.get("source_name") == "mitre_emb3d"})}
        for tid, o in tech.items()}
    sv_by_stix = {o["id"]: sid for sid, o in svo.items()}
    sv_links: dict[str, set[str]] = collections.defaultdict(set)
    for o in bundle["objects"]:
        if o["type"] == "relationship" and o["relationship_type"] == "related-to":
            for a, b in ((o["source_ref"], o["target_ref"]), (o["target_ref"], o["source_ref"])):
                if a in sv_by_stix and b in by_stix:
                    sv_links[sv_by_stix[a]].add(by_stix[b])
    sv = {sid: {"description": " ".join(o["description"]) if isinstance(o.get("description"), list) else o.get("description", ""),
                "tier": o.get("x_aerospace_threat_tier"), "did_layer": o.get("x_aerospace_did_layer"),
                "requirement": o.get("x_aerospace_high_level_requirements"),
                "techniques": sorted(sv_links.get(sid, ()))}
          for sid, o in svo.items()}
    for sid, d in sv.items():                     # defence-in-depth layers of the SVs that relate each technique
        for t in d["techniques"]:
            techniques[t].setdefault("sv_layers", set()).add(d["did_layer"])
    for t in techniques.values():
        t["sv_layers"] = sorted(t.get("sv_layers", ()))
    return Catalog(version, techniques, {k: sorted(set(v)) for k, v in cms.items()}, sv)


# ---------------------------------------------------------------- ENISA workbook + SafeMode (T1)

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
       "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}


def _col(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group():
        n = n * 26 + ord(ch) - 64
    return n - 1


def read_xlsx(path: Path) -> dict[str, list[list]]:
    """Minimal stdlib xlsx reader: {sheet name: rows as positional lists}."""
    z = zipfile.ZipFile(path)
    shared = ["".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t"))
              for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", _NS)]
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))}
    sheets = {}
    for s in wb.find("m:sheets", _NS):
        root = ET.fromstring(z.read("xl/" + rels[s.get(f"{{{_NS['r']}}}id")]))
        rows = []
        for row in root.iter(f"{{{_NS['m']}}}row"):
            d = {}
            for c in row.findall("m:c", _NS):
                v, t = c.find("m:v", _NS), c.get("t")
                if t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(f"{{{_NS['m']}}}t"))
                elif v is None:
                    continue
                elif t == "s":
                    val = shared[int(v.text)]
                else:
                    val = v.text
                d[_col(c.get("r"))] = val
            if d:
                rows.append([d.get(i) for i in range(max(d) + 1)])
        sheets[s.get("name")] = rows
    return sheets


def _norm(s) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


@dataclass
class Crosswalk:
    """Public ENISA threat -> ENISA control -> SPARTA technique crosswalk (T1)."""
    controls: dict[str, dict]                      # control id -> {title, segment, cluster}
    controls_by_threat: dict[str, set[str]]        # workbook threat name -> control ids
    rows_by_threat: dict[str, int]
    techniques_by_control: dict[str, set[str]]
    unjoined_rows: list

    def for_threat(self, name: str) -> dict:
        ctl = sorted(self.controls_by_threat.get(name, set()))
        techs = set().union(*[self.techniques_by_control.get(c, set()) for c in ctl]) if ctl else set()
        return {"workbook_rows": self.rows_by_threat.get(name, 0), "controls": ctl, "techniques": sorted(techs)}


def load_crosswalk(xlsx: Path, safemode_gz: Path) -> Crosswalk:
    sheets = read_xlsx(xlsx)
    control_rows = sheets["Control Framework_Control based"][1:]
    clusters, by_cluster = [], collections.defaultdict(list)
    for r in control_rows:
        if r[2] not in clusters:
            clusters.append(r[2])
        by_cluster[r[2]].append(r)
    controls = {}
    for i, cl in enumerate(clusters):
        for j, r in enumerate(by_cluster[cl]):
            controls[f"ENISA-STL-2025-03-sD.{18 + i}-i{j + 1:02d}"] = {
                "title": (r[3] or "").strip(), "segment": r[8], "cluster": r[2]}
    by_title = collections.defaultdict(list)
    for cid, c in controls.items():
        by_title[(_norm(c["cluster"])[:8], _norm(c["title"]))].append(cid)
    by_threat, rows_by_threat, unjoined = collections.defaultdict(set), collections.Counter(), []
    for r in sheets["Control Framework_Threat based"][1:]:
        rows_by_threat[r[2]] += 1
        key = (_norm(r[6])[:8], _norm(r[3]))
        if key in by_title:
            by_threat[r[2]].update(by_title[key])
            continue
        cand = [cid for cid, c in controls.items() if _norm(c["title"]) == _norm(r[3])]
        if len(cand) == 1:      # blank Control-cluster cell: fall back to a unique title match
            by_threat[r[2]].update(cand)
        else:
            unjoined.append((r[2], r[6], r[3]))
    sm = json.load(gzip.open(safemode_gz))
    tech_by_ctl = collections.defaultdict(set)
    for e in sm["edges"]:
        if e["target_family"] == "enisa_control":
            tech_by_ctl[e["target_id"]].add(e["technique_id"])
    return Crosswalk(controls, dict(by_threat), dict(rows_by_threat), dict(tech_by_ctl), unjoined)


def load_v1_mapping(path: Path, threat_id: str) -> list[str]:
    """Techniques the PHALANX v1 prototype mapped to a threat (MAP-CG-03, regression only)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [s["id"] for s in data.get(threat_id, {}).get("ttp", [])]
