"""Loads the authored data directory and validates it (schemas + cross-references + invariant I10).

Layout (plan v5 §18, trimmed to what exists):
  data/sources/                pinned external inputs + manifest.json
  data/threats/<ET>.json       ET with its projection (ETP)
  data/architectures/<G>.json  architecture variants
  data/scenarios/<ET>/*.json   scenario instances (SI)
  data/rules/vocabulary.json   closed vocabularies
  data/rules/techniques.json   technique profiles (rule table)
  data/rules/evidence/<ET>.json ET evidence clauses
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from functools import cached_property
from importlib import resources
from pathlib import Path

import jsonschema

from . import sources
from .sources import sha256_file

DEFAULT_DATA = Path(__file__).resolve().parents[2] / "data"


def _read(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def schema(name: str) -> dict:
    return json.loads(resources.files("phalanx").joinpath(f"schemas/{name}.schema.json").read_text(encoding="utf-8"))


@dataclass
class Workspace:
    root: Path = DEFAULT_DATA
    files: dict[str, Path] = field(default_factory=dict)   # logical name -> file, for provenance hashes

    def __post_init__(self):
        self.root = Path(self.root)

    # ---- authored inputs
    @cached_property
    def vocabulary(self) -> dict:
        return self._load("rules/vocabulary.json")

    @cached_property
    def techniques(self) -> dict:
        return self._load("rules/techniques.json")

    @cached_property
    def threats(self) -> dict[str, dict]:
        return {p.stem: self._load(p.relative_to(self.root)) for p in sorted((self.root / "threats").glob("*.json"))}

    @cached_property
    def architectures(self) -> dict[str, dict]:
        return {p.stem: self._load(p.relative_to(self.root)) for p in sorted((self.root / "architectures").glob("*.json"))}

    @cached_property
    def scenarios(self) -> dict[str, list[dict]]:
        out = {}
        for d in sorted(p for p in (self.root / "scenarios").iterdir() if p.is_dir()):
            out[d.name] = [self._load(p.relative_to(self.root)) for p in sorted(d.glob("*.json"))]
        return out

    def evidence(self, threat_id: str) -> dict | None:
        rel = Path(f"rules/evidence/{threat_id}.json")
        return self._load(rel) if (self.root / rel).exists() else None

    # ---- pinned external inputs
    @cached_property
    def manifest(self) -> sources.Manifest:
        return sources.Manifest.load(self.root / "sources")

    @cached_property
    def catalog(self) -> sources.Catalog:
        return sources.load_sparta(self.manifest.path("sparta"), self.manifest.entries["sparta"]["version"])

    @cached_property
    def crosswalk(self) -> sources.Crosswalk:
        return sources.load_crosswalk(self.manifest.path("enisa_controls"), self.manifest.path("safemode"))

    def v1_mapping(self, threat_id: str) -> list[str]:
        p = self.manifest.path("phalanx_v1")
        return sources.load_v1_mapping(p, threat_id) if p.exists() else []

    def _load(self, rel) -> dict:
        p = self.root / rel
        self.files[str(rel)] = p
        return _read(p)

    def input_hashes(self) -> dict[str, str]:
        """sha256 of every authored file read so far and every pinned source."""
        out = {f"data/{k}": sources.sha256_file(p) for k, p in sorted(self.files.items())}
        for e in self.manifest.entries.values():
            f = self.manifest.root / e["path"]
            out[f"data/sources/{e['path']}"] = sources.sha256_file(f) if f.exists() else ""
        return out

    # ---- validation
    def validate(self, check_sources: bool = True) -> list[str]:
        """Return every problem found; empty list = valid."""
        errs: list[str] = []

        def against(name, obj, where):
            n = len(errs)
            for e in jsonschema.Draft202012Validator(schema(name)).iter_errors(obj):
                path = "/".join(str(x) for x in e.absolute_path)
                errs.append(f"{where}: {path or '<root>'}: {e.message}")
            return len(errs) == n

        if check_sources:
            for k, (ok, actual) in self.manifest.verify().items():
                if not ok:
                    errs.append(f"sources/{k}: sha256 mismatch or missing file (got {actual or 'nothing'})")
        rules_ok = against("techniques", self.techniques, "rules/techniques.json")
        bad_threats = set()
        for tid, t in self.threats.items():
            if not against("threat", t, f"threats/{tid}.json"):
                bad_threats.add(tid)
            if t.get("id") != tid:
                errs.append(f"threats/{tid}.json: id {t.get('id')} does not match file name")
            ev = self.evidence(tid)
            if ev is not None:
                if not against("evidence", ev, f"rules/evidence/{tid}.json"):
                    bad_threats.add(tid)
        bad_archs = set()
        for gid, g in self.architectures.items():
            if against("architecture", g, f"architectures/{gid}.json"):
                errs += self._check_graph(gid, g)
            else:
                bad_archs.add(gid)
        for tid, sis in self.scenarios.items():
            if tid not in self.threats:
                errs.append(f"scenarios/{tid}: no threat file threats/{tid}.json")
            seen = set()
            for si in sis:
                where = f"scenarios/{tid}/{si.get('si_id')}"
                si_ok = against("scenario", si, where)
                if si.get("si_id") in seen:
                    errs.append(f"{where}: duplicate si_id")
                seen.add(si.get("si_id"))
                if si_ok and si.get("variant") not in bad_archs:
                    errs += self._check_scenario(tid, si, where, tid in bad_threats)
        if rules_ok:
            errs += self._check_identifiers(bad_threats)
        from . import registry, selectors
        if rules_ok and not bad_threats:      # the registry check reads rules and evidence without schema guards
            errs += [f"docs/rule_registry.json: {e}" for e in registry.check(registry.load(), self)]
        if (self.root / "selectors").exists():
            errs += [f"selectors: {e}" for e in selectors.validate_registry(selectors.load_registry(self))]
        return errs

    def _check_graph(self, gid, g) -> list[str]:
        errs, roles = [], set(self.vocabulary["boundary_roles"])
        for nid, n in g.get("nodes", {}).items():
            if set(n.get("functions", {})) != set(n.get("assets", [])):
                errs.append(f"architectures/{gid}: node {nid} functions keys differ from assets")
        for e in g.get("edges", []):
            for end in ("src", "dst"):
                if e.get(end) not in g.get("nodes", {}):
                    errs.append(f"architectures/{gid}: edge {e.get('id')} {end} {e.get(end)} is not a node")
            if e.get("role") not in roles:
                errs.append(f"architectures/{gid}: edge {e.get('id')} role {e.get('role')} not in vocabulary.boundary_roles")
            elif self.vocabulary["boundary_roles"][e["role"]]["transition"] != e.get("transition"):
                errs.append(f"architectures/{gid}: edge {e.get('id')} transition disagrees with role {e['role']}")
            assets = {a for n in (e.get("src"), e.get("dst")) for a in g["nodes"].get(n, {}).get("assets", [])}
            for a in e.get("endpoint_assets", []):
                if a not in assets:
                    errs.append(f"architectures/{gid}: edge {e.get('id')} endpoint asset {a} is on neither endpoint node")
            ends = [g.get("nodes", {}).get(e.get(x), {}).get("security_domain") for x in ("src", "dst")]
            if None not in ends and e.get("crosses_security_domain") != (ends[0] != ends[1]):
                errs.append(f"architectures/{gid}: edge {e.get('id')} crosses_security_domain disagrees with endpoint security domains")
        return errs

    def _check_scenario(self, tid, si, where, threat_bad=False) -> list[str]:
        errs = []
        g = self.architectures.get(si.get("variant"))
        if g is None:
            return [f"{where}: unknown variant {si.get('variant')}"]
        if si.get("threat") != tid:
            errs.append(f"{where}: threat {si.get('threat')} but stored under scenarios/{tid}")
        if si["attacker"]["origin_node"] not in g["nodes"]:
            errs.append(f"{where}: attacker origin {si['attacker']['origin_node']} not a node of {g['id']}")
        for asset, node in si["selected_asset_instances"].items():
            if asset not in g["nodes"].get(node, {}).get("assets", []):
                errs.append(f"{where}: selected asset {asset} is not on node {node} in {g['id']}")
        threat = None if threat_bad else self.threats.get(tid)
        if threat:
            extra = set(si["selected_asset_instances"]) - set(threat["projection"]["candidate_assets"])
            if extra:
                errs.append(f"{where}: selected assets {sorted(extra)} outside the threat projection")
            if si["realized_lifecycle"] not in threat["projection"]["candidate_lifecycle"]:
                errs.append(f"{where}: lifecycle {si['realized_lifecycle']} outside the threat projection")
        edges = {e["id"] for e in g["edges"]}
        for eid in si["protection_applied"]:
            if eid not in edges:
                errs.append(f"{where}: protection_applied names unknown edge {eid}")
        return errs

    def _check_identifiers(self, bad_threats=frozenset()) -> list[str]:
        """Invariant I10: authored rule tables may not name unknown or deprecated SPARTA techniques."""
        errs, cat = [], self.catalog.techniques
        tr = self.techniques

        def need(tid, where, allow_deprecated=False):
            if tid not in cat:
                errs.append(f"{where}: {tid} is not a SPARTA {self.catalog.version} technique")
            elif cat[tid]["deprecated"] and not allow_deprecated:
                errs.append(f"{where}: {tid} is deprecated in {self.catalog.version}")

        for tid in tr["overrides"]:
            need(tid, "rules/techniques.json overrides", allow_deprecated=True)
        for cls, ids in tr["attacker_seeds"].items():
            for tid in ids:
                need(tid, f"rules/techniques.json attacker_seeds.{cls}")
        for tid in tr["deprecation_successors"]:
            need(tid, "rules/techniques.json deprecation_successors")
        for tac in tr["tactic_defaults"]:
            if tac not in self.vocabulary["tactic_order"]:
                errs.append(f"rules/techniques.json: tactic {tac} not in vocabulary.tactic_order")
        auth, roles = self.vocabulary["authority_rules"], self.vocabulary["boundary_roles"]
        for where, p in [(f"tactic_defaults.{k}", v) for k, v in tr["tactic_defaults"].items()] + \
                        [(f"overrides.{k}", v) for k, v in tr["overrides"].items()]:
            if p.get("authority", "none") not in {*auth, "none"}:
                errs.append(f"rules/techniques.json {where}: authority {p['authority']} not in vocabulary.authority_rules")
            if p.get("traverses") not in {*roles, *self.vocabulary["traversal_only_roles"], None}:
                errs.append(f"rules/techniques.json {where}: traverses {p['traverses']} not in vocabulary.boundary_roles")
        for th in self.threats:
            if th in bad_threats:
                continue
            for r in self.threats[th]["projection"]["applicable_boundary_roles"]:
                if r not in roles:
                    errs.append(f"threats/{th}.json: applicable_boundary_roles {r} not in vocabulary.boundary_roles")
            ev = self.evidence(th)
            description = self.threats[th].get("description", "")
            for cid, c in (ev or {}).get("clauses", {}).items():
                if c["clause"] not in description:     # a clause is a citation: it must quote its threat verbatim
                    errs.append(f"rules/evidence/{th}.json {cid}: clause is not a verbatim part of threats/{th}.json description")
                for tid in c["techniques"]:
                    need(tid, f"rules/evidence/{th}.json {cid}")
            key = self.threats[th].get("crosswalk_key")
            if key is not None and key not in self.crosswalk.rows_by_threat:
                errs.append(f"threats/{th}.json: crosswalk_key '{key}' matches no threat row in the ENISA workbook")
            errs += self._check_source_row(th)
            errs += self._check_claims(th)
        return errs

    def _check_claims(self, th: str) -> list[str]:
        t, errs = self.threats[th], []
        for i, c in enumerate(t.get("claims", [])):
            where = f"threats/{th}.json claims[{i}] {c['sv']}"
            sv = self.catalog.sv.get(c["sv"])
            if sv is None:
                errs.append(f"{where}: not an SV-* statement in {self.catalog.version}")
            elif not sv["techniques"]:
                errs.append(f"{where}: SPARTA relates no technique to it")
            if c["basis"] == "enisa_quote" and c["quote"] not in t["description"]:
                errs.append(f"{where}: quote is not a verbatim part of the description")
            if c["basis"] == "analyst_asserted" and not c.get("author"):
                errs.append(f"{where}: analyst_asserted claim needs an author")
        return errs

    def _check_source_row(self, th: str) -> list[str]:
        """A threat transcribed from the legacy Annex C tuple must match its row there: the file hash recorded in
        `derivation_provenance`, and the name and description (whitespace-normalized). Clauses quote the
        description, so this ties every evidence quote to the source file."""
        t = self.threats[th]
        if "enisa_threats_tuple.csv" not in t.get("source", ""):
            return []
        path = self.root / "legacy_v1" / "enisa_threats_tuple.csv"
        where = f"threats/{th}.json"
        if not path.exists():
            return [f"{where}: source file {path} not found"]
        pinned = t["projection"]["derivation_provenance"].get("source_sha256")
        if pinned and sha256_file(path) != pinned:
            return [f"{where}: {path.name} sha256 differs from derivation_provenance.source_sha256"]
        with path.open(encoding="utf-8-sig", newline="") as f:
            row = next((r for r in csv.DictReader(f) if r["ID"] == th), None)
        if row is None:
            return [f"{where}: no row {th} in {path.name}"]
        norm = lambda s: re.sub(r"\s+", " ", s).strip()
        errs = []
        if norm(t["name"]) != norm(row["ENISA_Threat"]):
            errs.append(f"{where}: name differs from {path.name} row {th}")
        if norm(t["description"]) != norm(row["Threat Description (ENISA)"]):
            errs.append(f"{where}: description differs from {path.name} row {th}")
        return errs
