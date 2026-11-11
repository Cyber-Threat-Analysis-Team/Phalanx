"""Rule registry (protocol v0.3 s1.2): namespaced rule ids, legacy->current crosswalk, and a consistency check.

The registry lives in docs/rule_registry.json (data/rules/ is frozen). `check` is the gate: it rejects
duplicate/ambiguous ids, unknown prefixes, a broken crosswalk, and any rule id or reason code that the
data or the engine uses but the registry does not declare.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from .workspace import Workspace

DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "docs" / "rule_registry.json"
PREFIXES = ("LEG-R", "ET-P", "SI-I", "BC-GEN", "MAP-CG", "MAP-CHK", "BX-CHK", "AFG-CHK", "CP-CHK")
RELATIONS = ("equivalent", "split", "merged", "dropped", "new")
STATUSES = ("active", "frozen_legacy", "unlocated")
_ID_RE = re.compile(r"^(?:LEG-R\d+|(?:%s)(?:-[A-Z0-9]+)+)$" % "|".join(p for p in PREFIXES if p != "LEG-R"))
# an id-shaped token inside data or source text
_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9-])(?:LEG-R\d+|(?:%s)(?:-[A-Z0-9]+)+)(?![A-Za-z0-9])"
                       % "|".join(p for p in PREFIXES if p != "LEG-R"))
_SRC = Path(__file__).resolve().parent


def load(path: str | Path = DEFAULT_REGISTRY) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def prefix_of(rule_id: str) -> str | None:
    for p in PREFIXES:
        if rule_id.startswith(p) if p == "LEG-R" else rule_id.startswith(p + "-"):
            return p
    return None


def _norm(s: str) -> str:
    """Case- and zero-padding-insensitive form: LEG-R1, leg-r01 and LEG-R001 collide; MAP-CG-1 and MAP-CG-01 collide."""
    s = s.upper()
    m = re.fullmatch(r"LEG-R0*(\d+)", s)
    if m:
        return f"LEG-R{int(m.group(1))}"
    return "-".join(str(int(x)) if x.isdigit() else x for x in s.split("-"))


def by_id(registry: dict) -> dict[str, dict]:
    return {r["id"]: r for r in registry["rules"]}


def rule_for_reason_code(registry: dict, code: str) -> str | None:
    """The MAP-CHK rule id that owns a reason code (the code names the check that failed or was unknown)."""
    ids = [r["id"] for r in registry["rules"] if r.get("reason_code") == code]
    return ids[0] if len(ids) == 1 else None


def tokens_in(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text))


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(k)
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def _data_tokens(ws: Workspace) -> dict[str, set[str]]:
    """token -> places it is used, over every authored data file (pinned external sources excluded)."""
    found: dict[str, set[str]] = defaultdict(set)
    for p in sorted(ws.root.rglob("*.json")):
        rel = p.relative_to(ws.root)
        if rel.parts[0] == "sources":
            continue
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            continue
        for s in _walk_strings(obj):
            for t in tokens_in(s):
                found[t].add(f"data/{rel}")
    return found


def _source_tokens() -> dict[str, set[str]]:
    """token -> engine/report/other source modules naming it (this module is excluded: it only gives examples)."""
    found: dict[str, set[str]] = defaultdict(set)
    for p in sorted(_SRC.glob("*.py")):
        if p.name == Path(__file__).name:
            continue
        for t in tokens_in(p.read_text(encoding="utf-8")):
            found[t].add(f"src/phalanx/{p.name}")
    return found


def check(registry: dict, ws: Workspace) -> list[str]:
    """Return every problem found; empty list = the registry is consistent with the data and the engine."""
    errs: list[str] = []
    rules = registry.get("rules")
    if not isinstance(rules, list) or not rules:
        return ["registry: no rules"]
    if tuple(registry.get("prefixes", {})) != PREFIXES:
        errs.append(f"registry: prefixes {list(registry.get('prefixes', {}))} differ from the protocol set {list(PREFIXES)}")

    # ---- identifiers
    ids = [r.get("id") for r in rules]
    for i, n in Counter(ids).items():
        if n > 1:
            errs.append(f"duplicate id {i} ({n}x)")
    seen_norm: dict[str, str] = {}
    for r in rules:
        rid = r.get("id")
        if not isinstance(rid, str):
            errs.append(f"rule without a string id: {r}")
            continue
        pre = prefix_of(rid)
        if pre is None:
            errs.append(f"{rid}: unknown prefix (allowed {', '.join(PREFIXES)})")
        elif not _ID_RE.match(rid):
            errs.append(f"{rid}: malformed id")
        if r.get("prefix") != pre:
            errs.append(f"{rid}: prefix field {r.get('prefix')!r} does not match the id prefix {pre!r}")
        n = _norm(rid)
        if n in seen_norm and seen_norm[n] != rid:
            errs.append(f"ambiguous ids {seen_norm[n]} and {rid} (same after case/zero-padding normalisation)")
        seen_norm.setdefault(n, rid)
        for k in ("title", "description", "version"):
            if not r.get(k):
                errs.append(f"{rid}: missing {k}")
        if r.get("status") not in STATUSES:
            errs.append(f"{rid}: status {r.get('status')!r} not in {list(STATUSES)}")
        if (pre == "LEG-R") != (r.get("status") in ("frozen_legacy", "unlocated")):
            errs.append(f"{rid}: legacy status and LEG-R prefix disagree")
        src = r.get("source") or {}
        if not src.get("file") or not src.get("locator"):
            errs.append(f"{rid}: source needs file and locator")
    id_set = {i for i in ids if isinstance(i, str)}
    alias_owner: dict[str, str] = {}
    for r in rules:
        for a in r.get("aliases", []):
            na = _norm(a)
            if a in id_set or na in seen_norm:
                errs.append(f"{r.get('id')}: alias {a} collides with a rule id")
            elif na in alias_owner and alias_owner[na] != r.get("id"):
                errs.append(f"ambiguous alias {a}: claimed by {alias_owner[na]} and {r.get('id')}")
            alias_owner.setdefault(na, r.get("id"))
    reg = {r["id"]: r for r in rules if isinstance(r.get("id"), str)}

    # ---- crosswalk
    legacy_rows: dict[str, int] = Counter()
    current_used: set[str] = set()
    for k, row in enumerate(registry.get("crosswalk", [])):
        where = f"crosswalk[{k}]"
        rel, leg, cur = row.get("relation"), row.get("legacy", []), row.get("current", [])
        if rel not in RELATIONS:
            errs.append(f"{where}: relation {rel!r} not in {list(RELATIONS)}")
        if not row.get("delta"):
            errs.append(f"{where}: missing semantic-delta note")
        shape = {"equivalent": (1, 1, 1, 1), "split": (1, 1, 2, None), "merged": (2, None, 1, None),
                 "dropped": (1, None, 0, 0), "new": (0, 0, 1, None)}.get(rel)
        if shape:
            lo_l, hi_l, lo_c, hi_c = shape
            if len(leg) < lo_l or (hi_l is not None and len(leg) > hi_l) or len(cur) < lo_c or (hi_c is not None and len(cur) > hi_c):
                errs.append(f"{where}: relation {rel} does not fit {len(leg)} legacy -> {len(cur)} current ids")
        for i in leg:
            legacy_rows[i] += 1
            if i not in reg:
                errs.append(f"{where}: legacy id {i} is not registered")
            elif prefix_of(i) != "LEG-R":
                errs.append(f"{where}: {i} is not a LEG-R id")
        for i in list(cur) + list(row.get("see_also", [])):
            if i not in reg:
                errs.append(f"{where}: current id {i} is not registered")
            elif prefix_of(i) == "LEG-R":
                errs.append(f"{where}: {i} is a legacy id on the current side")
        current_used.update(cur)
    for r in rules:
        rid = r.get("id")
        if r.get("status") == "frozen_legacy" and legacy_rows[rid] != 1:
            errs.append(f"{rid}: active legacy rule appears in {legacy_rows[rid]} crosswalk rows (needs exactly 1)")
        if r.get("status") == "active" and rid not in current_used:
            errs.append(f"{rid}: active rule absent from the crosswalk (use a 'new' row)")

    # ---- reason codes <-> MAP-CHK rules
    vocab_codes = list(ws.vocabulary["reason_codes"])
    owners: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        if "reason_code" in r:
            if prefix_of(r["id"]) != "MAP-CHK":
                errs.append(f"{r['id']}: only MAP-CHK rules own reason codes")
            owners[r["reason_code"]].append(r["id"])
    for c in vocab_codes:
        if not owners.get(c):
            errs.append(f"reason code {c} (vocabulary.json) has no registered MAP-CHK rule")
    for c, who in owners.items():
        if len(who) > 1:
            errs.append(f"reason code {c} is claimed by several rules: {who}")
        if c not in vocab_codes:
            errs.append(f"{who[0]}: reason code {c} is not in vocabulary.json")

    # ---- candidate generators
    for gid, g in ws.vocabulary["candidate_generators"].items():
        r = reg.get(gid)
        if r is None:
            errs.append(f"generator {gid} (vocabulary.json) is not registered")
        elif r.get("generator_kind") != g["kind"]:
            errs.append(f"{gid}: registered kind {r.get('generator_kind')!r} differs from vocabulary kind {g['kind']!r}")
    for r in rules:
        if prefix_of(r.get("id", "")) == "MAP-CG" and r["id"] not in ws.vocabulary["candidate_generators"]:
            errs.append(f"{r['id']}: registered generator is absent from vocabulary.candidate_generators")

    # ---- data rows (authority rules, evidence clauses)
    declared: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in rules:
        d = r.get("data_rows")
        if d:
            declared[(d.get("file"), d.get("path"))].update(d.get("ids", []))
    actual: dict[tuple[str, str], set[str]] = {
        ("data/rules/vocabulary.json", "authority_rules"): set(ws.vocabulary["authority_rules"])}
    for tid in sorted(ws.threats):
        ev = ws.evidence(tid)
        if ev is not None:
            actual[(f"data/rules/evidence/{tid}.json", "clauses")] = set(ev["clauses"])
    for key, have in actual.items():
        for i in sorted(have - declared.get(key, set())):
            errs.append(f"{key[0]} {key[1]}.{i} is not registered under any rule's data_rows")
    for key, want in declared.items():
        if key not in actual:
            errs.append(f"data_rows names {key[0]} {key[1]}, which the workspace does not have")
        else:
            for i in sorted(want - actual[key]):
                errs.append(f"data_rows {key[0]} {key[1]}.{i} does not exist in the data")

    # ---- ids used by data and engine must be registered
    for where, found in (("data", _data_tokens(ws)), ("source", _source_tokens())):
        for t, places in sorted(found.items()):
            if t not in reg:
                errs.append(f"{t} is used in {where} ({', '.join(sorted(places))}) but not registered")
    return errs
