"""Anchor re-resolution against the pinned SPARTA catalog (protocol v0.3 §1.5; plan v5 §17 Phase 1).

Every published anchor ID is checked as printed. Problems are flagged, never silently mapped:

  malformed     printed ID does not match the SPARTA ID pattern (e.g. `IA-0009.0`)
  not_found     well-formed but absent from the catalog (e.g. `EX-0007.02`)
  deprecated    present but marked [DEPRECATED] (all IMP-0001…0006 in v4.0.1)
  label_mismatch present, but the printed label names a different technique (drift / granularity slip)
  label_widened  present; the catalog name keeps every printed word and adds scope (e.g. RF -> RF/Optical)
  label_cosmetic present; same words after removing parenthesised abbreviations of the preceding words
                 (e.g. "(CCD)", "(PNT)") and ignoring word order and "and" ("Backdoor: Software" = "Software Backdoor")
  ok             present; label equal, or no label printed

`usable_as_is` = ok, label_cosmetic or label_widened. Assertions tagged `possible_not_executed` are resolved
and listed but are not positive anchor assertions: per-anchor counts cover the rest only. For flagged rows, `suggestions` lists catalog IDs whose name matches the
printed label; they are hints for adjudication and are never applied.
"""
from __future__ import annotations

import collections
import json
import re
from pathlib import Path

from .sources import Catalog

ID_RE = re.compile(r"^[A-Z]{2,3}-\d{4}(\.\d{2})?$")
USABLE = {"ok", "label_cosmetic", "label_widened"}
_STOP = {"and", "or", "of", "the"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower().replace("‑", "-")).strip()


def _label_forms(tid: str, catalog: Catalog) -> set[str]:
    """Ways a label for `tid` may be printed: own name, and 'Parent: Child' for sub-techniques."""
    name = catalog.techniques[tid]["name"]
    forms = {_norm(name)}
    if "." in tid and tid.split(".")[0] in catalog.techniques:
        forms.add(_norm(f"{catalog.techniques[tid.split('.')[0]]['name']}: {name}"))
    return forms


def _strip_abbrev(label: str) -> str:
    """Drop a parenthesis whose letters are the initials of the words right before it: 'Timing (PNT)'."""
    out = label
    for m in re.finditer(r"\(([A-Za-z]{2,6})\)", label):
        before = [w for w in re.findall(r"[A-Za-z]+", label[:m.start()]) if w.lower() not in _STOP]
        ab = m.group(1).upper()
        if "".join(w[0].upper() for w in before[-len(ab):]) == ab:
            out = out.replace(m.group(0), " ")
    return out


def _words(label: str) -> set[str]:
    return set(_norm(_strip_abbrev(label)).split()) - _STOP


def _label_status(printed: str, tid: str, catalog: Catalog) -> str:
    p = _norm(printed)
    forms = _label_forms(tid, catalog)
    tail = printed.split(":")[-1]
    if p in forms or _norm(tail) in forms:
        return "ok"
    own = catalog.techniques[tid]["name"]
    pw, tw, ow = _words(printed), _words(tail), _words(own)
    if pw == ow or tw == ow:
        return "label_cosmetic"
    if pw < ow or tw < ow:
        return "label_widened"
    return "label_mismatch"


def _suggest(printed: str | None, catalog: Catalog) -> list[str]:
    if not printed:
        return []
    p, tail = _norm(printed), _norm(printed.split(":")[-1])
    hits = [tid for tid in catalog.techniques if not catalog.is_deprecated(tid)
            and (p in _label_forms(tid, catalog) or _norm(catalog.techniques[tid]["name"]) == p)]
    if not hits:   # sub-technique printed as 'Parent: Child' under a wrong parent: match the child name
        hits = [tid for tid in catalog.techniques if not catalog.is_deprecated(tid) and "." in tid
                and _norm(catalog.techniques[tid]["name"]) == tail]
    return sorted(hits)


def resolve(anchors: dict, catalog: Catalog) -> dict:
    rows = []
    for a in anchors["anchors"]:
        for s in a["assertions"]:
            pid, label = s["printed_id"], s.get("printed_label")
            if not ID_RE.match(pid):
                status = "malformed"
            elif pid not in catalog.techniques:
                status = "not_found"
            elif catalog.is_deprecated(pid):
                status = "deprecated"
            elif label is None:
                status = "ok"
            else:
                status = _label_status(label, pid, catalog)
            rows.append({"anchor": a["id"], "gate_role": a["gate_role"], "source_kind": a.get("source_kind"),
                         "id_from": a.get("id_from"), "execution": s.get("execution", "asserted"), "step": s["step"],
                         "raw_token": s.get("raw_token", pid), "printed_id": pid,
                         "printed_label": label,
                         "catalog_name": catalog.techniques[pid]["name"] if pid in catalog.techniques else None,
                         "status": status, "usable_as_is": status in USABLE,
                         "suggestions": [] if status == "ok" else [t for t in _suggest(label, catalog) if t != pid],
                         "locator": s["locator"]})
    per = collections.OrderedDict()
    for r in rows:
        c = per.setdefault(r["anchor"], {"gate_role": r["gate_role"], "source_kind": r["source_kind"], "assertions": 0,
                                         "usable_as_is": 0, "not_executed_listed": 0, "by_status": collections.Counter()})
        if r["execution"] == "possible_not_executed":
            c["not_executed_listed"] += 1
            continue
        c["assertions"] += 1
        c["usable_as_is"] += r["usable_as_is"]
        c["by_status"][r["status"]] += 1
    for c in per.values():
        c["by_status"] = dict(sorted(c["by_status"].items()))
    descriptive = [a["id"] for a in anchors["anchors"] if not a["assertions"]]
    return {"catalog": catalog.version, "rows": rows, "per_anchor": dict(per),
            "descriptive_not_resolved": descriptive}


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
