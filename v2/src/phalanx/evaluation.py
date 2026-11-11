"""EvaluationCell normalization (plan v5 §14.3).

Every method's raw output becomes cells `(method_id, si_id, technique_id) -> normalized_outcome` with
outcome in {accepted, rejected, unresolved, not_generated, not_applicable}:

  not_applicable  the method's applicability predicate A_m is false for this SI (excluded from its rates)
  not_generated   the method was applicable but did not propose the technique
  otherwise       the method's decision; B0 lists are normalized to `accepted`

Universe U. Plan v5 §14.3 fixes U per SI independently of any method's output: anchor assertions ∪
constructed negatives ∪ pre-written contrastive/metamorphic pairs. Pass it as `universe`. Without it the
cells use the development fallback "dev_union" (union of techniques the methods proposed), in which a
method's own output enlarges the denominator: such cells are diagnostic, never H1 results.
"""
from __future__ import annotations

import collections

OUTCOMES = ("accepted", "rejected", "unresolved", "not_generated", "not_applicable")

# A_m for development SIs. For anchor SIs, plan v5 §14.3 additionally requires a frozen ET linkage entry.
APPLICABILITY = {
    "B0": "the SI's ET is in the legacy 58-record corpus",
    "B1": "an EMB3D-side input (asserted TIDs per step) exists for the SI; only the OPS-SAT SI has one",
    "B1b": "the SI's ET has label text",
    "B2": "the SI names an ET",
    "B3": "the SI names an ET and an architecture variant",
}


def from_engine(bundle: dict) -> dict:
    """{si_id: {"applicable": bool, "decisions": {technique: status}}} from a B2/B3 bundle."""
    return {r["si"]["si_id"]: {"applicable": bool(r["si"].get("threat")) and
                               (bundle["method"] != "B3" or bool(r["si"].get("variant"))),
                               "decisions": {m["technique"]: m["status"] for m in r["mrs"]}}
            for r in bundle["results"]}


def from_b0(b0: dict) -> dict:
    """Candidate-list methods (B0, B1b): every listed technique is `accepted`."""
    return {r["si_id"]: {"applicable": b0["applicable"], "decisions": {t: "accepted" for t in r["techniques"]}}
            for r in b0["results"]}


def not_applicable(si_ids) -> dict:
    """A method whose applicability predicate is false on every SI (B1 without EMB3D-side input)."""
    return {si: {"applicable": False, "decisions": {}} for si in si_ids}


DEV_UNION = "dev_union"


def cells(outputs: dict[str, dict], universe: dict[str, list[str]] | None = None) -> list[dict]:
    """outputs: {method_id: {si_id: {"applicable", "decisions"}}} -> sorted EvaluationCell list.
    universe: frozen U as {si_id: [technique ids]}; None -> development union (DEV_UNION)."""
    sis = sorted(universe) if universe is not None else sorted({si for out in outputs.values() for si in out})
    rows = []
    for si in sis:
        if universe is not None:
            u = sorted(universe[si])
        else:
            u = sorted({t for out in outputs.values() for t in out.get(si, {}).get("decisions", {})})
        for method in sorted(outputs):
            o = outputs[method].get(si, {"applicable": False, "decisions": {}})
            for t in u:
                if not o["applicable"]:
                    outcome = "not_applicable"
                else:
                    outcome = o["decisions"].get(t, "not_generated")
                rows.append({"method_id": method, "si_id": si, "technique_id": t, "normalized_outcome": outcome})
    return rows


def counts(rows: list[dict]) -> dict:
    """{method: {si: {outcome: n}}}"""
    out: dict = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for r in rows:
        out[r["method_id"]][r["si_id"]][r["normalized_outcome"]] += 1
    return {m: {s: {k: c[k] for k in OUTCOMES} for s, c in d.items()} for m, d in out.items()}


def contrast(rows: list[dict], reference: str, other: str) -> dict:
    """Paired outcomes on cells where both methods are applicable: {si: {"ref->other": n}}; plus coverage."""
    by = {(r["method_id"], r["si_id"], r["technique_id"]): r["normalized_outcome"] for r in rows}
    out: dict = collections.defaultdict(collections.Counter)
    excluded = collections.Counter()
    for (m, si, t), ref in by.items():
        if m != reference:
            continue
        oth = by.get((other, si, t))
        if ref == "not_applicable" or oth in (None, "not_applicable"):
            excluded[si] += 1
            continue
        out[si][f"{ref}->{oth}"] += 1
    return {"pairs": {si: dict(sorted(c.items())) for si, c in sorted(out.items())},
            "excluded_not_jointly_applicable": dict(excluded)}
