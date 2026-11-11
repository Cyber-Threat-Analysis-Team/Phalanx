"""phalanx command-line interface.

  phalanx sources [--verify]            pinned external inputs and their hashes
  phalanx validate                      schemas, cross-references, identifier check (I10)
  phalanx list                          threats, architectures, scenarios
  phalanx run THREAT [-s SI ...] [-o DIR] [--json] [--method B3|B2]
  phalanx compare THREAT [-s SI ...] [-o DIR]   B3 vs B2 vs B0 as EvaluationCells
  phalanx explain BUNDLE SCENARIO TECHNIQUE
  phalanx outcomes BUNDLE               compact decision summary (for diffs / regression fixtures)
  phalanx metrics THREAT [-s SI] [-o DIR] [--runs N]   evaluation measures for B3/B2/B0/B1b
  phalanx linkage                       anchor -> ENISA ET linkage table (approved)
  phalanx b1 [-o DIR]                   baseline B1 (SPARTA's EMB3D crosswalk) on the OPS-SAT SI
  phalanx anchors [-o DIR]              re-resolve published anchor IDs against the pinned SPARTA catalog

Exit codes: 0 ok, 1 validation or invariant failure, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import pipeline, report
from .workspace import DEFAULT_DATA, Workspace


def _ws(args) -> Workspace:
    return Workspace(Path(args.data))


def cmd_sources(args) -> int:
    ws = _ws(args)
    status = ws.manifest.verify() if args.verify else {}
    bad = 0
    for k, e in ws.manifest.entries.items():
        line = f"{k:<15} {e['version']:<55} {e['sha256'][:16]}…"
        if args.verify:
            ok = status[k][0]
            bad += not ok
            line += "  OK" if ok else "  MISMATCH"
        print(line)
    return 1 if bad else 0


def cmd_validate(args) -> int:
    errs = _ws(args).validate(check_sources=not args.skip_sources)
    for e in errs:
        print(e)
    print(f"{len(errs)} problem(s)" if errs else "valid")
    return 1 if errs else 0


def cmd_list(args) -> int:
    ws = _ws(args)
    print("threats:")
    for tid, t in ws.threats.items():
        print(f"  {tid}  {t['name']}  ({len(ws.scenarios.get(tid, []))} scenarios, "
              f"evidence clauses: {'yes' if ws.evidence(tid) else 'no'})")
    print("architectures:")
    for gid, g in ws.architectures.items():
        print(f"  {gid}  {len(g['nodes'])} nodes, {len(g['edges'])} edges  — {g['source'][:70]}")
    print("scenarios:")
    for tid, sis in ws.scenarios.items():
        for si in sis:
            print(f"  {si['si_id']:<18} {si['variant']:<7} {si['attacker']['class']:<26} {si['label'][:60]}")
    return 0


def cmd_run(args) -> int:
    ws = _ws(args)
    errs = ws.validate(check_sources=True)
    if errs:
        print("input validation failed; run `phalanx validate`:", *errs[:10], sep="\n  ", file=sys.stderr)
        return 1
    bundle = pipeline.run(ws, args.threat, args.scenario or None, method=args.method)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{args.threat}{_sfx(args.method)}_bundle.json").write_text(json.dumps(bundle, indent=1, ensure_ascii=False), encoding="utf-8")
        (out / f"{args.threat}{_sfx(args.method)}_report.md").write_text(report.render(bundle), encoding="utf-8")
    if args.json:
        print(json.dumps({"canonical_sha256": bundle["canonical_sha256"], "summary": pipeline.summary(bundle),
                          "invariant_violations": bundle["invariant_violations"]}, ensure_ascii=False))
    else:
        print(f"{'scenario':<18} {'variant':<7} {'cand':>4} {'acc':>4} {'rej':>4} {'unr':>4}  crossed")
        for s in pipeline.summary(bundle):
            print(f"{s['scenario']:<18} {s['variant']:<7} {s['candidates']:>4} {s['accepted']:>4} {s['rejected']:>4} "
                  f"{s['unresolved']:>4}  {', '.join(s['crossed']) or '—'}")
        print(f"hash {bundle['canonical_sha256']}")
        if args.out:
            print(f"wrote {Path(args.out) / (args.threat + _sfx(args.method) + '_bundle.json')} and _report.md")
        for v in bundle["invariant_violations"]:
            print(f"INVARIANT {v}", file=sys.stderr)
    return 1 if bundle["invariant_violations"] else 0


def _sfx(method: str) -> str:
    return "" if method == "B3" else f"_{method}"


def cmd_compare(args) -> int:
    ws = _ws(args)
    errs = ws.validate(check_sources=True)
    if errs:
        print("input validation failed; run `phalanx validate`:", *errs[:10], sep="\n  ", file=sys.stderr)
        return 1
    res = pipeline.compare(ws, args.threat, args.scenario or None)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        slim = {k: v for k, v in res.items() if k != "bundles"}
        (out / f"{args.threat}_compare.json").write_text(json.dumps(slim, indent=1, ensure_ascii=False), encoding="utf-8")
        for m, b in res["bundles"].items():
            (out / f"{args.threat}{_sfx(m)}_bundle.json").write_text(json.dumps(b, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"universe: {res['universe']}" + ("  (development union: diagnostic only, not an H1 result)" if res["diagnostic_only"] else ""))
    print("cells per method and scenario (acc / rej / unr / not_gen / n_a):")
    for m in ("B3", "B2", "B0", "B1b", "B1"):
        for si, c in res["counts"][m].items():
            print(f"  {m}  {si:<16} {c['accepted']:>4} {c['rejected']:>4} {c['unresolved']:>4} "
                  f"{c['not_generated']:>4} {c['not_applicable']:>4}")
    for name, con in res["contrasts"].items():
        print(f"{name} (reference -> other, jointly applicable cells):")
        for si, pairs in con["pairs"].items():
            diff = {k: v for k, v in pairs.items() if k.split("->")[0] != k.split("->")[1]}
            same = sum(v for k, v in pairs.items() if k.split("->")[0] == k.split("->")[1])
            print(f"  {si:<16} same {same:>4}  differ: " + (", ".join(f"{k} {v}" for k, v in diff.items()) or "—"))
    print(f"B1b keywords {res['b1b']['keywords']} -> {len(res['b1b']['results'][0]['techniques']) if res['b1b']['results'] else 0}"
          " techniques (sensitivity analysis); B1 not applicable here (no EMB3D-side input; see `phalanx b1`)")
    print(f"cells hash {res['cells_sha256']}")
    bad = res["invariant_violations"]["B3"] + res["invariant_violations"]["B2"]
    for v in bad:
        print(f"INVARIANT {v}", file=sys.stderr)
    return 1 if bad else 0


def cmd_metrics(args) -> int:
    from . import metrics
    ws = _ws(args)
    errs = ws.validate(check_sources=True)
    if errs:
        print("input validation failed; run `phalanx validate`:", *errs[:10], sep="\n  ", file=sys.stderr)
        return 1
    if args.runs < 2:
        print("--runs must be at least 2 (replay compares runs)", file=sys.stderr)
        return 2
    res = metrics.report(ws, args.threat, args.scenario or None, runs=args.runs)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{args.threat}_metrics.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{args.threat}: {res['status']}")
    print(f"anchor recovery: {res['anchor_recovery']['status']}")
    cn = res["constructed_negatives"]
    print(f"constructed negatives ({cn['universe']['basis']}): {cn['universe']['negatives']} from "
          f"{cn['universe']['fixtures']} accepted cells; accepted (lower is better):")
    for m, d in cn["methods"].items():
        split = f"  rejected {d['rejected']}, unresolved {d['unresolved']}" if "rejected" in d else \
            f"  not_generated {d['not_generated']}"
        print(f"  {m:<4} {d['accepted']:>4}/{d['negatives']:<4} ({d['rate']:.1%}){split}")
    print(f"directional pass ({res['directional_pass']['status']}):")
    for m, d in res["directional_pass"]["methods"].items():
        print(f"  {m:<4} {d['passed']:>3}/{d['evaluated']:<3} violations {d['violation_count']}")
    for m in ("B3", "B2"):
        c, r, u = res["decision_record_completeness"][m], res["replay"][m], res["unresolved"][m]
        print(f"{m}: record completeness {c['complete']}/{c['mrs']}; replay {r['runs']} runs hash_equal={r['hash_equal']} "
              f"flips {r['decision_flips']} ({r['scope'].split(';')[0]}); unresolved {u['unresolved']}/{u['mrs']} ({u['rate']:.1%})")
    print(f"metrics hash {res['metrics_sha256']}")
    return 0


def cmd_linkage(args) -> int:
    ws = _ws(args)
    path = ws.root / "anchors" / "et_linkage.json"
    d = json.loads(path.read_text(encoding="utf-8"))
    print(f"{path.name}: {d['status']}")
    print(f"author: {d['author']}")
    for a in d["anchors"]:
        print(f"{a['anchor_id']} ({a['gate_role']})")
        for l in a["linkage"]:
            tuned = "  TUNED BEFORE LINKAGE" if l["tuned_before_linkage"] else ""
            print(f"  {l['et_id']:<5} {l['et_name'][:40]:<40} {l['confidence']:<6}{tuned}")
        if a["not_adopted"]:
            print(f"  (secondary links not adopted: {', '.join(a['not_adopted'])})")
    return 0


def cmd_b1(args) -> int:
    from . import baselines
    ws = _ws(args)
    path = ws.root / "anchors" / "opssat_emb3d.json"
    res = baselines.run_b1(json.loads(path.read_text(encoding="utf-8")), ws.catalog)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "B1_opssat.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"B1 (SPARTA's own EMB3D crosswalk as generator) on the OPS-SAT SI, {res['catalog']} — descriptive benchmark")
    for st in res["steps"]:
        cov = ", ".join(f"{a} {v}" for a, v in st["asserted_coverage"].items())
        print(f"  {st['step']:<32} {len(st['candidates']):>3} candidates, counted {st['counted'] or '—'}; asserted: {cov}")
    print(f"emitted {res['emitted']}, counted {res['counted']} (precision {res['precision']:.1%}); "
          f"asserted {res['asserted']}, covered {res['covered']} ({res['coverage']['exact']} exact + "
          f"{res['coverage']['parent_child']} parent/child)")
    return 0


def cmd_anchors(args) -> int:
    from . import anchors
    ws = _ws(args)
    res = anchors.resolve(anchors.load(ws.root / "anchors" / "published_mappings.json"), ws.catalog)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "anchor_resolution.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"anchor re-resolution against {res['catalog']}")
    print(f"{'anchor':<25} {'role':<24} {'asserted':>8} {'usable':>6}  status counts")
    for a, c in res["per_anchor"].items():
        extra = f" (+{c['not_executed_listed']} not executed, not counted)" if c["not_executed_listed"] else ""
        print(f"{a:<25} {c['gate_role']:<24} {c['assertions']:>8} {c['usable_as_is']:>6}  "
              + ", ".join(f"{k} {v}" for k, v in c["by_status"].items()) + extra)
    print("flagged (never auto-mapped):")
    for r in res["rows"]:
        if not r["usable_as_is"] and r["execution"] != "possible_not_executed":
            print(f"  {r['anchor']:<25} {r['printed_id']:<12} {r['status']:<15} printed '{r['printed_label']}'"
                  f" | catalog '{r['catalog_name']}'" + (f" | candidates {', '.join(r['suggestions'])}" if r["suggestions"] else ""))
    if res["descriptive_not_resolved"]:
        print("descriptive only, not resolved against SPARTA: " + ", ".join(res["descriptive_not_resolved"]))
    return 0


def _bundle(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_explain(args) -> int:
    print(report.explain(_bundle(args.bundle), args.scenario, args.technique))
    return 0


def cmd_outcomes(args) -> int:
    print(json.dumps(pipeline.outcomes(_bundle(args.bundle)), indent=1, ensure_ascii=False, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phalanx", description="Scenario-conditioned ENISA -> SPARTA threat-modeling engine")
    p.add_argument("--data", default=str(DEFAULT_DATA), help="data directory (default: %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sources", help="list pinned inputs")
    s.add_argument("--verify", action="store_true", help="check sha256 of every pinned file")
    s.set_defaults(fn=cmd_sources)
    s = sub.add_parser("validate", help="validate authored data")
    s.add_argument("--skip-sources", action="store_true", help="skip pinned-source hash check")
    s.set_defaults(fn=cmd_validate)
    sub.add_parser("list", help="list threats, architectures, scenarios").set_defaults(fn=cmd_list)
    s = sub.add_parser("run", help="run all scenarios of a threat")
    s.add_argument("threat")
    s.add_argument("-s", "--scenario", action="append", help="limit to scenario id (repeatable)")
    s.add_argument("-o", "--out", help="write <THREAT>_bundle.json and <THREAT>_report.md here")
    s.add_argument("--json", action="store_true", help="machine-readable summary on stdout")
    s.add_argument("--method", choices=["B3", "B2"], default="B3", help="B3 full method (default), B2 scenario-only")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("compare", help="run B3, B2, B0, B1b (and B1 as not applicable) on the same scenarios as EvaluationCells")
    s.add_argument("threat")
    s.add_argument("-s", "--scenario", action="append", help="limit to scenario id (repeatable)")
    s.add_argument("-o", "--out", help="write <THREAT>_compare.json and the B3/B2 bundles here")
    s.set_defaults(fn=cmd_compare)
    s = sub.add_parser("explain", help="show the nine-check trace for one decision")
    s.add_argument("bundle")
    s.add_argument("scenario")
    s.add_argument("technique")
    s.set_defaults(fn=cmd_explain)
    s = sub.add_parser("metrics", help="evaluation measures (negatives, directional pass, completeness, replay)")
    s.add_argument("threat")
    s.add_argument("-s", "--scenario", action="append", help="limit to scenario id (repeatable)")
    s.add_argument("-o", "--out", help="write <THREAT>_metrics.json here")
    s.add_argument("--runs", type=int, default=3, help="replay runs (default 3)")
    s.set_defaults(fn=cmd_metrics)
    s = sub.add_parser("linkage", help="show the approved anchor -> ENISA ET linkage table")
    s.set_defaults(fn=cmd_linkage)
    s = sub.add_parser("b1", help="baseline B1 on the OPS-SAT SI (descriptive benchmark)")
    s.add_argument("-o", "--out", help="write B1_opssat.json here")
    s.set_defaults(fn=cmd_b1)
    s = sub.add_parser("anchors", help="re-resolve published anchor IDs against SPARTA v4.0.1")
    s.add_argument("-o", "--out", help="write anchor_resolution.json here")
    s.set_defaults(fn=cmd_anchors)
    s = sub.add_parser("outcomes", help="compact decision summary of a bundle")
    s.add_argument("bundle")
    s.set_defaults(fn=cmd_outcomes)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyError as e:
        print(f"error: {e.args[0]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
