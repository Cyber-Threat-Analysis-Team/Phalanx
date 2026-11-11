# PHALANX v2 — threat-modeling engine (CLI)

Two engines over the same data:

- **Scenario engine** (`phalanx.tm`, `data/tm/`): places an ENISA threat on an architecture (transparent, G-CONV,
  G-D53) and an attacker scenario and derives the SPARTA v4.0.1 kill chain the scenario allows. See
  [Threat-modeling engine](#threat-modeling-engine-datatm).
- **Nine-check decision engine** (`phalanx.engine`): decides for every candidate SPARTA technique
  `accepted` / `rejected` / `unresolved`, with system-state reason codes and trust-boundary verdicts. It reproduces
  every decision of the TR52 pilot (`tests/fixtures/tr52_pilot_outcomes.json`). Rules are analyst-authored drafts.

No UI. Both engines are pure functions over plain dicts, so a front end can render their output without
re-implementing anything. Origin of every file: `../PROVENANCE.md`. Third-party sources and licences:
`THIRD_PARTY_NOTICES.md`.

## Try it (about five minutes)

```bash
cd v2
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'    # once; Python ≥ 3.11

.venv/bin/phalanx validate                         # 1. inputs are well-formed and pinned  -> "valid"
.venv/bin/phalanx run TR52 -o out                  # 2. decisions for six TR52 scenarios; read out/TR52_report.md
.venv/bin/phalanx explain out/TR52_bundle.json SI-TR52-C IA-0008.01   # 3. why one technique was decided so
.venv/bin/phalanx compare TR52 -o out              # 4. same scenarios under B3, B2, B0, B1b (B1 n/a)
.venv/bin/phalanx metrics TR52 -o out              # 5. negatives, directional pass, completeness, replay
.venv/bin/phalanx anchors                          # 6. published anchor IDs re-checked against SPARTA v4.0.1
.venv/bin/phalanx b1                               # 7. baseline B1 on the OPS-SAT case
.venv/bin/phalanx linkage                          # 8. anchor -> ENISA threat linkage
.venv/bin/pytest -q                                # 9. test suite (~15 s)
```

Output on the TR52 pilot is development output: illustrative, not validation.

**Change a scenario and see the effect.** Copy a scenario, edit one field, run it, and diff the decisions:

```bash
cp data/scenarios/TR52/A.json data/scenarios/TR52/MY.json
# edit MY.json: set "si_id": "SI-TR52-MY", then e.g. attacker.credential "mission_valid" -> "none",
# or protection_applied {"E-TCUL": true}, or "variant": "G-CONV"
.venv/bin/phalanx validate
.venv/bin/phalanx run TR52 -s SI-TR52-A -s SI-TR52-MY -o out
.venv/bin/phalanx explain out/TR52_bundle.json SI-TR52-MY EX-0009.02
rm data/scenarios/TR52/MY.json                     # scenarios are data; nothing else to undo
```

Allowed values for every field are in `src/phalanx/schemas/scenario.schema.json` and `data/rules/vocabulary.json`;
`phalanx validate` names the field and the problem when a value is wrong.

## All commands

```bash

.venv/bin/phalanx sources --verify          # pinned inputs and their sha256
.venv/bin/phalanx validate                  # schemas, cross-references, SPARTA ids (I10)
.venv/bin/phalanx list                      # threats, architectures, scenarios
.venv/bin/phalanx run TR52 -o out           # all TR52 scenarios -> out/TR52_bundle.json, out/TR52_report.md
.venv/bin/phalanx run TR52 -s SI-TR52-B --json
.venv/bin/phalanx run TR52 --method B2 -o out   # scenario-only comparison method
.venv/bin/phalanx compare TR52 -o out          # B3, B2, B0, B1b, B1 as EvaluationCells -> out/TR52_compare.json
.venv/bin/phalanx metrics TR52 -o out --runs 3  # evaluation measures -> out/TR52_metrics.json
.venv/bin/phalanx anchors -o out                # re-resolve published anchor IDs against SPARTA v4.0.1
.venv/bin/phalanx b1 -o out                     # baseline B1 on the OPS-SAT SI -> out/B1_opssat.json
.venv/bin/phalanx linkage                       # anchor -> ENISA ET linkage table
.venv/bin/phalanx explain out/TR52_bundle.json SI-TR52-C IA-0008.01   # nine-check trace of one decision
.venv/bin/phalanx outcomes out/TR52_bundle.json                       # compact decisions, for diffs
.venv/bin/pytest -q
```

`run` exits 1 if input validation fails or any output invariant is violated.

## Plan objects → code

| Method object | Where |
|---|---|
| ET (threat template) + ETP (projection) | `data/threats/<ET>.json` (`projection` block), `schemas/threat.schema.json` |
| G (architecture variant): nodes with security domain, planes, functions; edges with role, `use_optionality`, domain crossing | `data/architectures/G-D53.json`, `G-CONV.json`, `transparent.json`, `schemas/architecture.schema.json` |
| SI (scenario instance), incl. optional `authoring_aid` | `data/scenarios/<ET>/*.json`, `schemas/scenario.schema.json` |
| ET evidence clauses (ET linkage) | `data/rules/evidence/<ET>.json` |
| Technique profiles, attacker seeds, deprecation successors | `data/rules/techniques.json` |
| Reason codes, boundary roles, generators, authority rules | `data/rules/vocabulary.json` |
| Candidate generation (MAP-CG-01…04; T1 = MAP-CG-01) | `engine.candidates`, `sources.load_crosswalk` |
| Nine checks → MR (decision record) | `engine.check`, `engine.decide`, `schemas/decision.schema.json` |
| AFG (attack flow), AFG-CHK-01/02 | `engine.attack_flow` |
| Boundary verdicts (crossed > applicable > adjacent > not_applicable) | `engine.boundary_verdicts` |
| CPR (controls; placement not yet adjudicated) | `cpr_sparta`, `cpr_enisa_annex_d` in each result |
| AF (assurance findings) | `engine.findings`, `schemas/attack_flow.schema.json` |
| Invariants I1, I2, I4, I5, I6, I8, I9, I11, I12 (output); I10 (input) | `invariants.py`; `Workspace.validate` |
| Selector policy (symbolic / scoped / partial / unresolved), per-SI `selector_resolution` | `selectors.py`, `data/selectors/enisa_asset_selectors.json` |
| Rule registry and legacy crosswalk; rule id on every check result | `docs/rule_registry.json`, `docs/rule_namespace_crosswalk.md`, `registry.py` |
| Comparison methods B0 (v1 as shipped), B1 (SPARTA's EMB3D crosswalk, OPS-SAT only), B1b (keyword crosswalk), B2 (scenario-only), B3 (full) | `baselines.run_b0`, `run_b1`, `run_b1b`; `pipeline.run(method=…)`; B1 input `data/anchors/opssat_emb3d.json` |
| EvaluationCell normalization, contrasts; universe U as a parameter | `evaluation.py`, `pipeline.compare`, `schemas/evaluation_cell.schema.json` |
| Metric scripts: anchor recovery (synthetic fixtures only), constructed negatives, directional pass, record completeness, replay, unresolved / no-coverage | `metrics.py`, expectations `data/expectations/TR52.json` |
| Anchor → ENISA ET linkage (main links) | `data/anchors/et_linkage.json`; proposed ID corrections `data/anchors/adjudications.json` |
| Anchor re-resolution (protocol §1.5) | `anchors.py`, `data/anchors/published_mappings.json`, fixture `tests/fixtures/anchor_resolution.json` |
| Canonical hash, provenance | `pipeline.run` (hash excludes `inputs`, `generated_by`, `invariant_violations`) |

Semantics live in `data/rules`, not in code: changing a profile, seed, clause or
authority rule needs no code change.

## Boundary naming

Edges carry two separate labels:

- `role` (`boundary_role`): what the link does (`command_authority`, `operator_policy`,
  `artifact_admission`, `f1_over_isl`, `ng_over_feeder`, `physical_custody`). Verdicts depend on the
  role: a threat's projection names the roles it is about (TR52: `command_authority`).
- `figure_alias`: the TB1–TB5 the link sits under,
  with `figure_alias_basis` saying whether the paper states it or it is our interpretation. The run
  report marks interpreted aliases `(interp.)`.

So two links under the same paper boundary can get different verdicts (E-TCUL crossed, E-SLE adjacent; both TB2).


## Adding a threat

1. `data/threats/<ID>.json`: copy the ENISA Annex C fields, map assets in `projection.candidate_assets`,
   lifecycle in `projection.candidate_lifecycle`, roles in `projection.applicable_boundary_roles`;
   `crosswalk_key` = the threat name in the ENISA workbook (omit if none).
2. `data/rules/evidence/<ID>.json`: split the description into clauses and link techniques.
3. `data/scenarios/<ID>/*.json`: one file per SI.
4. Profiles for techniques the tactic defaults get wrong: `data/rules/techniques.json` `overrides`.
5. `phalanx validate`, then `phalanx run <ID>`.

## Threat-modeling engine (`data/tm/`)

Architecture first, then ENISA, then SPARTA. Files:

- `data/tm/attack_surface.json`: three architectures (source graph; nodes with `operated_by`, links with `kind` and `control`), controls (SDLS, NDS/IP, F1 IPsec, 5G AS/NAS, hosted-RAN segregation), nine attacker origins with attach rule, credentials and entry techniques (channel, injects), door / reverse-door / crosslink techniques, step authority, link-only techniques.
- `data/tm/adversary.json`: adversary role per threat (ENISA category by default; ENISA-quoted overrides to adversarial, enabling or none) and the scenario switch of each enabling threat.
- `data/tm/candidates/<TR>.json` (from `tools/tm_candidates.py`): ENISA text and SPARTA candidates (crosswalk, SV links, live Impact, every origin's entry/door/crosslink technique).
- `data/tm/mapping/<TR>.json`: access vectors (ENISA quote, basis, acquired credential), one reason code per candidate with role, `enables`, quotes, framework; or `no_sparta_fit {kind, reason}`. Checked by `tools/tm_validate.py` (per file, cross-threat reciprocity, surface and adversary files).
- `phalanx.tm`: entry paths computed from the links; scenario = vector × path × credential × controls off/on; entry by channel and control, hosted→bus door, crosslink, step authority, link-only steps, chain along `enables`; neutral architecture comparison.
- `tools/tm_showcase.py OUT`: HTML report (Korean), summary.json, per-threat CSV.

```bash
.venv/bin/python tools/tm_candidates.py
.venv/bin/python tools/tm_validate.py
.venv/bin/python tools/tm_showcase.py out/showcase
```

## Limitations

- Security domains are `assumed` except where a specification clause is cited.
- Threat mappings in `data/tm/mapping/` are `status: proposed` and not yet reviewed.
- Invariants I3 and I7 are not implemented; control placement (`placement`) is not adjudicated.
- Schemas, rules and the reason-code vocabulary are not frozen.
