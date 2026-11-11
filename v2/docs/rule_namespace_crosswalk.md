# Rule namespace crosswalk (protocol v0.3 §1.2)

Machine-readable source: `docs/rule_registry.json` (protocol name `rules/rule_registry.yaml`; kept here as JSON because `data/rules/` is frozen and the engine reads JSON only). Consistency gate: `phalanx.registry.check(registry.load(), Workspace())` must return `[]`; tests in `tests/test_registry.py`.

## Prefixes

| Prefix | Role |
|---|---|
| `LEG-R` | legacy v1 rules R1-R13, frozen |
| `ET-P` | ET template projection |
| `SI-I` | scenario instantiation |
| `BC-GEN` | boundary candidate generation |
| `MAP-CG` | SPARTA candidate generation |
| `MAP-CHK` | mapping compatibility checks and decision composition |
| `BX-CHK` | crossing validation |
| `AFG-CHK` | attack-flow consistency |
| `CP-CHK` | control placement |

Evidence-clause rows keep their existing data ids `ET-EV-01..05`. `ET-EV` is not one of the nine protocol prefixes, so those ids are registered as `data_rows` of `MAP-CHK-09` (the evidence check that consumes them), not as rules; the same holds for the authority-rule keys under `MAP-CHK-04`.

## Legacy rules (frozen v1: `v2/data/legacy_v1/ntn_threat_algorithm.py`, sha256 `12462d05da59...`)

| Id | Alias | What v1 does | v1 source |
|---|---|---|---|
| `LEG-R01` | R1 | Adversarial category -> TTP expected (frozen_legacy) | ADVERSARIAL l.37; classify_nature l.45; run l.156 |
| `LEG-R02` | R2 | Failure category -> TTP N/A (frozen_legacy) | FAILURE l.38; classify_nature l.48; run l.157 |
| `LEG-R03` | R3 | State/outage category -> TTP N/A, kept as precondition (frozen_legacy) | STATE l.39; classify_nature l.47; run l.158; report l.231 |
| `LEG-R04` | R4 | Environmental category -> TTP N/A (frozen_legacy) | ENVIRON l.40; classify_nature l.49; run l.159 |
| `LEG-R05` | R5 | Enabling/legacy category -> TTP expected, spawns adversarial chain (frozen_legacy) | ENABLING l.41; classify_nature l.46; run l.160 |
| `LEG-R06` | R6 | One threat -> many techniques (frozen_legacy) | run l.161-162 |
| `LEG-R07` | R7 | Confidence tagging (frozen_legacy) | run l.163, l.167-172; webapp/src/engine/ui.ts RULE_TIPS.R7 |
| `LEG-R08` | R8 | Countermeasure linkage (frozen_legacy) | run l.162; report l.232; webapp/src/engine/ui.ts RULE_TIPS.R8 |
| `LEG-R09` | R9 | Multi-segment footprint -> bridging sub-chain (frozen_legacy) | run l.164; report l.229 |
| `LEG-R10` | R10 | Multi-lifecycle footprint (frozen_legacy) | run l.165; report l.230 |
| `LEG-R00` | Pass-1 | Pass-1 derivation of S, TB and L from affected assets A (frozen_legacy; unnumbered in v1, registry-assigned id) | derive_segments l.56-68; CORE_KW/RFGROUND_KW/_crosses_ground_core l.71-79; derive_trust_boundaries l.81-91; derive_lifecycle l.94-107; run l.148-152 |
| `LEG-R11` | R11 | Interface boundary where the operator or security domain changes (frozen_legacy, 2026-08 review) | mapping review deck slide 10 |
| `LEG-R12` | R12 | Artifact admission boundary, analyst-assigned with evidence grades E1–E4 (frozen_legacy, 2026-08 review) | mapping review deck slides 10–11 |
| `LEG-R13` | R13 | Authority exercised over equipment (frozen_legacy, 2026-08 review) | mapping review deck slide 10 |

R1–R10 are defined in the frozen v1 code. R11–R13 and the revised R9 were defined in the August 2026 mapping-rule review (`연구노트/mapping_review/ENISA-SPARTA 매핑 규칙 검증 중간보고 2026-08.pptx`, slides 10–11) and are not implemented in the v1 code. The unnumbered v1 Pass-1 derivation block, previously filed under LEG-R11 by inference, is now `LEG-R00`.

## Current rules

| Id | Title | Source |
|---|---|---|
| `ET-P-LC-01` | Candidate lifecycle of the ETP | data/threats/TR52.json - projection.lifecycle_rule; Workspace._check_scenario |
| `ET-P-SEL-01` | ETP selector scope definition | data/selectors/enisa_asset_selectors.json - src/phalanx/selectors.py |
| `SI-I-WIN-01` | SI action window | data/rules/techniques.json - action_window; engine.check behavior |
| `SI-I-INST-01` | Attacker-scoped graph instantiation | src/phalanx/engine.py - engine.instantiate |
| `SI-I-SEL-01` | SI+G selector resolution | src/phalanx/selectors.py - selectors.resolve -> selector_resolution |
| `MAP-CG-01` | Candidate generator: T1 crosswalk | data/rules/vocabulary.json - candidate_generators.MAP-CG-01; engine.candidates; sources.Crosswalk |
| `MAP-CG-02` | Candidate generator: attacker-class seeds | data/rules/vocabulary.json - candidate_generators.MAP-CG-02; techniques.attacker_seeds |
| `MAP-CG-03` | Candidate generator: legacy chain (regression) | data/rules/vocabulary.json - candidate_generators.MAP-CG-03; Workspace.v1_mapping |
| `MAP-CG-04` | Candidate generator: deprecation successors | data/rules/vocabulary.json - candidate_generators.MAP-CG-04; techniques.deprecation_successors |
| `MAP-CHK-01` | Check: technique valid in the pinned SPARTA version | src/phalanx/engine.py - engine.check version |
| `MAP-CHK-02` | Check: behavior inside the SI action window | src/phalanx/engine.py - engine.check behavior; techniques.tactic_defaults.kind |
| `MAP-CHK-03` | Check: attacker class holds the required access position | src/phalanx/engine.py - engine.check access_position |
| `MAP-CHK-04` | Check: authority precondition | src/phalanx/engine.py - engine.check authority; vocabulary.authority_rules |
| `MAP-CHK-05` | Check: technique target intersects SI selected assets | src/phalanx/engine.py - engine.check target |
| `MAP-CHK-06` | Check: technique effect intersects SI intended effect | src/phalanx/engine.py - engine.check effect |
| `MAP-CHK-07` | Check: SI realized lifecycle in technique phases | src/phalanx/engine.py - engine.check lifecycle |
| `MAP-CHK-08` | Check: path and on-board foothold | src/phalanx/engine.py - engine.check reachability; engine.run_scenario passes 1-2; engine.edge_from |
| `MAP-CHK-09` | Check: ET-linked evidence clause supports the technique | src/phalanx/engine.py - engine.check evidence; Rules.evidence_index |
| `MAP-CHK-10` | Technique profile resolution | src/phalanx/engine.py - Rules.profile; techniques.tactic_defaults/overrides |
| `MAP-CHK-11` | Decision composition | src/phalanx/engine.py - engine.decide |
| `MAP-CHK-12` | Assurance-finding derivation | src/phalanx/engine.py - engine.findings; engine.run_threat |
| `BC-GEN-01` | Boundary-edge verdict candidates (applicable/adjacent/not_applicable) | src/phalanx/engine.py - engine.boundary_verdicts (flags applicable/adjacent) |
| `BX-CHK-01` | Crossing validation | src/phalanx/engine.py - engine.attack_flow crossings; engine.boundary_verdicts; invariants I4 |
| `AFG-CHK-01` | AFG: on-board actions are preceded by an accepted entry | src/phalanx/engine.py - engine.attack_flow check_AFG-CHK-01 |
| `AFG-CHK-02` | AFG: an accepted Impact step realises the intended effect | src/phalanx/engine.py - engine.attack_flow check_AFG-CHK-02 |
| `AFG-CHK-03` | AFG: ordering of accepted actions | src/phalanx/engine.py - engine.run_scenario accepted sort; engine.attack_flow |
| `CP-CHK-01` | Control-placement listing (no placement check yet) | src/phalanx/engine.py - engine.run_scenario cpr_sparta/cpr_enisa_annex_d |

## Crosswalk legacy -> current

| Legacy | Relation | Current | Semantic delta |
|---|---|---|---|
| `LEG-R01`, `LEG-R05` | merged | `MAP-CG-01` | v1 branched on the ENISA category (R1 adversarial, R5 enabling) and only flagged 'TTP expected'; it never computed techniques. The engine has no category gate: candidate generation runs for whichever ET is requested (pilot: TR52, category NAA) and every candidate is decided by MAP-CHK. R5's 'spawns an adversarial chain' is not modelled; enabling is a technique-profile effect value, not an ET category. |
| `LEG-R02` | dropped | - (see also `MAP-CHK-12`) | No current rule gates on failure categories (FM, UD); the pilot has no non-adversarial ET. Before the engine runs such an ET a rule must decide between no candidates (I11 no_framework_coverage) and not_applicable cells (protocol s1.1/s6.1). |
| `LEG-R03` | dropped | - | State/outage-as-precondition is not modelled; no current rule consumes an ET category. Same open decision as LEG-R02. |
| `LEG-R04` | dropped | - | Environmental category gate not modelled. Same open decision as LEG-R02. |
| `LEG-R06` | split | `MAP-CG-01`, `MAP-CG-02`, `MAP-CG-03`, `MAP-CG-04`, `MAP-CHK-11` | v1 asserted a one-to-many cardinality flag. Now four generators propose candidates with recorded provenance (MR.generators) and each candidate gets its own decision; many-to-many is a computed result, not an assertion. |
| `LEG-R07` | dropped | - (see also `MAP-CHK-11`) | No High/Med/Low confidence grade exists. Replaced by status accepted|rejected|unresolved with system-state reason codes and root facts (MAP-CHK-11); the two are not convertible. |
| `LEG-R08` | dropped | - (see also `CP-CHK-01`) | Legacy intent: countermeasures attach to specific assets and interfaces. Current CP-CHK-01 only lists countermeasures with placement 'not_adjudicated'; the attachment semantics return in Phase 3. |
| `LEG-R09` | split | `BC-GEN-01`, `AFG-CHK-03` | v1 flagged records spanning >=2 segments and asked for a bridging IA->EX/LM->IMP sub-chain. Now boundaries come from graph edges (BC-GEN-01) and the chain is built from accepted actions in order (AFG-CHK-03; AFG-CHK-01 requires entry before on-board action). The segment-count trigger is gone. |
| `LEG-R10` | split | `ET-P-LC-01`, `MAP-CHK-07` | v1 flagged multi-phase lifecycle and deferred any split. Now the ETP states candidate phases (ET-P-LC-01) and each SI fixes one realized phase that is checked against the technique phases (MAP-CHK-07); a multi-phase ET becomes several SIs rather than a flag. |
| `LEG-R00` | split | `ET-P-LC-01`, `BC-GEN-01` (see also `ET-P-SEL-01`, `SI-I-SEL-01`) | The Pass-1 block is split by output. Lifecycle (L): derived from A by keyword in v1, copied from the legacy tuple field in ET-P-LC-01 (provenance recorded; not equivalent in method, identical value for TR52). Trust boundaries (TB): v1 output as asserted boundaries is reclassified per plan v5 s10 as candidate/adjacency (BC-GEN-01) over graph edges; the Ground<->Core keyword heuristic is replaced by the architecture graph and security-domain membership. Segments (S): derivation from 'Segment:' prefixes is dropped (nodes carry segment/domain in G); selector scope is handled by ET-P-SEL-01 and SI-I-SEL-01. |
| - | new | `SI-I-WIN-01`, `SI-I-INST-01`, `SI-I-SEL-01`, `ET-P-SEL-01` | No v1 counterpart: scenario action window, attacker-scoped instantiation, selector scope and resolution. |
| - | new | `MAP-CG-02`, `MAP-CG-03`, `MAP-CG-04` | No v1 counterpart: attacker-seed, legacy-regression and deprecation-successor generators (v1 had no candidate generation). |
| - | new | `MAP-CHK-01`, `MAP-CHK-02`, `MAP-CHK-03`, `MAP-CHK-04`, `MAP-CHK-05`, `MAP-CHK-06`, `MAP-CHK-08`, `MAP-CHK-09`, `MAP-CHK-10`, `MAP-CHK-12` | No v1 counterpart: v1 left TTP, CM and Conf blank for the analyst. The nine compatibility dimensions (version, behavior, access_position, authority, target, effect, lifecycle, reachability, evidence), profile resolution and finding derivation are new (MAP-CHK-07 appears under LEG-R10). |
| - | new | `BX-CHK-01`, `AFG-CHK-01`, `AFG-CHK-02`, `CP-CHK-01` | No v1 counterpart: crossing validation (I4), attack-flow consistency checks, and control listing. |

| `LEG-R11` | split | `BC-GEN-01`, `BX-CHK-01` | v2 records operator/security-domain change as data (`security_domain`, `crosses_security_domain`) and does not derive a boundary from it; verdicts come from edge roles (BC-GEN-01) and 'crossed' needs a traversing accepted action (BX-CHK-01). A domain change alone neither creates nor crosses a boundary. |
| `LEG-R12` | dropped (see also `BC-GEN-01`) | — | Artifact admission is modelled structurally (boundary role `artifact_admission`); the analyst assignment and E1–E4 grading have no v2 counterpart. |
| `LEG-R13` | split | `MAP-CHK-04`, `SI-I-INST-01` | Authority is checked per technique from the attacker credential and protection state; HR assets are not modelled and there is no judged path. |

No row uses `equivalent`: no legacy rule survives unchanged in meaning.

## §1.2 bullet 4 - rule version and evidence with every derived output: current state (gap, not fixed here)

What bundles carry today (`pipeline.run`, `engine.run_scenario`):

- Bundle level: `inputs` = sha256 of every authored file read plus the pinned sources (this pins the exact rule tables), `generated_by.engine`, `canonical_sha256`.
- Per MR `provenance`: `threat`, `scenario`, `method`, `catalog` (SPARTA version), `engine`, and `rules` = `{vocabulary: <version>, techniques: <status string>, evidence: <status string>}`. `invariants.check_bundle` (I9) requires these keys.
- Per MR evidence: `generators` (MAP-CG ids), `checks[].code` (reason-code names), `supporting_evidence` (clause text; the clause id `ET-EV-nn` is inside the string), `opposing_evidence`.

Gaps against §1.2 bullet 4 / I9:

1. No per-rule version: `rules.techniques` and `rules.evidence` hold the free-text status `draft (analyst-authored, not frozen)`, not a version; only `vocabulary` has a version (`0.1.0-draft`). The registry's per-rule `version` is not copied into outputs.
2. Check results carry reason-code names, not `MAP-CHK-nn` ids; `registry.rule_for_reason_code` resolves them outside the bundle but the bundle itself does not.
3. Boundary verdicts (`BC-GEN-01`/`BX-CHK-01`), `ET-P-LC-01`, `SI-I-*` and `CP-CHK-01` outputs carry no rule id or version; AFG check keys `check_AFG-CHK-01/02` carry ids but no version, and `afg.nodes/edges` (`AFG-CHK-03`) and AF findings (`MAP-CHK-12`) carry none.
4. The evidence clause id is embedded only in a detail string, not a structured field.

Closing the gap needs new output fields (rule id, rule version, registry hash on each derived record), which changes `canonical_sha256`; deliberately not done in this slice.
