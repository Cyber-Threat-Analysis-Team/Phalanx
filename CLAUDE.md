# PHALANX — project context

PHALANX is an architecture-first threat-modeling method for 6G non-terrestrial networks (NTN). It turns ENISA Space Threat Landscape 2025 threats into scenario-specific kill chains of SPARTA v4.0.1 techniques on three architecture variants: transparent (gNB on the ground, satellite relays Uu; 3GPP TR 38.821), G-CONV (whole gNB on one satellite) and G-D53 (DU and CU on two satellites, F1 over the inter-satellite link). Every kept or removed step carries its reason and source quote.

| Where | What | Status |
| --- | --- | --- |
| `v2/` — `phalanx.tm`, `v2/data/tm/`, `v2/tools/tm_*.py` | scenario engine and reason-coded mappings | the method |
| `v2/` — `phalanx.engine`, `pipeline`, `anchors`, `baselines`, `metrics`, `data/{rules,scenarios,anchors,…}` | nine-check engine, TR52 pilot, baselines B0–B3 | kept runnable with its tests, not extended |
| `v2/data/legacy_v1/` | v1 prototype engine and data | baseline B0 input; never modified |

## Method in one screen

- **Attack surface** (`v2/data/tm/attack_surface.json`): nodes and links per architecture from the source graph (`v2/data/architectures/`) and 3GPP TR 38.821, additions marked `basis: assumed`; security controls on links (SDLS, NDS/IP, F1 IPsec, 5G AS/NAS, hosted-RAN segregation) with what bypasses them; nine attacker origins with attach rules, credentials and entry techniques; `trust_boundaries` maps each link to trust-boundary labels TB1–TB4 (labels only, never gate a step).
- **Adversary role** (`adversary.json`): ENISA category by default, ENISA-quoted overrides → 34 mapped, 1 no SPARTA fit, 8 enabling conditions, 10 without attacker, 5 held out.
- **Mapping** (`mapping/<TR>.json`, all `status: proposed`, unreviewed): access vectors with ENISA quote and evidence level; one reason code per SPARTA candidate — K-ACTION / K-ENABLE / K-EFFECT (kept), P-PREP (preparation, outside the chain), D-OTHER (belongs to a named other threat, which must keep it), D-UNDESCRIBED; `enables` links build the chain; every row carries `framework`.
- **Scenario engine** (`phalanx.tm`): threat × architecture × origin × access route × credential × security configuration (all off / all on / one off; `no_effect`, `bypassed`). Rules: entry by channel and control, command authority, bus reachability, hosted-RAN door, crosslink, link-only steps, ground-side steps, pruning along `enables`; every removed step names its reason.

## Terms

Use the left column in prose, issues and reports; code and data still use the right column:

| Term | In code / data |
| --- | --- |
| access route | entry path (`entry_paths`, `path`) |
| evidence level: stated / inferred / analyst decision | `basis`: `quote` / `weak` / `lead_decision` |
| security configuration | protection setting (`setting`) |

## Commands (run in `v2/`)

```bash
.venv/bin/pytest -q                                   # full suite; run before every commit
.venv/bin/python tools/tm_candidates.py               # regenerate data/tm/candidates/ and sparta_live.json
.venv/bin/python tools/tm_validate.py [TR..|--cross|--surface]
.venv/bin/python tools/tm_showcase.py OUT_DIR
```

`tm_validate.py` must report no errors and 0 D-OTHER violations before a mapping change is committed.

## Guardrails

- **Held-out threats**: TR30, TR31, TR34, TR36, TR41 are reserved for evaluation; never map or run them.
- **Claims**: results are development results (modelled applicability). Write "same results on G-CONV and G-D53", never "equally secure"; "not described by our ENISA mapping", never "absent from ENISA"; no "first", "better" or "accurate". Mappings count as results only after review.
- **Evidence**: every origin needs a verbatim ENISA quote of ≥ 3 words, except evidence level `analyst decision`, which needs a written reason. K-ACTION and K-EFFECT rows need an ENISA quote; every kept row needs a SPARTA quote.
- **Pinned sources** (`v2/data/sources/`: SPARTA v4.0.1, ENISA control workbook, SafeMode 2026.09.23-1, FiGHT v3.1.0): never edit; a new pin gets a version, sha256 and licence entry in `manifest.json`, a row in `PROVENANCE.md`, an entry in `v2/THIRD_PARTY_NOTICES.md` and its licence text in `v2/data/sources/licenses/`.
- **Public repository**: commit only finished, professional material. No internal notes, decision-log references or personal paths.

## Agent skills

- **Issue tracker**: GitHub Issues of Cyber-Threat-Analysis-Team/Phalanx (`gh` CLI). See `docs/agents/issue-tracker.md`.
- **Triage labels**: needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix. See `docs/agents/triage-labels.md`.
- **Domain docs**: `GLOSSARY.md` and `docs/adr/` at the repo root when they exist. See `docs/agents/domain.md`.
