# Third-party notices

This directory contains, or is derived from, the third-party sources below. Each entry lists what is included, where it is, the licence, the attribution required, and the changes made. Licence texts are in `data/sources/licenses/`.

## Redistributed or derived data

### SPARTA (The Aerospace Corporation)
- **Included:** `data/sources/sparta_data_v4.0.1.json` (SPARTA v4.0.1 STIX 2.1 bundle, exported 2026-09-02, unmodified); derived: `data/tm/sparta_live.json` (technique IDs, names, descriptions, tactics of live techniques), `data/tm/candidates/*.json` (candidate technique IDs per ENISA threat), `sparta_quote` excerpts in `data/tm/mapping/*.json`, technique IDs in `data/anchors/*.json` and `data/rules/`.
- **Licence:** SPARTA Terms of Service: non-exclusive, royalty-free licence for research, development and commercial purposes; copies must reproduce Aerospace's copyright designation and the licence. Text: `data/sources/licenses/SPARTA-terms-of-service.txt`.
- **Attribution:** "The Aerospace Corporation. This work is reproduced and distributed with the permission of The Aerospace Corporation." SPARTA® is a registered trademark of The Aerospace Corporation. SPARTA states that it uses MITRE ATT&CK (©2022 The MITRE Corporation; ATT&CK Terms of Use, https://attack.mitre.org/resources/terms-of-use/).
- **Changes:** derived files select live (non-deprecated) techniques and fields; mapping files quote short excerpts. The bundle itself is unmodified.
- **Not covered by the terms:** third-party contributions inside SPARTA are not addressed by the terms of service.

### ENISA Space Threat Landscape 2025 and its Control Framework (European Union Agency for Cybersecurity)
- **Included:** `data/sources/enisa-stl-control-framework-2025-03.xlsx` (Control Framework workbook, github.com/enisaeu/Space-Threat-Landscape, git blob `ac602576`, unmodified); derived: `data/tm/enisa_index.json` (threat IDs, names, categories, CIA, affected assets and descriptions from the STL report, Annex C), affected-asset fields in `data/tm/candidates/*.json`, `enisa_quote` excerpts in `data/tm/mapping/*.json` and `data/tm/adversary.json`; `../ENISA Dataset Threat Mapping.xlsx` (v1 prototype data derived from the same report).
- **Licence:** Creative Commons Attribution 4.0 International (CC BY 4.0), as stated by the ENISA repository and report. Text: `data/sources/licenses/CC-BY-4.0.txt`.
- **Attribution:** European Union Agency for Cybersecurity (ENISA), *Space Threat Landscape*, March 2025 (TP-01-25-007-EN-N), and *Space Threat Landscape Control Framework*, https://github.com/enisaeu/Space-Threat-Landscape. Licensed under CC BY 4.0.
- **Changes:** threat entries re-keyed as TR01–TR58 and transcribed into JSON; one typo kept verbatim in descriptions; the workbook is unmodified.

### SafeMode Space mapping corpus (R. Boundi, Kartia IKE)
- **Included:** `data/sources/safemode-mappings-v2026.09.23-1.json.gz` (release 2026.09.23-1, unmodified); derived: SafeMode-based candidate links and link confidences in `data/tm/candidates/*.json`.
- **Licence:** CC BY 4.0. Text: `data/sources/licenses/CC-BY-4.0.txt`.
- **Attribution:** R. Boundi (Kartia IKE), *SafeMode Space mapping corpus*, release 2026.09.23-1, Zenodo, https://doi.org/10.5281/zenodo.22911569. Licensed under CC BY 4.0.
- **Changes:** only the `enisa_control` edges and their confidence are used to derive candidates; the corpus file is unmodified.

### MITRE FiGHT (5G Hierarchy of Threats)
- **Included:** `data/sources/fight-v3.1.0.yaml` (file `fight.yaml`, github.com/mitre/FiGHT commit `097cd5f7`, v3.1.0, unmodified).
- **Licence:** Apache License 2.0. Repository licence file: `data/sources/licenses/FiGHT-LICENSE.txt`; full text: `data/sources/licenses/Apache-2.0.txt`. The repository at that commit has no NOTICE file.
- **Attribution:** MITRE FiGHT, © The MITRE Corporation, https://fight.mitre.org/, licensed under the Apache License 2.0.
- **Changes:** none.

## Identifiers transcribed from published analyses (no text reproduced)

`data/anchors/published_mappings.json` and `data/anchors/opssat_emb3d.json` record technique identifiers (SPARTA, MITRE EMB3D, ESTM, ATT&CK) that the publications below assert, with locators. No prose, figures or tables are reproduced; each work remains under its publisher's terms.

| Anchor | Source |
|---|---|
| OPS-SAT / CYSAT 2023 (primary) | Bailey & Roeher, "Hacking an On-Orbit Satellite: An Analysis of the CYSAT 2023 Demo", The Aerospace Corporation, 2023 |
| OPS-SAT (secondary, EMB3D/ESTM legs) | spacesecurity.info, "MITRE ESTM + EMB3D in Action: Analyzing OPS-SAT Through These Dual Frameworks" |
| Frøseth et al. | "Threat Modeling in Satellite Communications for Maritime Operations", ESORICS Workshops, Springer, 2025 |
| SpyChain | "SpyChain: Multi-Vector Supply Chain Attacks on Small Satellite Systems", arXiv:2510.06535 |
| Ear | "Towards Principled Analysis and Mitigation of Space Cyber Risks", PhD thesis, UCCS, arXiv:2508.16991 |
| Viasat KA-SAT | spacesecurity.info, "An analysis of the Viasat cyber attack with the MITRE ATT&CK framework" |

## Cited only, not redistributed

Standards and project deliverables used to build the architecture models are cited, not copied: 3GPP TR 38.821, TS 33.501, TS 33.210, TS 38.401, TR 33.700-29; CCSDS 355.0-B-2; 6G-NTN deliverables D3.7 and D5.3; ENISA *Technical Advisory on Secure Update Mechanisms* (2026). Node, link and control names in `data/tm/attack_surface.json` cite them by clause.
