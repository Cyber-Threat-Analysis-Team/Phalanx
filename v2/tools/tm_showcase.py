"""Build the threat-modeling showcase: every ENISA threat → SPARTA kill chains on G-CONV and G-D53.

Usage: .venv/bin/python tools/tm_showcase.py OUT_DIR
Writes OUT_DIR/index.html (Korean report), OUT_DIR/summary.json, OUT_DIR/mapping/<TRxx>.csv.
"""
from __future__ import annotations

import csv
import html
import json
import sys
from pathlib import Path

from phalanx.tm import ROLE_ORDER, Model, boundaries, entry_paths, not_covered, scenarios

HELD_OUT = {"TR30": "regression probe, not run before Phase 5", "TR34": "regression probe, not run before Phase 5",
            "TR31": "sealed for the Phase 5 evaluation", "TR36": "sealed for the Phase 5 evaluation",
            "TR41": "sealed for the Phase 5 evaluation"}
ROLE_KO = {"entry": "진입", "execution": "실행", "persistence": "지속성", "evasion": "탐지 회피", "lateral": "측면 이동",
           "exfiltration": "유출", "impact": "영향"}
CAT_KO = {"NAA": "악의적 활동/남용", "EIH": "도청·가로채기·하이재킹", "PA": "물리적 공격", "DIS": "재해", "LEI": "법적·관리 미흡",
          "OUT": "서비스 중단", "UD": "비의도적 피해", "FM": "고장·오작동", "LEG": "법적"}
CODE_KO = {"K-ACTION": "유지: 위협 행위 자체", "K-ENABLE": "유지: 필요한 단계", "K-EFFECT": "유지: 결과 실현",
           "P-PREP": "준비", "D-OTHER": "제외: 다른 위협", "D-UNDESCRIBED": "제외: 기술되지 않음"}
CRED_KO = {"mission_valid": "임무 키 보유", "none": "자격 없음", "mno_valid": "이동통신 자격", "subscriber_valid": "가입자 자격",
           "partner_valid": "파트너 접근"}
BASIS_KO = {"quote": "원문 근거", "weak": "약한 근거", "lead_decision": "책임자 결정"}
STRUCTURAL = {"satellite_count_only"}   # follows from the number of satellites, reported apart
DIFF_KO = {"satellite_count_only": "같은 경로·체인, 위성 수만 다름", "reached_differ": "도달 대상 차이", "paths_differ": "진입 경로 차이", "chains_differ": "킬 체인 단계 차이",
           "boundaries_differ": "신뢰 경계 차이", "controls_differ": "관련 보호 수단 차이", "residual_differs": "보호 수단 적용 시 결과 차이"}
FIT_KO = {"sparta_gap": "SPARTA에 해당 기법 없음", "surface_gap": "공격 표면 모델에 해당 출처 없음"}
e = html.escape

CSS = """
:root{--ink:#22263a;--muted:#4a5468;--soft:#7a8399;--rule:#dcdfe6;--paper:#f5f6f8;--accent:#eb6c36;--link:#2e5aa8;--ok:#2f7d4f;--not:#b3363f;--okbg:#e6f2ea;--notbg:#f8e6e7;--softbg:#eef0f4}
*{box-sizing:border-box}body{margin:0;font-family:'Noto Sans KR',sans-serif;color:var(--ink);background:var(--paper);font-size:15.5px;line-height:1.7;word-break:keep-all;overflow-wrap:break-word}
main{max-width:1200px;margin:0 auto;padding:48px 40px 96px}
h1{font-size:32px;line-height:1.3;margin:0 0 10px}h2{font-size:24px;margin:56px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--ink)}
h3{font-size:18px;margin:28px 0 10px}h4{margin:0}p{margin:8px 0}.sub{color:var(--muted)}.small{font-size:13.5px;color:var(--muted)}
.lead{font-size:17px;color:var(--muted);max-width:980px}
.card{background:#fff;border:1px solid var(--rule);border-radius:10px;padding:20px 24px;margin:16px 0}
.warn{border-left:5px solid var(--accent)}.note{border-left:5px solid var(--link)}
table{border-collapse:collapse;width:100%;background:#fff;font-size:14.5px;margin:10px 0;border:1px solid var(--rule)}
th,td{border-bottom:1px solid var(--rule);padding:10px 12px;text-align:left;vertical-align:top}
th{background:var(--softbg);font-weight:600;font-size:13.5px;color:var(--muted)}tbody tr:nth-child(even) td{background:#fafbfc}
code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.kpi{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:24px 0}
.kpi div{background:#fff;border:1px solid var(--rule);border-radius:10px;padding:18px 22px;font-size:14.5px;color:var(--muted)}
.kpi b{display:block;font-size:34px;line-height:1.2;color:var(--ink);margin-bottom:4px}.kpi .hl{border-top:4px solid var(--accent)}
.pill{display:inline-block;font-size:13px;font-weight:600;border-radius:999px;padding:1px 10px;margin:1px 4px 1px 0;white-space:nowrap}
.p-ok{background:var(--okbg);color:var(--ok)}.p-no{background:var(--softbg);color:var(--soft)}.p-bad{background:var(--notbg);color:var(--not)}
.p-arch{background:#e7edf8;color:var(--link)}.p-gray{background:var(--softbg);color:var(--muted);font-weight:500}
.ok{color:var(--ok);font-weight:600}.no{color:var(--soft)}.bad{color:var(--not);font-weight:600}
details{background:#fff;border:1px solid var(--rule);border-radius:10px;margin:12px 0;padding:0 24px}
details[open]{padding-bottom:16px}summary{cursor:pointer;padding:16px 0;font-weight:600;font-size:17px}
details details{border-radius:6px;padding:0 12px;margin:8px 0;background:var(--paper)}details details summary{font-size:13.5px;font-weight:500;padding:8px 0;color:var(--not)}
.q{color:var(--muted);font-style:italic}.arch{display:block}
.tag{display:inline-block;font-size:12.5px;border-radius:999px;padding:1px 9px;background:var(--softbg);margin-left:6px;color:var(--muted)}
table.scn td{font-size:14px}.role{display:inline-block;min-width:64px;color:var(--muted);font-size:13px}
.rm{color:var(--not);font-size:13px;margin:2px 0}details.rmd{background:none;border:0;padding:0;margin:4px 0}details.rmd summary{font-size:13px;font-weight:400;color:var(--muted);padding:2px 0}
.ul-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:4px 24px;font-size:13.5px}.ul-grid div{padding:2px 0;border-bottom:1px dotted var(--rule)}
"""


def setting_text(m: Model, sc: dict) -> str:
    lab = lambda cs: ", ".join(m.surface["controls"][c]["label_ko"] for c in cs)
    st = sc["setting"]
    if st.startswith("only "):
        return lab([st[len("only "):-len(" off")]]) + "만 끔"
    return {"off": "보호 수단 모두 끔", "on": "모두 켬: " + lab(sc["controls_on"]), "no_effect": "켜도 결과 같음: " + lab(sc["controls_on"]),
            "bypassed": "켜져 있으나 자격으로 통과: " + lab(sc["bypassed"]), "none": "경로에 모델링된 보호 수단 없음"}[st]


OP_KO = {"attacker": "공격자", "mno": "이동통신 운영 주체", "mission_operator": "임무 운영 주체", "integrator": "통합 업체",
         "partner": "파트너", "subscriber": "가입자", "neighbour satellite": "인접 위성", "ground→space": "지상→우주"}


def boundary_text(m: Model, b: str) -> str:
    lid, rest = b.split(": ", 1)
    for k, v in sorted(OP_KO.items(), key=lambda x: -len(x[0])):
        rest = rest.replace(k, v)
    tb = m.surface["trust_boundaries"]["by_link"][lid]["tb"]
    return f"<b>{'·'.join(tb) or 'TB 없음'}</b> {rest} (<code>{e(lid)}</code>)"


def chain_html(sc: dict) -> str:
    acc = [s for s in sc["steps"] if s["removed"] is None]
    lines = [f"<div><span class='role'>{ROLE_KO[r]}</span>" + ", ".join(f"<code>{e(s['technique'])}</code>" for s in acc if s["role"] == r) + "</div>"
             for r in ROLE_ORDER if any(s["role"] == r for s in acc)]
    lines.append(f"<div><span class='role'>도달</span><code>{e(sc['reached'] or '진입 실패')}</code></div>")
    return "".join(lines)


def scenario_table(m: Model, res: dict, i: int) -> str:
    groups: dict = {}
    for aid in res["architectures"]:
        for sc in res["architectures"][aid][i]["scenarios"]:
            key = (" → ".join(sc["path"]["via"]), tuple(sc["boundaries"]), sc["credential"], sc["setting"], sc["complete"], sc["reached"],
                   tuple(s["technique"] for s in sc["steps"] if s["removed"] is None))
            groups.setdefault(key, [[], sc])[0].append(aid)
    rows = []
    for (via, bnd, cred, _, done, _, _), (aids, sc) in groups.items():
        rm = [s for s in sc["steps"] if s["removed"]]
        rmh = (f"<details class='rmd'><summary>제거된 단계 {len(rm)}개</summary>"
               + "".join(f"<div class='rm'><s><code>{e(s['technique'])}</code></s> {e(s['removed'])}</div>" for s in rm) + "</details>") if rm else ""
        stop = f"<div class='rm'>{e(sc['stopped_by'])}</div>" if sc["stopped_by"] else ""
        rows.append(f"<tr><td>{'<br>'.join(aids)}</td><td>{e(via)}<div class='small'>{'<br>'.join(boundary_text(m, x) for x in bnd) or '—'}</div></td>"
                    f"<td>{CRED_KO.get(cred, cred)}<div class='small'>{e(setting_text(m, sc))}</div></td>"
                    f"<td>{'<span class=ok>완전</span>' if done else '<span class=bad>불완전</span>'}</td><td>{chain_html(sc)}{stop}{rmh}</td></tr>")
    return ("<table class='scn'><colgroup><col style='width:11%'><col style='width:26%'><col style='width:21%'><col style='width:8%'><col style='width:34%'></colgroup>"
            "<tr><th>아키텍처</th><th>진입 경로 · 넘는 신뢰 경계 (TB)</th><th>공격자 자격 · 보호 수단</th><th>결과</th><th>킬 체인</th></tr>" + "".join(rows) + "</table>")


def threat_section(m: Model, tid: str, res: dict, mp: dict) -> str:
    idx = m.index[tid]
    vec = "".join(f"<li><b>{e(m.surface['origins'][v['vector']]['label_ko'])}</b> (<code>{e(v['vector'])}</code>)"
                  f" · {BASIS_KO[v.get('basis', 'quote')]}"
                  + (f" · 획득 자격: {CRED_KO[v['credential']]}" if v.get("credential") else "")
                  + (f" — <span class='q'>\"{e(v['enisa_quote'])}\"</span>" if v.get("enisa_quote") else " — (원문 인용 없음: 분석가 판단)")
                  + f" <span class='sub'>{e(v['reason'])}</span></li>" for v in mp["vectors"])
    parts = [f"<p>{e(idx['description'])}</p><p><b>C/I/A</b>: {', '.join(idx['cia'])} · <b>범주</b>: {CAT_KO[idx['category']]}</p>",
             f"<h3>접근 벡터 (공격자 출처)</h3><ul>{vec}</ul>"]
    notes = [mp[k] for k in ("notes", "scope_note", "limits") if mp.get(k)]
    if notes:
        parts.append("<p><b>범위·한계</b></p>" + "".join(f"<p class='sub'>{e(n if isinstance(n, str) else '; '.join(map(str, n)))}</p>" for n in notes))
    for i, v in enumerate(mp["vectors"]):
        notes = "".join(f"<p class='sub'>{aid}: {e(res['architectures'][aid][i]['note'])}</p>" for aid in res["architectures"] if res["architectures"][aid][i].get("note"))
        parts.append(f"<h3>{e(m.surface['origins'][v['vector']]['label_ko'])}: 시나리오</h3>{notes}{scenario_table(m, res, i)}")
    diffs = [d for d in res["comparison"] if d["kinds"]]
    if diffs:
        li = "".join(f"<li><b>{e(m.surface['origins'][d['vector']]['label_ko'])}</b>: {', '.join(DIFF_KO.get(k, k) for k in d['kinds'])}"
                     f"<div class='mono sub'>{e(json.dumps(d['detail'], ensure_ascii=False))}</div></li>" for d in diffs)
        parts.append(f"<h3>아키텍처 비교 (G-CONV 기준)</h3><ul>{li}</ul>")
    else:
        parts.append("<h3>아키텍처 비교</h3><p>두 아키텍처에서 진입 경로·도달 대상·킬 체인·신뢰 경계·보호 수단이 같게 나옴 (보안 수준이 같다는 뜻은 아님, 4절).</p>")
    keep = sorted((r for r in mp["rows"] if r["code"].startswith("K-")), key=lambda r: (ROLE_ORDER.index(r["role"]), r["technique"]))
    trs = "".join(f"<tr><td><code>{e(r['technique'])}</code> {e(m.live[r['technique']]['name'])}</td><td>{ROLE_KO[r['role']]}</td><td>{CODE_KO[r['code']]}</td>"
                  f"<td>{e(r['reason'])}" + (f"<div class='q'>ENISA: \"{e(r['enisa_quote'])}\"</div>" if r.get("enisa_quote") else "")
                  + f"<div class='q'>SPARTA: \"{e(r['sparta_quote'])}\"</div></td></tr>" for r in keep)
    n = {c: sum(r["code"] == c for r in mp["rows"]) for c in CODE_KO}
    kept, dropped = n["K-ACTION"] + n["K-ENABLE"] + n["K-EFFECT"], n["D-OTHER"] + n["D-UNDESCRIBED"]
    parts.append(f"<h3>매핑 (유지 단계와 근거)</h3><p class='sub'>SPARTA 후보 <b>{len(mp['rows'])}</b>개 → "
                 f"유지 <b>{kept}</b> (위협 행위 {n['K-ACTION']} · 필요한 단계 {n['K-ENABLE']} · 결과 {n['K-EFFECT']}) · "
                 f"준비 <b>{n['P-PREP']}</b> · 제외 <b>{dropped}</b> (다른 위협에 속함 {n['D-OTHER']} · ENISA 설명에 없음 {n['D-UNDESCRIBED']}). "
                 f"기법별 전체 판정과 근거: <a href='mapping/{tid}.csv'>mapping/{tid}.csv</a></p>"
                 f"<table><tr><th>기법</th><th>역할</th><th>코드</th><th>근거</th></tr>{trs}</table>")
    return "".join(parts)


def main(out: Path) -> None:
    m = Model.load()
    (out / "mapping").mkdir(parents=True, exist_ok=True)
    for old in (out / "mapping").glob("*.csv"):
        old.unlink()
    rows, other, sections, summary = [], [], [], {}
    for tid in sorted(set(m.index) | set(HELD_OUT), key=lambda x: int(x[2:])):
        if tid in HELD_OUT:
            summary[tid] = {"status": "held_out", "reason": HELD_OUT[tid]}
            other.append(f"<tr><td>{tid}</td><td>{e(m.index[tid]['name']) if tid in m.index else ''}</td><td>{CAT_KO[m.index[tid]['category']] if tid in m.index else ''}</td><td>평가용으로 보류</td><td class='small'>{e(HELD_OUT[tid])}</td></tr>")
            continue
        idx, role = m.index[tid], m.role(tid)
        head = f"<td>{tid}</td><td>{e(idx['name'])}</td><td>{CAT_KO[idx['category']]}</td>"
        if role["role"] != "adversarial":
            sw = m.adversary.get("enabling_switches", {}).get(tid)
            txt = (f"공격 조건 (시나리오 설정: <code>{e(sw)}</code>)" if role["role"] == "enabling" else "공격자 없음")
            summary[tid] = {"status": role["role"] if role["role"] == "enabling" else "outside_sparta", "quote": role.get("quote"), "switch": sw}
            other.append(f"<tr>{head}<td>{txt}</td><td class='q'>" + (f"\"{e(role['quote'])}\"" if role.get("quote") else "") + "</td></tr>")
            continue
        mp = m.mapping(tid)
        if mp is None:
            summary[tid] = {"status": "not_mapped"}
            rows.append(f"<tr>{head}<td colspan='5' class='bad'>매핑 파일 없음</td></tr>")
            continue
        with open(out / "mapping" / f"{tid}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["technique", "framework", "name", "SPARTA tactic", "sources", "code", "role", "vectors", "enables / other threat", "reason", "ENISA quote", "SPARTA quote"])
            for r in sorted(mp["rows"], key=lambda r: (r["code"], r["technique"])):
                w.writerow([r["technique"], r.get("framework", "SPARTA"), m.live[r["technique"]]["name"], m.live[r["technique"]]["tactic"],
                            " ".join(r.get("sources", [])), r["code"], r.get("role", ""), " ".join(r.get("vectors", [])),
                            " ".join([r["enables"]] if isinstance(r.get("enables"), str) else r.get("enables") or []) or r.get("other_threat") or "",
                            r["reason"], r.get("enisa_quote", ""), r.get("sparta_quote", "")])
        res = scenarios(m, tid)
        if res.get("no_sparta_fit"):
            fit = mp["no_sparta_fit"]
            summary[tid] = {"status": "no_sparta_fit", **fit}
            rows.append(f"<tr>{head}<td colspan='5' class='no'>{FIT_KO[fit['kind']]}: {e(fit['reason'])}</td></tr>")
            continue
        scen = {a: [s for pv in res["architectures"][a] for s in pv["scenarios"]] for a in res["architectures"]}
        worst = {a: any(s["complete"] for s in scen[a]) for a in scen}
        resid = {a: any(s["complete"] for s in scen[a] if s["setting"] in ("on", "no_effect")) for a in scen}
        on_ok = [s for a in scen for s in scen[a] if s["complete"] and s["setting"] in ("on", "no_effect")]
        resid_link = any(any(x["link_only"] and x["removed"] is None for x in s["steps"]) for s in on_ok)
        insider = {a: any(s["complete"] for s in scen[a] if s["setting"] == "bypassed") for a in scen}
        nocontrol = {a: any(s["complete"] for s in scen[a] if s["setting"] == "none") for a in scen}
        basis = {v["vector"]: v.get("basis", "quote") for v in mp["vectors"]}
        kinds = sorted({k for d in res["comparison"] for k in d["kinds"] if basis[d["vector"]] == "quote" and k not in STRUCTURAL})
        structural = sorted({d["vector"] for d in res["comparison"] if set(d["kinds"]) & STRUCTURAL})
        weak_kinds = sorted({f"{k} ({d['vector']}, {BASIS_KO[basis[d['vector']]]})" for d in res["comparison"] for k in d["kinds"]
                             if basis[d["vector"]] != "quote" and k not in STRUCTURAL})
        kept = sum(r["code"].startswith("K-") for r in mp["rows"])
        summary[tid] = {"status": "mapped", "vectors": [v["vector"] for v in mp["vectors"]], "kept": kept, "candidates": len(mp["rows"]),
                        "complete_any": worst, "complete_with_controls_on": resid,
                        "controls_on_kind": ("link_level" if resid_link else "no_protection_met") if on_ok else None, "complete_via_credential_bypass": insider, "complete_without_modelled_control": nocontrol, "differences": kinds, "differences_weak_basis": weak_kinds, "satellite_count_only": structural, "vector_basis": basis, "result": res}
        vec = ", ".join(m.surface["origins"][v["vector"]]["label_ko"].split(" (")[0] + ("*" if v.get("basis", "quote") != "quote" else "") for v in mp["vectors"])
        yn = lambda d: ("<span class='pill p-ok'>예</span>" if d["G-CONV"] else "<span class='pill p-no'>아니오</span>") if d["G-CONV"] == d["G-D53"] \
            else " ".join(f"{a} " + ("<span class='pill p-ok'>예</span>" if d[a] else "<span class='pill p-no'>아니오</span>") for a in d)
        rows.append(f"<tr>{head}<td>{e(vec)}</td><td>{kept} / {len(mp['rows'])}</td>"
                    f"<td>{yn(worst)}</td><td>{yn(resid)}</td>"
                    f"<td>{', '.join(DIFF_KO.get(k, k) for k in kinds) or '<span class=no>없음</span>'}"
                    + (f"<div class='small'>약한 근거 출처({e(', '.join(sorted({m.surface['origins'][d['vector']]['label_ko'].split(' (')[0] for d in res['comparison'] if d['kinds'] and basis[d['vector']] != 'quote'})))})에서만 차이 있음 → 4절</div>" if weak_kinds else "") + "</td></tr>")
        sections.append(f"<details id='{tid}'><summary>{tid} · {e(idx['name'])}</summary>{threat_section(m, tid, res, mp)}</details>")
    mapped = {t: s for t, s in summary.items() if s["status"] == "mapped"}
    nc = not_covered(m)
    k_any = sum(any(s["complete_any"].values()) for s in mapped.values())
    k_res = sum(any(s["complete_with_controls_on"].values()) for s in mapped.values())
    k_res_link = sum(s["controls_on_kind"] == "link_level" for s in mapped.values())
    k_res_none = sum(s["controls_on_kind"] == "no_protection_met" for s in mapped.values())
    k_ins = sum(any(s["complete_via_credential_bypass"].values()) for s in mapped.values())
    k_noc = sum(any(s["complete_without_modelled_control"].values()) for s in mapped.values())
    k_diff = [t for t, s in mapped.items() if s["differences"]]
    by_kind = {k: [t for t, s in mapped.items() if k in s["differences"]] for k in DIFF_KO}
    used = {v for s in mapped.values() for v in s["vectors"]}
    unused = [m.surface["origins"][v]["label_ko"] for v in m.surface["origins"] if v not in used]
    surf = []
    for aid, a in m.surface["architectures"].items():
        tr = "".join(f"<tr><td rowspan='{max(len(ps), 1)}'>{e(o['label_ko'])}</td>"
                     + ("</tr><tr>".join(f"<td>{e(' → '.join(p['via']))} ⇒ <code>{e(p['reaches'])}</code></td><td class='small'>{'<br>'.join(boundary_text(m, b) for b in boundaries(a, p)) or '—'}</td>" for p in ps)
                        or "<td class='no'>없음</td><td></td>") + "</tr>"
                     for o, ps in ((o, entry_paths(a, o)) for o in m.surface["origins"].values()))
        assumed = [f"{l['id']}" for l in a["links"] if "assumed" in l.get("basis", "")] + [n for n, x in a["nodes"].items() if "assumed" in x.get("basis", "")]
        surf.append(f"<div class='card'><b>{aid}</b> · {e(a['label_ko'])}<table><colgroup><col style='width:30%'><col style='width:36%'><col style='width:34%'></colgroup><tr><th>공격자 출처</th><th>진입 경로 ⇒ 도달 대상 (링크를 따라 계산)</th><th>넘는 신뢰 경계 (TB)</th></tr>{tr}</table>"
                    f"<p class='sub'>가정한 요소: {e(', '.join(assumed))}</p></div>")
    overrides = "".join(f"<tr><td>{t}</td><td>{CAT_KO[m.index[t]['category']]}</td><td>{ {'adversarial': '공격자 있음 → 매핑', 'enabling': '공격 조건', 'none': '공격자 없음'}[o['role']]}</td>"
                        f"<td class='q'>\"{e(o['quote'])}\"</td><td>{e(o['reason'])}</td></tr>" for t, o in sorted(m.adversary["overrides"].items()))
    tbd = m.surface["trust_boundaries"]
    BKO = {"stated": "논문 명시", "interpretation": "해석", "definition": "정의상", "none": "해당 없음"}
    tb_rows = "".join(f"<tr><td><b>{k}</b></td><td>{e(v)} <span class='small'>({e(', '.join(l + ': ' + BKO[x['basis'].split(':')[0]] for l, x in tbd['by_link'].items() if k in x['tb']))})</span></td></tr>" for k, v in tbd["defs"].items()) \
        + f"<tr><td><b>TB 없음</b></td><td>논문 경계에 해당하지 않음 (TB5 인적 자원 ↔ 기술 구간은 논문에 있으나 모델링한 경로가 지나지 않음) <span class='small'>({e(', '.join(l for l, x in tbd['by_link'].items() if not x['tb']))})</span></td></tr>"
    count = lambda st: sum(s["status"] == st for s in summary.values())
    diff_li = "".join(f"<li>{DIFF_KO[k]}: {len(v)}개 {', '.join(v)}</li>" for k, v in by_kind.items() if v) or "<li>없음</li>"
    tr = lambda x: DIFF_KO.get(x.split(" (")[0], x.split(" (")[0]) + " (" + x.split(" (", 1)[1] if " (" in x else x
    weak_li = "".join(f"<li>{t}: {e('; '.join(tr(x) for x in s['differences_weak_basis']))}</li>" for t, s in mapped.items() if s["differences_weak_basis"]) or "<li>없음</li>"
    doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>PHALANX 위협 모델링 쇼케이스 (초안)</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;600;700&display=swap" rel="stylesheet"><style>{CSS}</style></head><body><main>
<p class="sub">6G-NTN 우주 구간 위협 모델링 · 2026-10-27 · 초안</p>
<h1>ENISA 위협 → SPARTA 킬 체인: 전체 초안</h1>
<p class="lead">ENISA Space Threat Landscape 2025의 위협마다 공격자 출처(접근 벡터)를 정하고, SPARTA v4.0.1 기법 후보를 고정된 사유 코드와 인용문으로 판정한 뒤, 두 6G NTN 아키텍처(G-CONV, G-D53)에서 진입 경로·공격자 자격·보호 수단별 시나리오로 킬 체인을 구성함.</p>
<div class="card warn"><b>초안 주의</b>: 접근 벡터·공격자 유무·기법 판정은 assistant가 제안한 것이며 연구 책임자의 검토 전임. 아키텍처는 원본 그래프(G-D53의 feeder 위성에는 TT&C·업데이트·ATLO 링크 없음)를 따르되, 호스팅 RAN을 이동통신 운영 주체가 운영한다는 것, 사용자 단말·서비스 링크·GNSS 수신은 가정임. 원본 아키텍처 파일에서도 TT&C(SLE, TC 업링크)·업데이트·ATLO 링크는 저자가 정의한 확장(author_defined_extension)임. 정확도·우수성 주장이 아닌 개발용 결과임.</div>
<div class="kpi"><div class="hl"><b>{len(mapped)}</b>SPARTA로 매핑한 공격자 있는 위협</div><div class="hl"><b>{k_any}</b>어떤 시나리오에서든 킬 체인이 완전한 위협</div><div class="hl"><b>{len(k_diff)}</b>ENISA가 직접 지명한 출처에서 G-CONV와 G-D53의 결과가 다른 위협 (ENISA·SPARTA로 기술할 수 있는 범위, 4절)</div>
<div><b>{k_res_link} / {k_res_none}</b>보호 수단을 켜도 완전 (자격 없는 공격자): 링크 자체 공격 / 경로에 보호 수단이 없음</div><div><b>{k_ins}</b>자격(임무 키 등)이 보호 수단을 통과해서 완전</div><div><b>{count('enabling')} / {count('outside_sparta')} / {count('no_sparta_fit')} / {len(HELD_OUT)}</b>공격 조건 / 공격자 없음 / SPARTA 미적합 / 평가용 보류</div></div>
<div class="card note"><b>보호 수단과 결과</b><ul><li>자격 없는 공격자가 보호 수단을 모두 켠 상태에서도 완전한 위협 {k_res}개: 켜진 보호 수단을 링크 자체에 대한 공격(재밍·감청·플러딩)으로 이겨 내는 위협 {k_res_link}개, 경로에서 모델링된 보호 수단을 만나지 않는 위협(결과가 지상 IT에 머묾, 근접·물리 공격) {k_res_none}개.</li><li>자격(임무 키 등)으로 보호 수단을 통과해 완전한 위협 {k_ins}개.</li><li>경로에 모델링된 보호 수단이 없어 완전한 위협(공급망, 근접 등) {k_noc}개. 한 위협에 공격 경로가 여러 개 있어 그룹은 겹칠 수 있음.</li><li>SDLS 켬은 프로토콜이 올바르게 구현되었다는 가정이며, SDLS 자체를 깨는 위협(TR28, TR52 등)은 SDLS 끔 시나리오로 나타남.</li></ul></div>
<h2>1. 방법</h2>
<div class="card"><ol><li><b>사전 준비</b>: 아키텍처별 노드·링크·운영 주체·보호 수단, 공격자 출처별 부착 지점·자격·진입 기법(채널 포함). 진입 경로는 링크를 따라 계산함(<code>data/tm/attack_surface.json</code>).</li>
<li><b>공격자 유무</b>: ENISA 범주가 기본이며 설명문이 달리 말하면 인용으로 재분류(공격자 있음 / 공격 조건 / 공격자 없음).</li>
<li><b>위협 특성화</b>: 위협마다 접근 벡터를 ENISA 원문 인용과 함께 선택하고 근거 강도(원문 근거·약한 근거·책임자 결정)를 표시. 위협이 자격 획득을 다루면 획득 자격을 표시.</li>
<li><b>SPARTA 매핑</b>: 후보(crosswalk, SV 링크, 현행 Impact, 모든 출처의 진입·문·위성 간 기법)마다 코드 하나와 인용. 관련 위협끼리 묶어 판정하고, "다른 위협에 속함" 제외는 그 위협이 실제로 유지해야 함.</li>
<li><b>시나리오</b>: 위협 × 아키텍처 × 출처 × 진입 경로 × 공격자 자격 × 보호 수단(끔/켬). 진입 기법은 그 채널의 링크가 있는 경로에서만, 주입형이면 보호 수단이 꺼져 있거나 자격으로 통과할 때만 채택. 호스팅 RAN에서 버스로 넘어가려면 문 기법(IA-0006/LM-0001)과 분리 해제가, 위성 간 이동에는 LM-0003이 필요. 단계마다 필요한 권한과 선행 단계(enables)를 검사하고 제거 사유를 표시.</li>
<li><b>아키텍처 비교</b>: G-CONV 기준으로 도달 대상, 진입 경로, 킬 체인, 신뢰 경계, 관련 보호 수단, 보호 수단 적용 시 결과를 중립적으로 비교.</li></ol></div>
<div class="card"><b>공격자 유무 재분류</b><table><tr><th>ID</th><th>ENISA 범주</th><th>판정</th><th>근거 인용</th><th>사유</th></tr>{overrides}</table></div>
<h2>2. 공격 표면</h2><p class="sub">신뢰 경계는 경로를 따라 운영 주체가 바뀌거나 지상에서 우주로 넘어가는 지점이며, 아키텍처와 경로에서 계산함. 각 경계에는 ASIANComNet 2026 논문의 TB 번호를 붙임(원본 아키텍처 파일의 figure_alias와 같음). 경계는 기록·비교용이며 단계를 막지 않음: 체인을 막는 것은 링크의 보호 수단, 자격, 호스팅 RAN 문 규칙임.</p>
<table><colgroup><col style="width:10%"><col style="width:90%"></colgroup><tr><th>TB</th><th>뜻 (해당 링크)</th></tr>{tb_rows}</table><div class="arch">{''.join(surf)}</div>
<h2>3. 전체 위협 요약</h2>
<h3>3.1 공격자가 있는 위협 (SPARTA 매핑 대상)</h3>
<p class="sub">* 표시된 출처는 원문 근거가 약하거나 책임자 결정임.</p>
<p class="sub">완전한 체인·보호 수단 켬 열은 G-CONV와 G-D53 결과가 같으면 한 번만 표시함.</p>
<table><colgroup><col style="width:6%"><col style="width:17%"><col style="width:10%"><col style="width:27%"><col style="width:8%"><col style="width:11%"><col style="width:11%"><col style="width:10%"></colgroup><tr><th>ID</th><th>위협</th><th>범주</th><th>공격자 출처</th><th>유지 / 후보</th><th>완전한 체인 (어떤 시나리오든)</th><th>보호 수단 켬에서도 완전</th><th>아키텍처 차이</th></tr>{''.join(rows)}</table>
<h3>3.2 공격자가 없거나 공격 조건인 위협, 평가용 보류</h3>
<p class="sub">공격 조건은 다른 위협의 시나리오에서 보호 수단 끔·취약점 같은 설정으로 쓰임. 공격자 없는 위협은 SPARTA 범위 밖임.</p>
<table><colgroup><col style="width:6%"><col style="width:22%"><col style="width:12%"><col style="width:22%"><col style="width:38%"></colgroup><tr><th>ID</th><th>위협</th><th>범주</th><th>판정</th><th>근거 인용</th></tr>{''.join(other)}</table>
<h2>4. 아키텍처 비교 (G-CONV vs G-D53)</h2>
<div class="card note"><p><b>결과</b>: ENISA 원문이 직접 지명한 공격자 출처만 쓰면, 결과가 다른 위협은 {len(k_diff)}개임{(': ' + ', '.join(k_diff)) if k_diff else ''}. 이는 <b>두 아키텍처의 보안 수준이 같다는 뜻이 아님</b>. ENISA 위협 설명과 SPARTA 기법으로 기술할 수 있는 범위에서 차이가 드러나지 않았다는 뜻임.</p></div>
<h3>왜 같게 나오는가</h3>
<ul><li>두 아키텍처는 RAN 배치만 다름: G-CONV는 위성 한 대에 gNB 전체, G-D53은 CU와 DU를 두 위성에 나누고 위성 간 링크(ISL)로 F1을 연결함.</li>
<li>ENISA가 직접 지명한 출처의 공격 경로(지상국 → TT&amp;C 업링크 → 위성 버스, 업데이트·통합, 근접)는 RAN을 지나지 않음. 두 아키텍처에서 이 경로는 같으므로 RAN 배치의 차이가 결과에 나타날 수 없음.</li></ul>
<h3>이 결과로 말할 수 없는 것</h3>
<ul><li>RAN이나 ISL을 지나는 공격: ENISA 위협 설명은 이곳의 공격자를 지명하지 않음. 모델에는 해당 출처({e(', '.join(unused)) or '없음'})가 있으나, 이를 고른 위협은 없음.</li>
<li>RAN 기능 자체에 대한 공격과 영향: SPARTA에는 RAN 기능을 공격하는 기법이 없음. 5G 공격 프레임워크(FiGHT) 확장에서 다룰 대상임.</li>
<li>여러 보호 수단을 동시에 끈 경우: 보호 설정은 하나씩만 끔.</li></ul>
<h3>차이가 나타나는 경우 (본 결과와 분리, 검토 대상)</h3>
<table><colgroup><col style="width:22%"><col style="width:22%"><col style="width:56%"></colgroup><tr><th>종류</th><th>위협</th><th>내용</th></tr>
<tr><td>원문에서 추론한 출처</td><td>{', '.join(t for t, s in mapped.items() if s['differences_weak_basis']) or '없음'}</td><td>feeder 링크의 rogue 게이트웨이나 사용자 단말에서 들어오는 공격자는 RAN을 지나므로, G-D53에서는 진입 경로(ISL의 F1 경유), 경로의 보호 수단(F1 IPsec), 도달 대상(feeder 위성)이 달라짐. 이 출처들은 ENISA 원문에 직접 나오지 않고 추론한 것임. 검토에서 원문 근거로 인정하면 실제 아키텍처 차이가 됨.</td></tr>
<tr><td>위성 수만 다름</td><td>{', '.join(t + ('*' if any(s['vector_basis'][v] != 'quote' for v in s['satellite_count_only']) else '') for t, s in mapped.items() if s['satellite_count_only']) or '없음'}</td><td>근접 공격자는 경로와 체인이 같고, G-D53에 위성이 하나 더 있어 두 번째 위성에도 닿음. 결과 차이로 세지 않음. (* 근접 출처가 원문에서 추론한 것임)</td></tr></table>
<details><summary>추론한 출처의 차이 상세</summary><ul>{weak_li}</ul></details>
<h2>5. ENISA 위협이 기술하지 않은 SPARTA 기법</h2>
<div class="card"><p>후보로 제안되었으나 어떤 위협에서도 유지·준비로 쓰이지 않은 기법 {len(nc['proposed_unused'])}개, 후보로도 제안되지 않은 기법 {len(nc['never_proposed'])}개. 억지로 위협에 넣지 않고 그대로 보고함.</p>
<div class="ul-grid">{''.join(f"<div><code>{e(t)}</code> {e(m.live[t]['name'])}</div>" for t in nc['proposed_unused'])}</div>
<p class="sub">후보로도 제안되지 않음: {e(' '.join(nc['never_proposed']))}</p></div>
<h2>6. 위협별 상세</h2>{''.join(sections)}
</main></body></html>"""
    (out / "index.html").write_text(doc, encoding="utf-8")
    summary["_not_covered_by_enisa"] = nc
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"mapped {len(mapped)}, complete {k_any}, complete with controls on {k_res}, with differences {len(k_diff)}, "
          f"not covered {len(nc['proposed_unused'])}+{len(nc['never_proposed'])}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
