"""T4 对抗测试报告生成器（SPEC-M4 §6）。

从 probe.db（SPEC-M4 §4 表结构）读取 captures / clr_reports / fcr_results /
edr_results，生成六节中文 Markdown 报告：

1. 头部：生成时间、清单版本、各组样本量
2. CLR 汇总表（组 × 命中数/检查数/跳过数）+ 命中明细表
3. EDR 表（组 × 维度 detected 计数，目标全 0）
4. FCR 分桶表（site × group_tag × outcome 计数与 v3 score 分布，分入口不聚合）
5. 对照组差异段（受测组 vs A-native vs B-extension 并排）
6. 结论模板段（数据不足写"样本不足"，不编造结论）

口径纪律（实施方案 §一）：CLR/EDR/FCR 三指标独立报告，永不聚合成分数；
指标只在同一清单版本间可比，报告必须标注清单版本。
空库/缺表时不报错，各节输出"暂无数据"。
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

# 分组展示顺序（SPEC §4 group_tag 口径），未知名排最后
GROUP_ORDER = ["T-cold", "T-warm", "A-native", "B-extension"]
TEST_GROUPS = ["T-cold", "T-warm"]
CONTROL_GROUPS = ["A-native", "B-extension"]
# 实施方案 §一：FCR 每入口每组 N ≥ 10
FCR_MIN_N = 10
NO_DATA = "暂无数据"
INSUFFICIENT = "样本不足"


# ---------------------------------------------------------------------------
# 读库
# ---------------------------------------------------------------------------

def _connect(db_path):
    """只读打开库；文件不存在返回 None（调用方按空库处理，各节"暂无数据"）。"""
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_names(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r["name"] for r in rows}


def _load_captures(conn):
    """captures 表 → [{id, group_tag, persona_id, entry, captured_at}]；缺表返回 []。"""
    if "captures" not in _table_names(conn):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT id, group_tag, persona_id, entry, captured_at FROM captures ORDER BY id"
    )]


def _load_clr_reports(conn):
    """clr_reports JOIN captures → [{capture_id, group_tag, report(dict)}]；坏 JSON 跳过。"""
    tables = _table_names(conn)
    if "clr_reports" not in tables or "captures" not in tables:
        return []
    out = []
    for r in conn.execute(
        "SELECT r.capture_id AS capture_id, c.group_tag AS group_tag, r.report AS report "
        "FROM clr_reports r JOIN captures c ON c.id = r.capture_id ORDER BY r.id"
    ):
        try:
            report = json.loads(r["report"])
        except (TypeError, ValueError):
            continue  # 损坏行不编造，跳过
        if not isinstance(report, dict):
            continue
        out.append({
            "capture_id": r["capture_id"],
            "group_tag": r["group_tag"],
            "report": report,
        })
    return out


def _load_fcr(conn):
    if "fcr_results" not in _table_names(conn):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT group_tag, site, outcome, score FROM fcr_results ORDER BY id"
    )]


def _load_edr(conn):
    if "edr_results" not in _table_names(conn):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT group_tag, dimension, detected FROM edr_results ORDER BY id"
    )]


# ---------------------------------------------------------------------------
# 聚合
# ---------------------------------------------------------------------------

def _group_sort_key(tag):
    return (GROUP_ORDER.index(tag) if tag in GROUP_ORDER else len(GROUP_ORDER), tag)


def _clr_summary(clr_rows):
    """{group: {"runs": n, "hits": n, "total": n, "skipped": n}}"""
    summary = {}
    for row in clr_rows:
        rep = row["report"]
        g = summary.setdefault(row["group_tag"],
                               {"runs": 0, "hits": 0, "total": 0, "skipped": 0})
        g["runs"] += 1
        g["hits"] += len(rep.get("hits") or [])
        g["total"] += int(rep.get("total") or 0)
        g["skipped"] += len(rep.get("skipped") or [])
    return summary


def _checklist_versions(clr_rows):
    versions = []
    for row in clr_rows:
        v = row["report"].get("checklist_version")
        if v and v not in versions:
            versions.append(str(v))
    return versions


def _sample_counts(captures):
    """{group: 样本数}"""
    counts = {}
    for c in captures:
        counts[c["group_tag"]] = counts.get(c["group_tag"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# 六节渲染
# ---------------------------------------------------------------------------

def _section_header(captures, clr_rows, now):
    lines = ["# 替身（Tishen）M4 对抗测试报告", ""]
    lines.append("## 一、头部")
    lines.append("")
    lines.append(f"- 生成时间：{now}")
    versions = _checklist_versions(clr_rows)
    if versions:
        note = "、".join(versions)
        if len(versions) > 1:
            note += "（多版本并存：CLR 指标只在同一清单版本间可比）"
        lines.append(f"- 清单版本：{note}")
    else:
        lines.append(f"- 清单版本：{NO_DATA}")
    counts = _sample_counts(captures)
    if counts:
        lines.append("- 各组样本量（captures 条数）：")
        lines.append("")
        lines.append("| 组 | 样本量 |")
        lines.append("|---|---|")
        for tag in sorted(counts, key=_group_sort_key):
            lines.append(f"| {tag} | {counts[tag]} |")
    else:
        lines.append(f"- 各组样本量：{NO_DATA}")
    lines.append("")
    return lines


def _section_clr(clr_rows):
    lines = ["## 二、CLR 自洽性露馅率（北极星指标 = 0）", ""]
    if not clr_rows:
        lines.append(NO_DATA)
        lines.append("")
        return lines
    summary = _clr_summary(clr_rows)
    lines.append("### 2.1 汇总（组 × 命中数/检查数/跳过数）")
    lines.append("")
    lines.append("| 组 | 评测次数 | 命中数 | 检查数 | 跳过数 |")
    lines.append("|---|---|---|---|---|")
    for tag in sorted(summary, key=_group_sort_key):
        s = summary[tag]
        lines.append(f"| {tag} | {s['runs']} | {s['hits']} | {s['total']} | {s['skipped']} |")
    lines.append("")
    lines.append("### 2.2 命中明细")
    lines.append("")
    hit_rows = []
    for row in clr_rows:
        for hit in row["report"].get("hits") or []:
            hit_rows.append((row["group_tag"], row["capture_id"], hit))
    if not hit_rows:
        lines.append("全部检查零命中。")
    else:
        lines.append("| 组 | capture_id | check_id | 断言 | 严重度 | 证据字段 |")
        lines.append("|---|---|---|---|---|---|")
        for group, cap_id, hit in hit_rows:
            evidence = hit.get("evidence") or {}
            ev = "；".join(f"{k}={v}" for k, v in evidence.items()) or "—"
            lines.append(
                f"| {group} | {cap_id} | {hit.get('check_id', '—')} "
                f"| {hit.get('assertion', '—')} | {hit.get('severity', '—')} | {ev} |"
            )
    lines.append("")
    return lines


def _section_edr(edr_rows):
    lines = ["## 三、EDR 环境识别（目标 3/3 全部未识别）", ""]
    if not edr_rows:
        lines.append(NO_DATA)
        lines.append("")
        return lines
    dims = []
    for r in edr_rows:
        if r["dimension"] not in dims:
            dims.append(r["dimension"])
    # {group: {dim: [detected_cnt, total]}}
    table = {}
    for r in edr_rows:
        cell = table.setdefault(r["group_tag"], {}).setdefault(r["dimension"], [0, 0])
        cell[1] += 1
        cell[0] += int(r["detected"])
    lines.append("（单元格 = 被识别次数 / 记录总数，目标被识别次数全 0）")
    lines.append("")
    lines.append("| 组 | " + " | ".join(dims) + " |")
    lines.append("|---" * (len(dims) + 1) + "|")
    for tag in sorted(table, key=_group_sort_key):
        cells = []
        for d in dims:
            if d in table[tag]:
                det, tot = table[tag][d]
                cells.append(f"{det}/{tot}")
            else:
                cells.append("—")
        lines.append(f"| {tag} | " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def _section_fcr(fcr_rows):
    lines = ["## 四、FCR 实战挑战率（分入口分组，不聚合）", ""]
    if not fcr_rows:
        lines.append(NO_DATA)
        lines.append("")
        return lines
    sites = sorted({r["site"] for r in fcr_rows})
    groups = sorted({r["group_tag"] for r in fcr_rows}, key=_group_sort_key)
    for idx, site in enumerate(sites, start=1):
        lines.append(f"### 4.{idx} 入口：{site}")
        lines.append("")
        site_rows = [r for r in fcr_rows if r["site"] == site]
        outcomes = sorted({r["outcome"] for r in site_rows})
        lines.append("| 组 | " + " | ".join(outcomes) + " | 合计 |")
        lines.append("|---" * (len(outcomes) + 2) + "|")
        for tag in groups:
            grp = [r for r in site_rows if r["group_tag"] == tag]
            if not grp:
                continue
            counts = {o: sum(1 for r in grp if r["outcome"] == o) for o in outcomes}
            cells = [str(counts[o]) if counts[o] else "0" for o in outcomes]
            lines.append(f"| {tag} | " + " | ".join(cells) + f" | {len(grp)} |")
        lines.append("")
        # v3 score 分布（score 非空的记录，按组分桶）
        score_groups = {}
        for r in site_rows:
            if r["score"] is not None:
                score_groups.setdefault(r["group_tag"], []).append(str(r["score"]))
        if score_groups:
            lines.append("v3 score 分布：")
            lines.append("")
            lines.append("| 组 | 分桶 → 次数 |")
            lines.append("|---|---|")
            for tag in sorted(score_groups, key=_group_sort_key):
                buckets = {}
                for s in score_groups[tag]:
                    buckets[s] = buckets.get(s, 0) + 1
                dist = "；".join(f"{b} × {buckets[b]}" for b in sorted(buckets))
                lines.append(f"| {tag} | {dist} |")
            lines.append("")
    return lines


def _section_control_diff(clr_rows, fcr_rows):
    lines = ["## 五、对照组差异（受测组 vs A-native vs B-extension）", ""]
    if not clr_rows and not fcr_rows:
        lines.append(NO_DATA)
        lines.append("")
        return lines
    compare_groups = TEST_GROUPS + CONTROL_GROUPS

    # 5.1 CLR 并排
    lines.append("### 5.1 CLR 并排")
    lines.append("")
    summary = _clr_summary(clr_rows)
    present = [g for g in compare_groups if g in summary]
    if present:
        lines.append("| 组 | 角色 | 命中数 | 检查数 | 跳过数 |")
        lines.append("|---|---|---|---|---|")
        for tag in present:
            role = "受测组" if tag in TEST_GROUPS else "对照组"
            s = summary[tag]
            lines.append(f"| {tag} | {role} | {s['hits']} | {s['total']} | {s['skipped']} |")
    else:
        lines.append(NO_DATA)
    lines.append("")

    # 5.2 FCR 并排（逐入口，各组结果分布并列行，不聚合）
    lines.append("### 5.2 FCR 并排")
    lines.append("")
    sites = sorted({r["site"] for r in fcr_rows})
    present_fcr = [g for g in compare_groups
                   if any(r["group_tag"] == g for r in fcr_rows)]
    if not sites or not present_fcr:
        lines.append(NO_DATA)
    else:
        for site in sites:
            lines.append(f"入口 {site}：")
            lines.append("")
            lines.append("| 组 | 结果分布（outcome × 次数） | 合计 |")
            lines.append("|---|---|---|")
            for tag in present_fcr:
                grp = [r for r in fcr_rows
                       if r["site"] == site and r["group_tag"] == tag]
                if not grp:
                    continue
                dist_map = {}
                for r in grp:
                    key = r["outcome"] if r["score"] is None else f"{r['outcome']}[{r['score']}]"
                    dist_map[key] = dist_map.get(key, 0) + 1
                dist = "；".join(f"{k} × {dist_map[k]}" for k in sorted(dist_map))
                lines.append(f"| {tag} | {dist} | {len(grp)} |")
            lines.append("")
    return lines


def _section_conclusion(clr_rows, edr_rows, fcr_rows):
    lines = ["## 六、结论", ""]
    if not clr_rows and not edr_rows and not fcr_rows:
        lines.append(f"{INSUFFICIENT}：三指标均无记录，不给出结论。")
        lines.append("")
        return lines

    # CLR：有数据时按目标 0 陈述事实
    summary = _clr_summary(clr_rows)
    test_hits = {g: summary[g]["hits"] for g in TEST_GROUPS if g in summary}
    if not test_hits:
        lines.append(f"- CLR：{INSUFFICIENT}（受测组无 R-Gate 评测记录）。")
    elif all(h == 0 for h in test_hits.values()):
        detail = "、".join(f"{g} 0 命中" for g in test_hits)
        lines.append(f"- CLR：受测组达成零命中目标（{detail}）。")
    else:
        detail = "、".join(f"{g} {h} 命中" for g, h in test_hits.items())
        lines.append(f"- CLR：受测组存在命中，未达成零命中目标（{detail}），"
                     "须定位根因层并回归复测至零。")

    # EDR：三维度均有记录且 detected 全 0 才算 3/3
    test_edr = [r for r in edr_rows if r["group_tag"] in TEST_GROUPS]
    if not test_edr:
        lines.append(f"- EDR：{INSUFFICIENT}（受测组无记录）。")
    else:
        dims = {r["dimension"] for r in test_edr}
        detected = sum(int(r["detected"]) for r in test_edr)
        if dims >= {"headless", "bot", "vm"} and detected == 0:
            lines.append("- EDR：受测组 3/3 通过（headless/bot/vm 全部未识别）。")
        elif detected == 0:
            lines.append(f"- EDR：{INSUFFICIENT}（已录维度 {sorted(dims)} 未被识别，"
                         "三维度记录不全）。")
        else:
            lines.append(f"- EDR：受测组被识别 {detected} 次，未通过；"
                         "失败面与证据须归入 CLR 清单复核。")

    # FCR：每入口每组 N ≥ 10 才有足够样本
    test_fcr = [r for r in fcr_rows if r["group_tag"] in TEST_GROUPS]
    if not test_fcr:
        lines.append(f"- FCR：{INSUFFICIENT}（受测组无记录）。")
    else:
        pair_n = {}
        for r in test_fcr:
            key = (r["site"], r["group_tag"])
            pair_n[key] = pair_n.get(key, 0) + 1
        short = [f"{site}/{tag} N={n}" for (site, tag), n in sorted(pair_n.items())
                 if n < FCR_MIN_N]
        if short:
            lines.append(f"- FCR：{INSUFFICIENT}（{'、'.join(short)}，"
                         f"每入口每组需 N ≥ {FCR_MIN_N}）；现有分布见第四节，"
                         "达到样本量前不作通过性判断。")
        else:
            lines.append("- FCR：受测组各入口样本量达标，分布见第四节；"
                         "FCR 只作分入口报告，不与 CLR/EDR 聚合。")

    lines.append("")
    lines.append("> 口径声明：CLR/EDR/FCR 三指标独立测量、独立报告，不聚合成分数；"
                 "CLR 结论仅在同清单版本间可比。")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_report(db_path: str) -> str:
    """读取 probe.db，返回六节中文 Markdown 报告全文。

    库文件不存在 / 空库 / 缺表均不报错，各节输出"暂无数据"。
    """
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    conn = _connect(db_path)
    if conn is None:
        captures, clr_rows, fcr_rows, edr_rows = [], [], [], []
    else:
        try:
            captures = _load_captures(conn)
            clr_rows = _load_clr_reports(conn)
            fcr_rows = _load_fcr(conn)
            edr_rows = _load_edr(conn)
        finally:
            conn.close()

    lines = []
    lines += _section_header(captures, clr_rows, now)
    lines += _section_clr(clr_rows)
    lines += _section_edr(edr_rows)
    lines += _section_fcr(fcr_rows)
    lines += _section_control_diff(clr_rows, fcr_rows)
    lines += _section_conclusion(clr_rows, edr_rows, fcr_rows)
    return "\n".join(lines)


def main(argv=None) -> int:
    """CLI：--db probe.db --out report.md（--out 缺省时输出到 stdout）。"""
    parser = argparse.ArgumentParser(
        prog="tishen-report",
        description="从 probe.db 生成 M4 对抗测试 Markdown 报告",
    )
    parser.add_argument("--db", required=True, help="probe.db 路径（SPEC-M4 §4）")
    parser.add_argument("--out", default=None, help="输出 Markdown 路径（缺省 stdout）")
    args = parser.parse_args(argv)

    md = build_report(args.db)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        sys.stdout.write(md + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
