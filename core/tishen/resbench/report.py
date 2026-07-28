"""R4 资源基线报告生成器（SPEC-M5 §7）。

从 resbench.db（SPEC-M5 §2 定死 Schema）只读读取 runs / samples / boots /
boot_segments / fidelity / meta，生成六节中文 Markdown 报告：

1. 头部：生成时间、runs 数、meta 表键值（loadset/镜像版本）、各 scenario 样本量；
2. MEM：scenario × (n, mean, p95, max)（字节人性化 MiB/GiB 一位小数）+ 2GB 判定段
   （基准 scenario=idle_5tab 的 p95 ≤ 2147483648 → "验收线成立"，超线 → "验收线未达成"，
   无数据 → "暂无数据"）；
3. CPU：scenario × (n, mean, max)；
4. BOOT：boot_mode × (n, total_ms mean/max) + cold-create 分解瀑布表（segment ×
   平均 elapsed_ms 差分，按 §5 段序）；数据不足写"样本不足"；
5. SLEEP：sleep_mode × item 的 pass 矩阵（通过/失败/无数据）+ 失败证据明细；
6. 结论与调度建议段：只陈述数据事实（p95/判定/保真失败项）；调度建议在有完整
   idle_5tab 数据时输出模板段（"按实测 p95 X，宿主机 Y GB 内存理论活跃上限约 Z"，
   Z 由 meta[host_mem_gb] 计算），缺 meta 写"缺宿主机内存 meta，不出建议"，不编造结论。

口径纪律（实施方案 §一）：MEM/CPU/BOOT/SLEEP 四指标独立测量、独立报告，永不聚合；
max 为 1s 采样粒度内 max；p95 取最近秩（nearest-rank）口径。
只读模式开库（mode=ro），库文件不存在不创建不报错，空库/缺表各节输出"暂无数据"。
"""

import argparse
import math
import os
import sqlite3
import sys
from datetime import datetime, timezone

# SPEC-M5 §7：2GB 验收线阈值（字节）
MEM_LIMIT_BYTES = 2147483648
# 基准判定 scenario（实施方案 §一 MEM 口径）
BASELINE_SCENARIO = "idle_5tab"
# §5 段名枚举（顺序固定），cold-create 瀑布表按此序
SEGMENT_ORDER = [
    "entry", "lint_recheck", "timezone", "locale", "fonts",
    "xrandr", "fcitx5", "observ", "neko", "chrome_launch",
]
# scenario 展示顺序，未知名排最后
SCENARIO_ORDER = ["idle_5tab", "video_play", "stream_encode", "boot", "sleep"]
BOOT_MODE_ORDER = ["cold-create", "cold-start", "warm-resume"]
SLEEP_MODE_ORDER = ["pause", "stop", "checkpoint"]
# SPEC-M5 §6 清单 id（报告列序与之对齐）
FIDELITY_ITEMS = [
    "url_preserved", "scroll_preserved", "cookies_preserved",
    "localstorage_preserved", "form_state_preserved", "video_resumable",
    "observ_gap_normal",
]

NO_DATA = "暂无数据"
INSUFFICIENT = "样本不足"
MIB = 1024 ** 2
GIB = 1024 ** 3


# ---------------------------------------------------------------------------
# 读库（只读，缺表降级）
# ---------------------------------------------------------------------------

def _connect(db_path):
    """只读打开库；文件不存在返回 None（调用方按空库处理，不创建不报错）。"""
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


def _load_runs(conn):
    if "runs" not in _table_names(conn):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT id, scenario, loadset_version, image_version, started_at, note"
        " FROM runs ORDER BY id"
    )]


def _load_samples(conn):
    """samples JOIN runs → [{scenario, mem_bytes, mem_limit_bytes, cpu_pct}]；缺表返回 []。"""
    tables = _table_names(conn)
    if "samples" not in tables or "runs" not in tables:
        return []
    return [dict(r) for r in conn.execute(
        "SELECT r.scenario AS scenario, s.mem_bytes AS mem_bytes,"
        " s.mem_limit_bytes AS mem_limit_bytes, s.cpu_pct AS cpu_pct"
        " FROM samples s JOIN runs r ON r.id = s.run_id ORDER BY s.id"
    )]


def _load_boots(conn):
    if "boots" not in _table_names(conn):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT id, run_id, boot_mode, total_ms, recorded_at FROM boots ORDER BY id"
    )]


def _load_segments(conn):
    """boot_segments JOIN boots → [{boot_id, boot_mode, segment, elapsed_ms}]。"""
    tables = _table_names(conn)
    if "boot_segments" not in tables or "boots" not in tables:
        return []
    return [dict(r) for r in conn.execute(
        "SELECT s.boot_id AS boot_id, b.boot_mode AS boot_mode,"
        " s.segment AS segment, s.elapsed_ms AS elapsed_ms"
        " FROM boot_segments s JOIN boots b ON b.id = s.boot_id ORDER BY s.id"
    )]


def _load_fidelity(conn):
    if "fidelity" not in _table_names(conn):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT run_id, sleep_mode, item, pass, evidence, checked_at"
        " FROM fidelity ORDER BY id"
    )]


def _load_meta(conn):
    if "meta" not in _table_names(conn):
        return {}
    return {r["key"]: r["value"] for r in conn.execute(
        "SELECT key, value FROM meta ORDER BY key"
    )}


# ---------------------------------------------------------------------------
# 统计与格式化
# ---------------------------------------------------------------------------

def _p95(values):
    """最近秩（nearest-rank）p95：升序第 ceil(0.95*n) 个（1 基）。"""
    if not values:
        return None
    ordered = sorted(values)
    idx = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[idx]


def _human_bytes(n):
    """字节人性化：≥1GiB 用 GiB、≥1MiB 用 MiB（均一位小数），再小直接给字节。"""
    if n is None:
        return "—"
    if n >= GIB:
        return f"{n / GIB:.1f} GiB"
    if n >= MIB:
        return f"{n / MIB:.1f} MiB"
    return f"{n} B"


def _scenario_sort_key(name):
    return (SCENARIO_ORDER.index(name) if name in SCENARIO_ORDER
            else len(SCENARIO_ORDER), name)


def _ordered_scenarios(samples):
    return sorted({s["scenario"] for s in samples}, key=_scenario_sort_key)


def _mem_stats(samples):
    """{scenario: {"n", "mean", "p95", "max"}}（mem_bytes 原始字节）。"""
    by_scenario = {}
    for s in samples:
        by_scenario.setdefault(s["scenario"], []).append(s["mem_bytes"])
    stats = {}
    for name, vals in by_scenario.items():
        stats[name] = {
            "n": len(vals),
            "mean": sum(vals) / len(vals),
            "p95": _p95(vals),
            "max": max(vals),
        }
    return stats


def _cpu_stats(samples):
    """{scenario: {"n", "mean", "max"}}（cpu_pct）。"""
    by_scenario = {}
    for s in samples:
        by_scenario.setdefault(s["scenario"], []).append(s["cpu_pct"])
    stats = {}
    for name, vals in by_scenario.items():
        stats[name] = {
            "n": len(vals),
            "mean": sum(vals) / len(vals),
            "max": max(vals),
        }
    return stats


def _gb_verdict(mem_stats):
    """2GB 判定 → (状态词, idle_5tab p95 原始字节|None)。"""
    stat = mem_stats.get(BASELINE_SCENARIO)
    if not stat:
        return NO_DATA, None
    p95 = stat["p95"]
    if p95 <= MEM_LIMIT_BYTES:
        return "验收线成立", p95
    return "验收线未达成", p95


# ---------------------------------------------------------------------------
# 六节渲染
# ---------------------------------------------------------------------------

def _section_header(runs, samples, meta, now):
    lines = ["# 替身（Tishen）M5 资源基线报告", ""]
    lines.append("## 一、头部")
    lines.append("")
    lines.append(f"- 生成时间：{now}")
    lines.append(f"- runs 数：{len(runs)}")
    if meta:
        lines.append("- meta 表键值：")
        lines.append("")
        lines.append("| key | value |")
        lines.append("|---|---|")
        for k in sorted(meta):
            lines.append(f"| {k} | {meta[k]} |")
    else:
        lines.append(f"- meta 表键值：{NO_DATA}")
    counts = {}
    for s in samples:
        counts[s["scenario"]] = counts.get(s["scenario"], 0) + 1
    lines.append("")
    if counts:
        lines.append("- 各 scenario 样本量（samples 条数）：")
        lines.append("")
        lines.append("| scenario | 样本量 |")
        lines.append("|---|---|")
        for name in sorted(counts, key=_scenario_sort_key):
            lines.append(f"| {name} | {counts[name]} |")
    else:
        lines.append(f"- 各 scenario 样本量：{NO_DATA}")
    lines.append("")
    return lines


def _section_mem(mem_stats):
    lines = ["## 二、MEM 内存基线（判定线 p95 ≤ 2GB）", ""]
    if not mem_stats:
        lines.append(NO_DATA)
        lines.append("")
        return lines
    lines.append("### 2.1 采样窗统计（mean / p95 / max，max 为 1s 粒度内 max）")
    lines.append("")
    lines.append("| scenario | n | mean | p95 | max |")
    lines.append("|---|---|---|---|---|")
    for name in sorted(mem_stats, key=_scenario_sort_key):
        s = mem_stats[name]
        lines.append(
            f"| {name} | {s['n']} | {_human_bytes(round(s['mean']))}"
            f" | {_human_bytes(s['p95'])} | {_human_bytes(s['max'])} |"
        )
    lines.append("")
    lines.append("### 2.2 2GB 判定段")
    lines.append("")
    verdict, p95 = _gb_verdict(mem_stats)
    if p95 is None:
        lines.append(f"- 基准 scenario={BASELINE_SCENARIO}：{NO_DATA}")
    else:
        lines.append(
            f"- 基准 scenario={BASELINE_SCENARIO} 的 p95 = {_human_bytes(p95)}"
            f"（{p95} 字节），判定线 {MEM_LIMIT_BYTES} 字节（2GiB）：**{verdict}**。"
        )
        if verdict == "验收线未达成":
            lines.append("- 超线处置：按实施方案 §四进入预案评估（标签休眠/编码降档/"
                         "硬编/内存硬限），不悄悄挪线。")
    lines.append("")
    return lines


def _section_cpu(cpu_stats):
    lines = ["## 三、CPU 处理器基线（相对全部核的百分比）", ""]
    if not cpu_stats:
        lines.append(NO_DATA)
        lines.append("")
        return lines
    lines.append("| scenario | n | mean | max |")
    lines.append("|---|---|---|---|")
    for name in sorted(cpu_stats, key=_scenario_sort_key):
        s = cpu_stats[name]
        lines.append(f"| {name} | {s['n']} | {s['mean']:.1f}% | {s['max']:.1f}% |")
    lines.append("")
    return lines


def _section_boot(boots, segments):
    lines = ["## 四、BOOT 启动时延（三档分口径，不混报）", ""]
    if not boots:
        lines.append(NO_DATA)
        lines.append("")
        return lines

    # 4.1 三档汇总（total_ms 可空：缺段时不编造总和，均值/最大只统计非空行）
    lines.append("### 4.1 三档汇总（total_ms mean/max）")
    lines.append("")
    by_mode = {}
    for b in boots:
        by_mode.setdefault(b["boot_mode"], []).append(b["total_ms"])

    def mode_key(m):
        return (BOOT_MODE_ORDER.index(m) if m in BOOT_MODE_ORDER
                else len(BOOT_MODE_ORDER), m)

    lines.append("| boot_mode | n | total_ms mean | total_ms max |")
    lines.append("|---|---|---|---|")
    for mode in sorted(by_mode, key=mode_key):
        totals = [t for t in by_mode[mode] if t is not None]
        n = len(by_mode[mode])
        if totals:
            mean = f"{sum(totals) / len(totals):.0f}"
            mx = str(max(totals))
        else:
            mean = mx = "—"
        lines.append(f"| {mode} | {n} | {mean} | {mx} |")
    lines.append("")

    # 4.2 cold-create 分解瀑布表（segment × 平均 elapsed_ms 差分，按 §5 段序）
    lines.append("### 4.2 cold-create 分解瀑布表（平均累计 elapsed_ms 与段均差分）")
    lines.append("")
    cold_ids = {b["id"] for b in boots if b["boot_mode"] == "cold-create"}
    cold_segs = [s for s in segments if s["boot_id"] in cold_ids]
    if not cold_ids or not cold_segs:
        lines.append(INSUFFICIENT)
        lines.append("")
        return lines
    # 每段在各 boot 上的 elapsed_ms 均值
    seg_vals = {}
    for s in cold_segs:
        seg_vals.setdefault(s["segment"], []).append(s["elapsed_ms"])
    seg_mean = {seg: sum(v) / len(v) for seg, v in seg_vals.items()}
    present = [seg for seg in SEGMENT_ORDER if seg in seg_mean]
    present += sorted(seg for seg in seg_mean if seg not in SEGMENT_ORDER)
    lines.append("| segment | 平均累计 elapsed_ms | 段均耗时（差分 ms） |")
    lines.append("|---|---|---|")
    prev = 0.0
    for seg in present:
        mean = seg_mean[seg]
        lines.append(f"| {seg} | {mean:.0f} | {mean - prev:.0f} |")
        prev = mean
    lines.append("")
    return lines


def _section_sleep(fidelity_rows):
    lines = ["## 五、SLEEP 休眠-唤醒保真清单（逐条通过/失败，不设聚合分）", ""]
    if not fidelity_rows:
        lines.append(NO_DATA)
        lines.append("")
        return lines

    def mode_key(m):
        return (SLEEP_MODE_ORDER.index(m) if m in SLEEP_MODE_ORDER
                else len(SLEEP_MODE_ORDER), m)

    modes = sorted({r["sleep_mode"] for r in fidelity_rows}, key=mode_key)
    items = [i for i in FIDELITY_ITEMS
             if any(r["item"] == i for r in fidelity_rows)]
    items += sorted({r["item"] for r in fidelity_rows if r["item"] not in FIDELITY_ITEMS})

    # 5.1 pass 矩阵：同 (sleep_mode, item) 多行时任一失败 → 失败，否则有通过 → 通过
    lines.append("### 5.1 pass 矩阵（sleep_mode × item）")
    lines.append("")
    cell = {}
    for r in fidelity_rows:
        key = (r["sleep_mode"], r["item"])
        cur = cell.get(key)
        cell[key] = "失败" if r["pass"] == 0 else (cur or "通过")
        if cur == "失败":
            cell[key] = "失败"
    lines.append("| sleep_mode | " + " | ".join(items) + " |")
    lines.append("|---" * (len(items) + 1) + "|")
    for mode in modes:
        cells = [cell.get((mode, it), "无数据") for it in items]
        lines.append(f"| {mode} | " + " | ".join(cells) + " |")
    lines.append("")

    # 5.2 失败证据明细
    lines.append("### 5.2 失败证据明细")
    lines.append("")
    fails = [r for r in fidelity_rows if r["pass"] == 0]
    if not fails:
        lines.append("全部已录判定均通过。")
    else:
        lines.append("| sleep_mode | item | evidence | checked_at |")
        lines.append("|---|---|---|---|")
        for r in fails:
            lines.append(
                f"| {r['sleep_mode']} | {r['item']} | {r['evidence'] or '—'}"
                f" | {r['checked_at']} |"
            )
    lines.append("")
    return lines


def _section_conclusion(mem_stats, fidelity_rows, meta):
    lines = ["## 六、结论与调度建议", ""]

    verdict, p95 = _gb_verdict(mem_stats)
    if p95 is None:
        lines.append(f"- MEM：{INSUFFICIENT}（基准 scenario={BASELINE_SCENARIO} 无采样），"
                     "不作 2GB 判定。")
    else:
        lines.append(
            f"- MEM：基准 scenario={BASELINE_SCENARIO} p95 = {_human_bytes(p95)}"
            f"（{p95} 字节），2GB 判定：{verdict}。"
        )

    if not fidelity_rows:
        lines.append(f"- SLEEP：{INSUFFICIENT}（无 fidelity 记录）。")
    else:
        fails = sorted({(r["sleep_mode"], r["item"])
                        for r in fidelity_rows if r["pass"] == 0})
        if fails:
            detail = "、".join(f"{m}/{i}" for m, i in fails)
            lines.append(f"- SLEEP：存在保真失败项（{detail}），证据见第五节，"
                         "须定位修复后复测。")
        else:
            modes = sorted({r["sleep_mode"] for r in fidelity_rows})
            lines.append(f"- SLEEP：已录判定全部通过（sleep_mode：{'、'.join(modes)}）。")

    lines.append("")
    lines.append("### 调度建议")
    lines.append("")
    if p95 is None:
        lines.append(f"{INSUFFICIENT}：无完整 {BASELINE_SCENARIO} 数据，不出建议。")
    else:
        host_mem_gb = meta.get("host_mem_gb")
        try:
            host_mem_gb = float(host_mem_gb)
        except (TypeError, ValueError):
            host_mem_gb = None
        if host_mem_gb is None or host_mem_gb <= 0:
            lines.append("缺宿主机内存 meta，不出建议。")
        elif p95 <= 0:
            lines.append(f"{INSUFFICIENT}：p95 非正值，不出建议。")
        else:
            # Z = 宿主机内存（GB 按 GiB=1024³ 字节计）整除实测 p95
            z = int(host_mem_gb * GIB // p95)
            lines.append(
                f"- 按实测 p95 {_human_bytes(p95)}，宿主机 {host_mem_gb:g} GB 内存"
                f"理论活跃上限约 {z} 个替身（Z = 宿主机内存整除实测 p95，"
                "GB 按 1024³ 字节计；未含宿主机系统自身占用，上线前须再扣预留）。"
            )
    lines.append("")
    lines.append("> 口径声明：MEM/CPU/BOOT/SLEEP 四指标独立测量、独立报告，不聚合；"
                 "MEM 取容器总内存（docker stats cgroup 口径），max 为 1s 粒度内 max。")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_report(db_path: str) -> str:
    """读取 resbench.db，返回六节中文 Markdown 报告全文。

    库文件不存在 / 空库 / 缺表均不报错，各节输出"暂无数据"。
    """
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    conn = _connect(db_path)
    if conn is None:
        runs, samples, boots, segments, fidelity_rows, meta = [], [], [], [], [], {}
    else:
        try:
            runs = _load_runs(conn)
            samples = _load_samples(conn)
            boots = _load_boots(conn)
            segments = _load_segments(conn)
            fidelity_rows = _load_fidelity(conn)
            meta = _load_meta(conn)
        finally:
            conn.close()

    mem_stats = _mem_stats(samples)
    cpu_stats = _cpu_stats(samples)

    lines = []
    lines += _section_header(runs, samples, meta, now)
    lines += _section_mem(mem_stats)
    lines += _section_cpu(cpu_stats)
    lines += _section_boot(boots, segments)
    lines += _section_sleep(fidelity_rows)
    lines += _section_conclusion(mem_stats, fidelity_rows, meta)
    return "\n".join(lines)


def main(argv=None) -> int:
    """CLI：--db resbench.db --out report.md（--out 缺省时输出到 stdout）。"""
    parser = argparse.ArgumentParser(
        prog="tishen-resbench-report",
        description="从 resbench.db 生成 M5 资源基线 Markdown 报告",
    )
    parser.add_argument("--db", required=True, help="resbench.db 路径（SPEC-M5 §2）")
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
