# test_resbench_report.py —— R4 资源基线报告用例（SPEC-M5 §7/§8）
#
# import 说明：resbench 子包无 __init__.py（归 Coder X 所有，本分支不得新建），
# `from tishen.resbench import report` 走 PEP 420 命名空间包子包机制即可工作
# （conftest 已把 core/ 入 sys.path）；合并 X 分支后本文件无需任何改动。
# 测试只按 SPEC-M5 §2 Schema 自建临时 SQLite fixture，不 import X 的模块。

import os
import sqlite3

from tishen.resbench import report
from tishen.resbench.report import build_report, main

SCHEMA = """
CREATE TABLE runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario TEXT NOT NULL, loadset_version TEXT, image_version TEXT,
  started_at TEXT NOT NULL, note TEXT
);
CREATE TABLE samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id), ts TEXT NOT NULL,
  mem_bytes INTEGER NOT NULL, mem_limit_bytes INTEGER, cpu_pct REAL NOT NULL
);
CREATE TABLE boots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER REFERENCES runs(id), boot_mode TEXT NOT NULL,
  total_ms INTEGER, recorded_at TEXT NOT NULL
);
CREATE TABLE boot_segments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  boot_id INTEGER NOT NULL REFERENCES boots(id),
  segment TEXT NOT NULL, elapsed_ms INTEGER NOT NULL
);
CREATE TABLE fidelity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER REFERENCES runs(id), sleep_mode TEXT NOT NULL,
  item TEXT NOT NULL, pass INTEGER NOT NULL, evidence TEXT, checked_at TEXT NOT NULL
);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""

SECTION_TITLES = ["## 一、头部", "## 二、MEM", "## 三、CPU", "## 四、BOOT",
                  "## 五、SLEEP", "## 六、结论与调度建议"]


def _make_db(tmp_path, name="resbench.db", schema=SCHEMA):
    db = str(tmp_path / name)
    conn = sqlite3.connect(db)
    if schema:
        conn.executescript(schema)
    conn.commit()
    return db, conn


def _add_run_with_samples(conn, scenario, mem_list, cpu_list):
    cur = conn.execute(
        "INSERT INTO runs (scenario, started_at) VALUES (?, '2026-07-29T00:00:00')",
        (scenario,))
    run_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO samples (run_id, ts, mem_bytes, cpu_pct) VALUES (?, 't', ?, ?)",
        [(run_id, m, c) for m, c in zip(mem_list, cpu_list)])
    conn.commit()
    return run_id


# 1. 六节齐全：一节不缺
def test_report_has_all_six_sections(tmp_path):
    db, conn = _make_db(tmp_path)
    _add_run_with_samples(conn, "idle_5tab", [1_500_000_000] * 10, [10.0] * 10)
    conn.close()
    md = build_report(db)
    for title in SECTION_TITLES:
        assert title in md


# 2. 空库降级：库文件存在但无表 → 各节"暂无数据"，不报错
def test_report_empty_db_degrades(tmp_path):
    db, conn = _make_db(tmp_path, schema=None)
    conn.close()
    md = build_report(db)
    for title in SECTION_TITLES:
        assert title in md
    assert md.count("暂无数据") >= 4
    assert "验收线" not in md  # 无数据不出判定


# 3. 库文件不存在：不创建、不报错
def test_report_missing_db_path(tmp_path):
    db = str(tmp_path / "nonexistent.db")
    md = build_report(db)
    for title in SECTION_TITLES:
        assert title in md
    assert not os.path.exists(db)


# 4. 缺表降级：只有 runs/samples，BOOT/SLEEP 节各自"暂无数据"，MEM/CPU 正常
def test_report_missing_tables_degrade(tmp_path):
    db, conn = _make_db(tmp_path, schema="""
CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scenario TEXT NOT NULL,
  loadset_version TEXT, image_version TEXT, started_at TEXT NOT NULL, note TEXT);
CREATE TABLE samples (id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id), ts TEXT NOT NULL,
  mem_bytes INTEGER NOT NULL, mem_limit_bytes INTEGER, cpu_pct REAL NOT NULL);
""")
    _add_run_with_samples(conn, "video_play", [800_000_000] * 5, [30.0] * 5)
    conn.close()
    md = build_report(db)
    assert "| video_play | 5 |" in md  # MEM/CPU 表有数据
    boot_pos = md.index("## 四、BOOT")
    sleep_pos = md.index("## 五、SLEEP")
    assert "暂无数据" in md[boot_pos:sleep_pos]
    assert "暂无数据" in md[sleep_pos:md.index("## 六、")]


# 5. 2GB 判定：p95 ≤ 2147483648 → 验收线成立（含等值边界）
def test_2gb_verdict_pass(tmp_path):
    db, conn = _make_db(tmp_path)
    _add_run_with_samples(conn, "idle_5tab", [report.MEM_LIMIT_BYTES], [1.0])
    conn.close()
    md = build_report(db)
    assert "验收线成立" in md


# 6. 2GB 判定：p95 超线 → 验收线未达成；无 idle_5tab 数据 → 暂无数据
def test_2gb_verdict_fail_and_no_data(tmp_path):
    db, conn = _make_db(tmp_path)
    _add_run_with_samples(conn, "idle_5tab", [report.MEM_LIMIT_BYTES + 1], [1.0])
    conn.close()
    md = build_report(db)
    assert "验收线未达成" in md
    assert "不悄悄挪线" in md

    db2, conn2 = _make_db(tmp_path, name="resbench2.db")
    _add_run_with_samples(conn2, "video_play", [100_000_000], [1.0])
    conn2.close()
    md2 = build_report(db2)
    mem_pos = md2.index("## 二、MEM")
    cpu_pos = md2.index("## 三、CPU")
    assert "暂无数据" in md2[mem_pos:cpu_pos]
    assert "验收线成立" not in md2
    assert "验收线未达成" not in md2


# 7. MEM 人性化显示：GiB/MiB 一位小数；p95 最近秩口径
def test_mem_humanized_and_p95(tmp_path):
    db, conn = _make_db(tmp_path)
    # 20 个样本，p95 = 第 19 个（nearest-rank）
    mems = [100 * 1024 ** 2 + i * 1024 ** 2 for i in range(20)]  # 100..119 MiB
    _add_run_with_samples(conn, "idle_5tab", mems, [1.0] * 20)
    _add_run_with_samples(conn, "stream_encode", [3 * 1024 ** 3], [99.0])
    conn.close()
    md = build_report(db)
    assert "| idle_5tab | 20 | 109.5 MiB | 118.0 MiB | 119.0 MiB |" in md
    assert "3.0 GiB" in md


# 8. BOOT 瀑布表差分：段均差分 = 相邻段平均累计 elapsed_ms 之差，按 §5 段序
def test_boot_waterfall_diff(tmp_path):
    db, conn = _make_db(tmp_path)
    for total, segs in [(900, [("entry", 0), ("lint_recheck", 100), ("chrome_launch", 900)]),
                        (1100, [("entry", 0), ("lint_recheck", 200), ("chrome_launch", 1100)])]:
        cur = conn.execute(
            "INSERT INTO boots (run_id, boot_mode, total_ms, recorded_at)"
            " VALUES (NULL, 'cold-create', ?, '2026-07-29T01:00:00')", (total,))
        boot_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO boot_segments (boot_id, segment, elapsed_ms) VALUES (?, ?, ?)",
            [(boot_id, s, e) for s, e in segs])
    conn.execute(
        "INSERT INTO boots (run_id, boot_mode, total_ms, recorded_at)"
        " VALUES (NULL, 'warm-resume', 800, '2026-07-29T02:00:00')")
    conn.commit()
    conn.close()
    md = build_report(db)
    assert "| cold-create | 2 | 1000 | 1100 |" in md
    assert "| warm-resume | 1 | 800 | 800 |" in md
    # 瀑布表：entry 均 0（差分 0）→ lint_recheck 均 150（差分 150）→ chrome_launch 均 1000（差分 850）
    assert "| entry | 0 | 0 |" in md
    assert "| lint_recheck | 150 | 150 |" in md
    assert "| chrome_launch | 1000 | 850 |" in md
    assert md.index("| entry | 0 | 0 |") < md.index("| lint_recheck | 150 | 150 |") \
        < md.index("| chrome_launch | 1000 | 850 |")


# 9. BOOT 无 cold-create 段数据 → 瀑布表"样本不足"
def test_boot_waterfall_insufficient(tmp_path):
    db, conn = _make_db(tmp_path)
    conn.execute(
        "INSERT INTO boots (run_id, boot_mode, total_ms, recorded_at)"
        " VALUES (NULL, 'cold-start', 4000, '2026-07-29T01:00:00')")
    conn.commit()
    conn.close()
    md = build_report(db)
    assert "| cold-start | 1 | 4000 | 4000 |" in md
    assert "样本不足" in md


# 10. SLEEP 矩阵：通过/失败/无数据三态 + 失败证据明细
def test_sleep_matrix_and_failure_evidence(tmp_path):
    db, conn = _make_db(tmp_path)
    rows = [
        ("pause", "url_preserved", 1, "URL 一致", "2026-07-29T10:00:00"),
        ("pause", "cookies_preserved", 0, "cookie 丢失", "2026-07-29T10:00:00"),
        ("stop", "url_preserved", 1, "manual: 已确认", "2026-07-29T11:00:00"),
    ]
    conn.executemany(
        "INSERT INTO fidelity (run_id, sleep_mode, item, pass, evidence, checked_at)"
        " VALUES (NULL, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()
    md = build_report(db)
    assert "| pause | 通过 | 失败 |" in md or "| pause | 失败 | 通过 |" in md
    # 列序按清单 id：url_preserved 在 cookies_preserved 前；stop 行 cookies 无数据
    assert "| pause | 通过 | 失败 |" in md
    assert "| stop | 通过 | 无数据 |" in md
    assert "| pause | cookies_preserved | cookie 丢失 | 2026-07-29T10:00:00 |" in md
    # 结论节点名失败项
    assert "pause/cookies_preserved" in md


# 11. 调度建议：meta 缺失 → "缺宿主机内存 meta，不出建议"；有 meta → 模板段含 Z
def test_scheduling_advice_meta_gate(tmp_path):
    db, conn = _make_db(tmp_path)
    _add_run_with_samples(conn, "idle_5tab", [1_073_741_824] * 10, [5.0] * 10)  # p95=1GiB
    conn.close()
    md = build_report(db)
    assert "缺宿主机内存 meta，不出建议" in md
    assert "理论活跃上限约" not in md

    db2, conn2 = _make_db(tmp_path, name="resbench2.db")
    _add_run_with_samples(conn2, "idle_5tab", [1_073_741_824] * 10, [5.0] * 10)
    conn2.execute("INSERT INTO meta (key, value) VALUES ('host_mem_gb', '16')")
    conn2.commit()
    conn2.close()
    md2 = build_report(db2)
    assert "按实测 p95 1.0 GiB，宿主机 16 GB 内存理论活跃上限约 16" in md2
    assert "缺宿主机内存 meta，不出建议" not in md2


# 12. CLI main：--out 写文件、无 --out 走 stdout，均返回 0
def test_main_cli_out_and_stdout(tmp_path, capsys):
    db, conn = _make_db(tmp_path)
    _add_run_with_samples(conn, "idle_5tab", [1_000_000_000], [5.0])
    conn.close()

    out = str(tmp_path / "report.md")
    assert main(["--db", db, "--out", out]) == 0
    with open(out, encoding="utf-8") as f:
        md = f.read()
    for title in SECTION_TITLES:
        assert title in md

    assert main(["--db", db]) == 0
    captured = capsys.readouterr()
    assert "## 一、头部" in captured.out
