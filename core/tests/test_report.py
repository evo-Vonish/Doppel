"""T4 report.py 测试（SPEC-M4 §6/§7：report ≥6 条含空库）。

fixture 按 SPEC-M4 §4 建 captures/clr_reports/fcr_results/edr_results 四表并插样例数据。

import 说明：core/tishen/adversarial/__init__.py 由 Coder A（m4-rgate 分支）创建，
本分支尚无该文件；Python 3 命名空间包机制下 `from tishen.adversarial import report`
可直接导入（conftest 已把 core/ 加入 sys.path），合并 A 分支后无需改动。
"""

import json
import sqlite3

import pytest

from tishen.adversarial import report

CHECKLIST_VERSION = "clr-checklist-v1"

DDL = """
CREATE TABLE captures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_tag TEXT NOT NULL,
  persona_id TEXT,
  entry TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE clr_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  capture_id INTEGER NOT NULL REFERENCES captures(id),
  report TEXT NOT NULL
);
CREATE TABLE fcr_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_tag TEXT NOT NULL, persona_id TEXT,
  site TEXT NOT NULL,
  outcome TEXT NOT NULL,
  score TEXT,
  recorded_at TEXT NOT NULL, note TEXT
);
CREATE TABLE edr_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_tag TEXT NOT NULL, persona_id TEXT,
  dimension TEXT NOT NULL,
  detected INTEGER NOT NULL,
  evidence TEXT, recorded_at TEXT NOT NULL
);
"""

PAYLOAD = json.dumps({"capture_version": 1}, ensure_ascii=False)


def _clr_json(hits, total=78, skipped=None):
    return json.dumps({
        "checklist_version": CHECKLIST_VERSION,
        "total": total,
        "hits": hits,
        "passed": total - len(hits) - len(skipped or []),
        "skipped": skipped or [],
    }, ensure_ascii=False)


HIT_EXAMPLE = {
    "check_id": "CLR-UA-01",
    "assertion": "UA 声称的浏览器主版本须在 Sec-CH-UA brands 中出现",
    "severity": "critical",
    "evidence": {"navigator.userAgent": "Mozilla/5.0 ... Chrome/138", "sec_ch_ua.brands": "Chromium 137"},
}

SKIP_EXAMPLE = {"check_id": "CLR-NET-03", "reason": "field_missing"}


def _insert_capture(cur, group, persona=None, entry="probe"):
    cur.execute(
        "INSERT INTO captures (group_tag, persona_id, entry, captured_at, payload)"
        " VALUES (?, ?, ?, ?, ?)",
        (group, persona, entry, "2026-07-29T03:00:00Z", PAYLOAD),
    )
    return cur.lastrowid


def _make_full_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.executescript(DDL)
    # captures × clr_reports：T-cold 1 命中 + 1 跳过；T-warm/A-native 零命中；B-extension 2 命中
    cid = _insert_capture(cur, "T-cold", persona="p-cold")
    cur.execute("INSERT INTO clr_reports (capture_id, report) VALUES (?, ?)",
                (cid, _clr_json([HIT_EXAMPLE], skipped=[SKIP_EXAMPLE])))
    cid = _insert_capture(cur, "T-warm", persona="p-warm")
    cur.execute("INSERT INTO clr_reports (capture_id, report) VALUES (?, ?)",
                (cid, _clr_json([])))
    cid = _insert_capture(cur, "A-native")
    cur.execute("INSERT INTO clr_reports (capture_id, report) VALUES (?, ?)",
                (cid, _clr_json([])))
    cid = _insert_capture(cur, "B-extension")
    cur.execute("INSERT INTO clr_reports (capture_id, report) VALUES (?, ?)",
                (cid, _clr_json([HIT_EXAMPLE, {**HIT_EXAMPLE, "check_id": "CLR-GPU-02"}])))
    # fcr_results：recaptcha_v3 带 score 分桶（T-cold ×12 / T-warm ×2 / 对照组若干），
    # turnstile 无 score；分入口分组不聚合
    for i in range(12):
        cur.execute(
            "INSERT INTO fcr_results (group_tag, persona_id, site, outcome, score,"
            " recorded_at, note) VALUES (?, ?, ?, ?, ?, ?, NULL)",
            ("T-cold", "p-cold", "recaptcha_v3", "score_bucket",
             "0.3" if i < 8 else "0.5", "2026-07-29T04:00:00Z"),
        )
    for group, site, outcome, score in [
        ("T-warm", "recaptcha_v3", "score_bucket", "0.9"),
        ("T-warm", "recaptcha_v3", "score_bucket", "0.7"),
        ("A-native", "recaptcha_v3", "score_bucket", "0.9"),
        ("B-extension", "recaptcha_v3", "score_bucket", "0.1"),
        ("T-cold", "turnstile", "pass", None),
        ("T-cold", "turnstile", "challenged", None),
        ("T-warm", "turnstile", "pass", None),
        ("A-native", "turnstile", "pass", None),
        ("B-extension", "turnstile", "blocked", None),
    ]:
        cur.execute(
            "INSERT INTO fcr_results (group_tag, persona_id, site, outcome, score,"
            " recorded_at, note) VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (group, None, site, outcome, score, "2026-07-29T04:00:00Z"),
        )
    # edr_results：三维度；T-cold 全 0（3/3），B-extension bot 被识别 1 次
    for dim in ("headless", "bot", "vm"):
        cur.execute(
            "INSERT INTO edr_results (group_tag, persona_id, dimension, detected,"
            " evidence, recorded_at) VALUES (?, ?, ?, ?, NULL, ?)",
            ("T-cold", "p-cold", dim, 0, "2026-07-29T05:00:00Z"),
        )
    cur.execute(
        "INSERT INTO edr_results (group_tag, persona_id, dimension, detected,"
        " evidence, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("B-extension", None, "bot", 1, "fingerprint demo: bot=certain",
         "2026-07-29T05:00:00Z"),
    )
    conn.commit()
    conn.close()


@pytest.fixture
def full_db(tmp_path):
    db = tmp_path / "probe.db"
    _make_full_db(str(db))
    return str(db)


@pytest.fixture
def empty_db(tmp_path):
    db = tmp_path / "probe.db"
    sqlite3.connect(str(db)).close()  # 零表空库
    return str(db)


# ---------------------------------------------------------------------------
# 1. 六节齐全
# ---------------------------------------------------------------------------

SECTION_MARKS = ["## 一、头部", "## 二、CLR", "## 三、EDR", "## 四、FCR",
                 "## 五、对照组差异", "## 六、结论"]


def test_six_sections_present(full_db):
    md = report.build_report(full_db)
    for mark in SECTION_MARKS:
        assert mark in md, f"缺少章节 {mark}"


# ---------------------------------------------------------------------------
# 2. CLR 汇总 + 命中明细
# ---------------------------------------------------------------------------

def test_clr_summary_and_hits(full_db):
    md = report.build_report(full_db)
    # 汇总行：组 × 命中/检查/跳过
    assert "| T-cold | 1 | 1 | 78 | 1 |" in md
    assert "| B-extension | 1 | 2 | 78 | 0 |" in md
    # 命中明细：check_id / assertion / severity / 证据字段
    assert "CLR-UA-01" in md
    assert "UA 声称的浏览器主版本须在 Sec-CH-UA brands 中出现" in md
    assert "critical" in md
    assert "navigator.userAgent=" in md
    assert "sec_ch_ua.brands=" in md


# ---------------------------------------------------------------------------
# 3. EDR 表：组 × 维度 detected 计数
# ---------------------------------------------------------------------------

def test_edr_table_counts(full_db):
    md = report.build_report(full_db)
    assert "| T-cold | 0/1 | 0/1 | 0/1 |" in md  # 三维度全未识别
    # B-extension 只有 bot 维度 1 次被识别，其余维度无记录为 —
    assert "| B-extension | — | 1/1 | — |" in md
    assert "3/3" in md  # 结论段：T-cold 三维度全 0


# ---------------------------------------------------------------------------
# 4. FCR 分桶表分组正确（分入口不聚合）
# ---------------------------------------------------------------------------

def test_fcr_bucketing_grouped_by_site(full_db):
    md = report.build_report(full_db)
    # 两个入口各自独立成节
    assert "入口：recaptcha_v3" in md
    assert "入口：turnstile" in md
    # recaptcha_v3：T-cold 12 次 score_bucket
    assert "| T-cold | 12 | 12 |" in md
    # v3 score 分布：T-cold 0.3×8 + 0.5×4
    assert "| T-cold | 0.3 × 8；0.5 × 4 |" in md
    # turnstile：outcome 计数分列（blocked/challenged/pass），T-cold = 0/1/1 合计 2
    assert "| T-cold | 0 | 1 | 1 | 2 |" in md
    assert "| B-extension | 1 | 0 | 0 | 1 |" in md
    # 不跨入口聚合：turnstile 的 pass 不得计入 recaptcha_v3 行
    v3_section = md.split("入口：recaptcha_v3")[1].split("入口：turnstile")[0]
    assert "pass" not in v3_section.split("v3 score")[0]


# ---------------------------------------------------------------------------
# 5. 空库 / 缺表 / 路径不存在降级
# ---------------------------------------------------------------------------

def test_empty_db_degrades(empty_db):
    md = report.build_report(empty_db)
    for mark in SECTION_MARKS:
        assert mark in md
    assert md.count("暂无数据") >= 4
    assert "样本不足" in md


def test_missing_tables_degrade(tmp_path):
    db = tmp_path / "probe.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(DDL.split("CREATE TABLE fcr_results")[0])  # 只有 captures+clr_reports
    conn.commit()
    conn.close()
    md = report.build_report(str(db))
    for mark in SECTION_MARKS:
        assert mark in md


def test_nonexistent_db_path(tmp_path):
    md = report.build_report(str(tmp_path / "nope.db"))
    assert "暂无数据" in md and "样本不足" in md
    assert not (tmp_path / "nope.db").exists()  # 只读打开，不创建文件


# ---------------------------------------------------------------------------
# 6. 清单版本读取
# ---------------------------------------------------------------------------

def test_checklist_version_in_header(full_db):
    md = report.build_report(full_db)
    assert f"- 清单版本：{CHECKLIST_VERSION}" in md


def test_checklist_version_no_data(empty_db):
    md = report.build_report(empty_db)
    assert "- 清单版本：暂无数据" in md


# ---------------------------------------------------------------------------
# 7. 对照组并排段
# ---------------------------------------------------------------------------

def test_control_group_side_by_side(full_db):
    md = report.build_report(full_db)
    sec5 = md.split("## 五、对照组差异")[1].split("## 六、结论")[0]
    # CLR 并排：四组俱全且角色标注正确
    for tag, role in [("T-cold", "受测组"), ("T-warm", "受测组"),
                      ("A-native", "对照组"), ("B-extension", "对照组")]:
        assert f"| {tag} | {role} |" in sec5
    # FCR 并排：同入口下受测组与对照组并列行
    fcr_side = sec5.split("5.2 FCR 并排")[1]
    for tag in ("T-cold", "A-native", "B-extension"):
        assert f"| {tag} |" in fcr_side
    assert "score_bucket[0.3] × 8" in fcr_side  # 分桶级分布并排


# ---------------------------------------------------------------------------
# 8. 结论段：数据不足写"样本不足"，有数据按目标陈述
# ---------------------------------------------------------------------------

def test_conclusion_insufficient_fcr_sample(tmp_path):
    db = tmp_path / "probe.db"
    conn = sqlite3.connect(str(db))
    cur = conn.cursor()
    cur.executescript(DDL)
    cid = _insert_capture(cur, "T-cold", persona="p")
    cur.execute("INSERT INTO clr_reports (capture_id, report) VALUES (?, ?)",
                (cid, _clr_json([])))
    # FCR 只有 3 条（<10）→ 样本不足
    for _ in range(3):
        cur.execute(
            "INSERT INTO fcr_results (group_tag, site, outcome, score, recorded_at)"
            " VALUES ('T-cold', 'turnstile', 'pass', NULL, '2026-07-29T04:00:00Z')")
    conn.commit()
    conn.close()
    md = report.build_report(str(db))
    assert "- CLR：受测组达成零命中目标" in md
    assert "- FCR：样本不足" in md


def test_conclusion_clr_hit_reported(full_db):
    md = report.build_report(full_db)
    # T-cold 有 1 命中 → 不得宣称零命中
    assert "未达成零命中目标" in md


# ---------------------------------------------------------------------------
# 9. CLI 写文件成功
# ---------------------------------------------------------------------------

def test_cli_writes_file(full_db, tmp_path):
    out = tmp_path / "report.md"
    rc = report.main(["--db", full_db, "--out", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# 替身（Tishen）M4 对抗测试报告")
    for mark in SECTION_MARKS:
        assert mark in text


def test_cli_stdout(full_db, capsys):
    rc = report.main(["--db", full_db])
    assert rc == 0
    assert "## 六、结论" in capsys.readouterr().out
