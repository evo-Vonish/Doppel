# test_resbench_fidelity.py —— R3 休眠保真校验用例（SPEC-M5 §6/§8）
#
# import 说明：resbench 子包无 __init__.py（__init__.py 归 Coder X 所有，
# 本分支不得新建），`from tishen.resbench import fidelity` 走 PEP 420 命名空间
# 包子包机制即可工作（conftest 已把 core/ 入 sys.path）；合并 X 分支（补上
# __init__.py）后本文件无需任何改动。

import sqlite3

import pytest

from tishen.resbench import fidelity
from tishen.resbench.fidelity import (
    FIDELITY_CHECKLIST_V1,
    run_fidelity,
    write_fidelity,
)


def _all_pass_evidence():
    ev = {item: True for item in FIDELITY_CHECKLIST_V1 if item != "observ_gap_normal"}
    ev["observ_gap_normal"] = {"gap_expected": 3, "gap_actual": 2}
    return ev


# 1. 全过：failed/skipped 皆空，版本与 total 契约固定
def test_run_fidelity_all_pass():
    r = run_fidelity(_all_pass_evidence())
    assert r["checklist_version"] == "fidelity-v1"
    assert r["total"] == 7
    assert r["failed"] == []
    assert r["skipped"] == []
    assert [it["item"] for it in r["items"]] == FIDELITY_CHECKLIST_V1
    assert all(it["pass"] is True for it in r["items"])


# 2. 部分失败：失败项入 failed 且不入 skipped
def test_run_fidelity_partial_failure():
    ev = _all_pass_evidence()
    ev["cookies_preserved"] = {"pass": False, "detail": "cookie 值变化"}
    r = run_fidelity(ev)
    assert r["failed"] == ["cookies_preserved"]
    assert r["skipped"] == []
    item = next(it for it in r["items"] if it["item"] == "cookies_preserved")
    assert item["pass"] is False
    assert "cookie 值变化" in item["evidence"]


# 3. 证据缺失 → pass=None 记 skipped，不判失败
def test_run_fidelity_missing_evidence_skipped_not_failed():
    r = run_fidelity({})
    assert r["failed"] == []
    assert r["skipped"] == FIDELITY_CHECKLIST_V1
    assert all(it["pass"] is None for it in r["items"])
    assert all(it["evidence"] for it in r["items"])  # 有占位说明，不留空


# 4. observ_gap_normal 预期内（gap_actual ≤ gap_expected）→ 通过
def test_observ_gap_expected_gap_passes():
    r = run_fidelity({"observ_gap_normal": {"gap_expected": 5, "gap_actual": 5}})
    item = next(it for it in r["items"] if it["item"] == "observ_gap_normal")
    assert item["pass"] is True
    assert "gap_expected=5" in item["evidence"]
    assert "gap_actual=5" in item["evidence"]
    assert "observ_gap_normal" not in r["failed"]


# 5. observ_gap_normal 异常增长（gap_actual > gap_expected）→ 失败；缺两数 → skipped
def test_observ_gap_abnormal_fails_and_missing_numbers_skipped():
    r = run_fidelity({"observ_gap_normal": {"gap_expected": 2, "gap_actual": 9}})
    assert r["failed"] == ["observ_gap_normal"]

    r2 = run_fidelity({"observ_gap_normal": {"gap_actual": 9}})
    assert "observ_gap_normal" in r2["skipped"]
    assert "observ_gap_normal" not in r2["failed"]

    r3 = run_fidelity({"observ_gap_normal": "not-a-dict"})
    assert "observ_gap_normal" in r3["skipped"]
    assert "observ_gap_normal" not in r3["failed"]


# 6. 自定义 checklist 子集：total 跟随，未列项不出现
def test_run_fidelity_custom_checklist():
    r = run_fidelity({"url_preserved": True}, checklist=["url_preserved", "scroll_preserved"])
    assert r["total"] == 2
    assert [it["item"] for it in r["items"]] == ["url_preserved", "scroll_preserved"]
    assert r["skipped"] == ["scroll_preserved"]


# 7. 写库：只写有判定行（skipped 不落库），返回行数与库内容一致
def test_write_fidelity_rows(tmp_path):
    db = str(tmp_path / "resbench.db")
    ev = _all_pass_evidence()
    ev["video_resumable"] = {"pass": False, "detail": "manual: 视频未续播"}
    del ev["form_state_preserved"]  # 证据缺失 → skipped → 不落库
    r = run_fidelity(ev)

    n = write_fidelity(db, 42, "pause", r, "2026-07-29T10:00:00")
    assert n == 6  # 7 条 - 1 条 skipped

    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT run_id, sleep_mode, item, pass, evidence, checked_at FROM fidelity"
    ).fetchall()
    conn.close()
    assert len(rows) == 6
    by_item = {row[2]: row for row in rows}
    assert "form_state_preserved" not in by_item
    assert by_item["url_preserved"][3] == 1
    assert by_item["video_resumable"][3] == 0
    assert "manual:" in by_item["video_resumable"][4]
    assert by_item["video_resumable"][0] == 42
    assert by_item["video_resumable"][1] == "pause"
    assert by_item["video_resumable"][5] == "2026-07-29T10:00:00"


# 8. 全部 skipped → 写 0 行，不报错
def test_write_fidelity_all_skipped_writes_zero(tmp_path):
    db = str(tmp_path / "resbench.db")
    r = run_fidelity({})
    assert write_fidelity(db, None, "stop", r, "2026-07-29T10:00:00") == 0


# 9. sleep_mode 三档枚举值原样落库（stop/checkpoint 与 pause 同路径）
@pytest.mark.parametrize("mode", ["pause", "stop", "checkpoint"])
def test_write_fidelity_sleep_modes(tmp_path, mode):
    db = str(tmp_path / "resbench.db")
    r = run_fidelity({"url_preserved": True})
    assert write_fidelity(db, None, mode, r, "2026-07-29T10:00:00") == 1
    conn = sqlite3.connect(db)
    modes = [row[0] for row in conn.execute("SELECT sleep_mode FROM fidelity")]
    conn.close()
    assert modes == [mode]
