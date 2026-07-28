"""R3 休眠-唤醒保真校验（SPEC-M5 §6）。

保真检查为逐条通过/失败清单（fidelity checklist v1），不设聚合分：
- 证据缺失 → pass=None 记 skipped（不判失败）；
- observ_gap_normal 口径与 M3 第四节对齐：暂停期无流量的预期 gap 不算异常，
  evidence 须含 gap_expected / gap_actual 两个数，gap_actual ≤ gap_expected 判通过。

证据字典约定（调用方按 item id 组装）：
- 一般条目：evidence[item] 为 bool，或 {"pass": bool, "detail": str} 字典
  （detail 缺省时用占位说明；pass 为 None 视同证据缺失）；
- observ_gap_normal：evidence["observ_gap_normal"] 为
  {"gap_expected": number, "gap_actual": number, "detail": str(可选)}。

write_fidelity 只写有明确判定的行（pass 非 None）：fidelity 表 pass 列
NOT NULL，skipped 项无判定值，不落库、不编造。
"""

import sqlite3

# SPEC-M5 §6：7 条清单，id 固定、顺序固定
FIDELITY_CHECKLIST_V1 = [
    "url_preserved",
    "scroll_preserved",
    "cookies_preserved",
    "localstorage_preserved",
    "form_state_preserved",
    "video_resumable",
    "observ_gap_normal",
]

CHECKLIST_VERSION = "fidelity-v1"

_NO_EVIDENCE = "证据缺失"
_GAP_ITEM = "observ_gap_normal"


def _eval_generic(item, ev):
    """一般条目判定 → (pass: bool|None, evidence: str)。

    ev 为 bool 或 {"pass": bool|None, "detail": str}；其余形态/缺 pass 视为证据缺失。
    """
    if isinstance(ev, bool):
        return ev, f"探针实测：{ev}"
    if isinstance(ev, dict):
        p = ev.get("pass")
        if p is None:
            return None, str(ev.get("detail") or _NO_EVIDENCE)
        return bool(p), str(ev.get("detail") or f"探针实测：{bool(p)}")
    return None, _NO_EVIDENCE


def _eval_observ_gap(ev):
    """observ_gap_normal：预期 gap（暂停期无流量）不算异常。

    evidence 须含 gap_expected / gap_actual 两数；gap_actual ≤ gap_expected 判通过。
    """
    if not isinstance(ev, dict):
        return None, _NO_EVIDENCE
    expected = ev.get("gap_expected")
    actual = ev.get("gap_actual")
    if not isinstance(expected, (int, float)) or not isinstance(actual, (int, float)):
        return None, str(ev.get("detail") or "缺 gap_expected/gap_actual，证据缺失")
    passed = actual <= expected
    detail = ev.get("detail")
    text = f"gap_expected={expected}，gap_actual={actual}"
    if detail:
        text += f"（{detail}）"
    return passed, text


def run_fidelity(evidence: dict, checklist: list | None = None) -> dict:
    """逐条校验保真清单。

    evidence：调用方按 item id 组装的证据 dict（探针采集值/观测库 gap 统计/人工确认）。
    返回 {"checklist_version": "fidelity-v1", "total": 7,
          "items": [{"item": str, "pass": bool|None, "evidence": str}],
          "failed": [item_id...], "skipped": [item_id...]}
    证据缺失 → pass=None 记 skipped（不判失败）。
    """
    items = checklist if checklist is not None else FIDELITY_CHECKLIST_V1
    evidence = evidence or {}
    out_items = []
    failed = []
    skipped = []
    for item in items:
        ev = evidence.get(item)
        if ev is None:
            passed, text = None, _NO_EVIDENCE
        elif item == _GAP_ITEM:
            passed, text = _eval_observ_gap(ev)
        else:
            passed, text = _eval_generic(item, ev)
        out_items.append({"item": item, "pass": passed, "evidence": text})
        if passed is False:
            failed.append(item)
        elif passed is None:
            skipped.append(item)
    return {
        "checklist_version": CHECKLIST_VERSION,
        "total": len(items),
        "items": out_items,
        "failed": failed,
        "skipped": skipped,
    }


_FIDELITY_DDL = """CREATE TABLE IF NOT EXISTS fidelity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER REFERENCES runs(id),
  sleep_mode TEXT NOT NULL,
  item TEXT NOT NULL,
  pass INTEGER NOT NULL,
  evidence TEXT,
  checked_at TEXT NOT NULL
)"""


def write_fidelity(db_path: str, run_id: int | None, sleep_mode: str, result: dict,
                   checked_at: str) -> int:
    """把 run_fidelity 结果写入 fidelity 表，返回写入行数。

    只写有明确判定的行（pass 为 True/False → 1/0）；skipped（pass=None）项
    无判定值，不落库（pass 列 NOT NULL，不编造）。
    """
    rows = [
        (run_id, sleep_mode, it["item"], 1 if it["pass"] else 0,
         it["evidence"], checked_at)
        for it in result.get("items", [])
        if it.get("pass") is not None
    ]
    if not rows:
        return 0
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_FIDELITY_DDL)
        conn.executemany(
            "INSERT INTO fidelity (run_id, sleep_mode, item, pass, evidence, checked_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return len(rows)
