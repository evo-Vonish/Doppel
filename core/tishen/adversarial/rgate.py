"""R-Gate 运行时一致性 linter（SPEC-M4 §3）。

定位：吃探针采集的 FingerprintCapture JSON，执行 CLR 清单全部断言，
输出命中项与证据。与出厂门禁 linter V1–V10（V-Gate，规格层查 persona.yaml）
互补：V-Gate 查「规格自洽」，R-Gate 查「运行时兑现」。

判定语义（SPEC-M4 §3，一字不动）：
- capture 字段缺失（或为 null）→ 该条记 skipped（reason=field_missing），不计命中；
- 值存在且矛盾 → hit，附实际值证据；
- 值存在且自洽 → 计入 passed。

纯函数，无 I/O，可单测。
"""

from __future__ import annotations

CHECKLIST_VERSION = "clr-checklist-v1"


def _field(check, name):
    """同时兼容 ClrCheck dataclass 与 dict 两种清单条目形态。"""
    if isinstance(check, dict):
        return check[name]
    return getattr(check, name)


def run_rgate(capture: dict, checklist: list | None = None) -> dict:
    """对一份 FingerprintCapture 执行 CLR 清单，返回 ClrReport：

    {"checklist_version": str, "total": int, "hits": [
        {"check_id": str, "assertion": str, "severity": str,
         "evidence": {"<字段路径>": "<实际值>", ...}}],
     "passed": int, "skipped": [{"check_id": str, "reason": "field_missing"}]}

    checklist 为 None 时使用内置 CHECKLIST_V1（clr-checklist-v1）。
    """
    if checklist is None:
        from .clr_checklist_v1 import CHECKLIST_V1
        checklist = CHECKLIST_V1

    hits: list[dict] = []
    skipped: list[dict] = []
    passed = 0

    for check in checklist:
        check_id = _field(check, "id")
        verdict = _field(check, "check")(capture)
        if verdict is None:
            # 所需字段缺失：记 skipped，不计命中（SPEC-M4 §3）
            skipped.append({"check_id": check_id, "reason": "field_missing"})
        elif verdict == "pass":
            passed += 1
        else:
            hits.append({
                "check_id": check_id,
                "assertion": _field(check, "assertion"),
                "severity": _field(check, "severity"),
                "evidence": verdict,
            })

    return {
        "checklist_version": CHECKLIST_VERSION,
        "total": len(checklist),
        "hits": hits,
        "passed": passed,
        "skipped": skipped,
    }
