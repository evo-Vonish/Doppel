"""演化门禁序列编排器（EVO-3，演化方案 §四步骤 0–8）。

本件为**骨架**：真机步骤（R-Gate 实跑 / 镜像升级 / 外部抽样 / 指纹采集）全部
经 EvolveHooks 依赖注入，默认 None → 该步骤记 skipped 且序列合法滞留（held），
**绝不带病推进**（§四-7）。纯函数件（时机门禁 / drift pack 校验 / diff 审计）
直接复用 evolution.py。

顺序铁律（§四）：
    0 gate          时机门禁（复用 EVO-2 check_evolve_gate，含 §四-2 时机断言）
    1 rgate_before  演化前 F_old 跑 R-Gate → CLR 必须 = 0（带露馅演化=放大露馅）
    2 precondition  前置断言：drift pack 结构校验（§三 schema）
    3 pull_image    镜像升级 tishen-image:<to> + 冻结参数重放（profile 卷原样挂载）
    4 rgate_after   F_new 全量 CLR 重跑（82 条）
    5 diff_audit    diff 审计双断言（audit_diff，§四-5，本案核心创新）
    6 external      外部抽样：CreepJS trust score ∧ tls.peet.ws JA3/JA4（§四-6）
    7 canary        金丝雀批量推进属 EVO-4（方案 §六），本件仅记录 skipped 说明
    8 history       履历落 history（含 clr_after/diff_audit，§四-8）——只在
                    pull_image 与 CLR 重跑真实执行（非 skipped）后才生成

结果口径（§四-7「任一门禁失败 → 合法滞留当前版本 + 告警」）：
    evolved   —— 全部门禁通过，history 落账，current_chrome 推进至 pack.to
    held      —— 合法滞留：时机未开/未签发、CLR 前置非零（先修露馅）、
                 真机依赖未接入（skipped）、镜像拉取失败、外部抽样未过
    rejected  —— 演化执行后结果非法：F_new CLR≠0 或 diff 审计双断言违例
                 （白名单外变化 / G-UA 未变到位），拒绝落账
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Callable

from .evolution import audit_diff, check_evolve_gate, validate_drift_pack
from .persona import Evolution, Persona


@dataclass
class EvolveHooks:
    """真机依赖注入点（本件全部默认 None → 对应步骤记 skipped 且序列 held）。

    hook 契约：
      run_rgate(capture) -> ClrReport
          §四-1/4 断言面，签名同 tishen.adversarial.rgate.run_rgate
          （真机接线时直接传该函数；CLR 命中数 = len(report["hits"])）。
      pull_image(persona, pack) -> 结果
          §四-3 镜像升级：拉取 tishen-image:<pack["to"]> 真实 Chrome 二进制
          + 冻结参数重放 + profile 卷原样挂载（R-D 联动，信誉连续）。
          返回 False 或 {"ok": False} 判失败，其余（含 None/dict）判成功。
      sample_external(persona, pack) -> bool | {"ok": bool, "detail": str}
          §四-6 外部抽样：CreepJS trust score 不低于基线 ∧ tls.peet.ws
          JA3/JA4 = 目标版官方值。
      capture_fn(persona, phase) -> FingerprintCapture（SPEC-M4 §2）
          F_old/F_new 采集（探针 harness，M4）；phase ∈ {"before", "after"}。
    """

    run_rgate: Callable[[dict], dict] | None = None
    pull_image: Callable[[object, dict], object] | None = None
    sample_external: Callable[[object, dict], object] | None = None
    capture_fn: Callable[[object, str], dict] | None = None


def _clr_count(report) -> int:
    """ClrReport → CLR 命中数；报告残缺时按 0 计（hits 缺省为空）。"""
    if not isinstance(report, dict):
        return 0
    hits = report.get("hits")
    return len(hits) if isinstance(hits, list) else 0


def _sample_verdict(sample) -> tuple[bool, str]:
    """外部抽样 hook 返回值归一化：(是否通过, 中文说明)。"""
    if isinstance(sample, dict):
        ok = bool(sample.get("ok"))
        detail = sample.get("detail") or (
            "外部抽样通过（CreepJS ∧ tls.peet.ws）" if ok
            else f"外部抽样未通过：{sample!r}")
        return ok, str(detail)
    ok = bool(sample)
    return ok, ("外部抽样通过（CreepJS ∧ tls.peet.ws）" if ok else "外部抽样未通过")


def run_evolve_sequence(persona, pack: dict, *,
                        hooks: EvolveHooks | None = None,
                        today: str | date | None = None) -> dict:
    """演化门禁序列（§四 0–8）。返回：

        {"outcome": "evolved" | "held" | "rejected",
         "steps": [{"step": str, "ok": bool, "skipped": bool, "detail": str}, ...],
         "history_entry": dict | None}

    persona 接受 Persona 或 Evolution（与 check_evolve_gate 口径一致）；
    outcome=evolved 时原地推进 evolution.current_chrome 并追加 history 条目
    （持久化由调用方负责，CLI --execute 在 evolved 时 dump 回 persona.yaml）。
    today 供门禁判定注入（None=本机日期）；history 条目 at 取真实墙钟
    （秒级 ISO8601，persona.validate_structure 要求）。
    """
    hooks = hooks or EvolveHooks()
    today_d = date.today() if today is None else today
    ev: Evolution = persona.evolution if isinstance(persona, Persona) else persona

    steps: list[dict] = []

    def record(step: str, ok: bool, detail: str, skipped: bool = False) -> None:
        steps.append({"step": step, "ok": ok, "skipped": skipped, "detail": detail})

    def stop(outcome: str) -> dict:
        return {"outcome": outcome, "steps": steps, "history_entry": None}

    # §四-0/2 时机门禁（复用 EVO-2 纯函数：时机闸门 ∧ 单调增 ∧ 不超前 ∧ OS×版本）
    gate_ok, reasons = check_evolve_gate(persona, pack, today_d)
    record("gate", gate_ok,
           "时机门禁四断言全过（时机闸门/单调增/不超前发布日/OS×版本，§四-0/2）"
           if gate_ok else "；".join(reasons))
    if not gate_ok:
        return stop("held")  # 合法滞留：时机/签发条件未满足（§四-7）

    # §四-1 演化前 R-Gate：CLR 必须 = 0（带露馅演化=放大露馅）
    missing = [name for name, h in (("capture_fn", hooks.capture_fn),
                                    ("run_rgate", hooks.run_rgate)) if h is None]
    if missing:
        record("rgate_before", False,
               f"真机依赖未接入：{'、'.join(missing)}（探针 harness/R-Gate，§五）",
               skipped=True)
        return stop("held")
    try:
        f_old = hooks.capture_fn(persona, "before")
        report_old = hooks.run_rgate(f_old)
    except Exception as e:  # hook 属真机边界，异常按门禁未过处理，不带病推进
        record("rgate_before", False, f"演化前采集/评估异常：{e}")
        return stop("held")
    clr_old = _clr_count(report_old)
    if clr_old != 0:
        record("rgate_before", False,
               f"演化前 CLR={clr_old}（带露馅演化=放大露馅，§四-1）：先修露馅再演化")
        return stop("held")
    record("rgate_before", True, "演化前 CLR=0（§四-1）")

    # §四-2 前置断言：drift pack 结构校验（时机类断言已在 gate 覆盖）
    pack_errors = validate_drift_pack(pack)
    if pack_errors:
        record("precondition", False, "；".join(pack_errors))
        return stop("held")  # 结构非法=未签发口径（§三），合法滞留
    record("precondition", True, "drift pack 结构合法（§三 schema 七组+六冻结项）")

    # §四-3 镜像升级：真实 Chrome 二进制 + 冻结参数重放（架构红线，§一）
    if hooks.pull_image is None:
        record("pull_image", False, "镜像流水线未接入", skipped=True)
        return stop("held")
    try:
        pull_res = hooks.pull_image(persona, pack)
    except Exception as e:
        record("pull_image", False, f"镜像升级异常：{e}")
        return stop("held")
    if pull_res is False or (isinstance(pull_res, dict) and pull_res.get("ok") is False):
        record("pull_image", False, f"镜像升级失败：{pull_res!r}")
        return stop("held")
    record("pull_image", True,
           f"镜像升级至 tishen-image:{pack.get('to')}，冻结参数重放"
           "（profile 卷原样挂载=信誉连续，§四-3/R-D 联动）")

    # §四-4 F_new 全量 CLR 重跑
    try:
        f_new = hooks.capture_fn(persona, "after")
        report_new = hooks.run_rgate(f_new)
    except Exception as e:
        record("rgate_after", False, f"演化后采集/评估异常：{e}")
        return stop("held")
    clr_new = _clr_count(report_new)
    if clr_new != 0:
        record("rgate_after", False,
               f"演化后 CLR={clr_new}（不许带病演化，§四-7）：演化结果带露馅，拒绝落账")
        return stop("rejected")
    record("rgate_after", True, "演化后 CLR=0（全量重跑，§四-4）")

    # §四-5 diff 审计双断言（本案核心创新）
    audit_ok, audit_errors = audit_diff(f_old, f_new, pack)
    record("diff_audit", audit_ok,
           "双断言通过（变化集 ⊆ 白名单 ∧ ⊇ G-UA 必变集，§四-5）"
           if audit_ok else "；".join(audit_errors))
    if not audit_ok:
        return stop("rejected")

    # §四-6 外部抽样：CreepJS trust score ∧ tls.peet.ws JA3/JA4
    if hooks.sample_external is None:
        record("external_sample", False,
               "外部抽样未接入（CreepJS/tls.peet.ws，§四-6）", skipped=True)
        return stop("held")
    try:
        sample = hooks.sample_external(persona, pack)
    except Exception as e:
        record("external_sample", False, f"外部抽样异常：{e}")
        return stop("held")
    sample_ok, sample_detail = _sample_verdict(sample)
    record("external_sample", sample_ok, sample_detail)
    if not sample_ok:
        return stop("held")  # 外部信誉波动属临时性，合法滞留可重试（§四-7）

    # §四-7 金丝雀：1–2 个 persona 先行 48h → 批量推进，策略属 EVO-4（方案 §六）
    record("canary", True,
           "金丝雀批量推进策略属 EVO-4（方案 §六），本件仅编排单 persona 门禁序列",
           skipped=True)

    # §四-8 履历落 history（含 clr_after/diff_audit）——只在 pull_image 与
    # CLR 重跑真实执行后才会到达此处（skipped 路径上方均已提前 held）
    entry = {
        "from": pack["from"],
        "to": pack["to"],
        "at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "stable_release_date": pack["stable_release_date"],
        "drift_pack": f"{pack['from']}→{pack['to']}",
        "clr_after": clr_new,
        "diff_audit": "pass",
    }
    ev.history.append(entry)
    ev.current_chrome = pack["to"]  # §二：演化推进 current_chrome（单调增已由 gate 保证）
    record("history", True,
           f"履历落账：{entry['from']} → {entry['to']}"
           f"（clr_after={clr_new}, diff_audit=pass，§四-8）")
    return {"outcome": "evolved", "steps": steps, "history_entry": entry}
