"""漂移包（drift pack）schema 与演化时机门禁（演化方案 §三 / §四步骤 0·2）。

本模块只含**纯函数与数据件骨架**，不执行真实演化（门禁序列编排属 EVO-3）：

    DRIFT_PACK_SCHEMA                       —— drift pack JSON 结构约定（§三）
    validate_drift_pack(pack) -> list[str]  —— 结构校验（中文错误列表）
    check_evolve_gate(persona_evolution, pack, today) -> tuple[bool, list[str]]
        时机门禁（§四步骤 0/2）：时机闸门 ∧ 单调增 ∧ 不超前 stable 发布日
        ∧ OS×版本组合合法（版本目录表）
    build_drift_pack_skeleton(from_ver, to_ver, release_date) -> dict
        生成器骨架：七组空壳 + invariants 六冻结项预填。
        G-API 真值来自 chromestatus/MDN BCD 机器 diff（联网件，本件不联网，
        留 TODO 由镜像流水线补全）；G-TLS/G-REND 真值来自真机抽测 harness
        对比（§三生成方式），骨架仅给占位结构，未签发前禁止演化。

架构红线（方案 §一）：演化 = 换真实 Chrome 镜像 + 重放冻结参数，本模块不产出
任何字符串级指纹模拟数据（仅 G-UA 整组替换的备用路径在 §三被允许，亦不在骨架内编造）。
"""

from __future__ import annotations

from datetime import date, datetime

from .persona import Evolution, Persona, _chrome_version_key, _is_date_str

# ---------------------------------------------------------------------------
# drift pack schema 约定（§三）：七字段组与 CLR 清单 v1.1 共享分组词汇表
# ---------------------------------------------------------------------------

DRIFT_PACK_GROUPS = ["G-UA", "G-JSVER", "G-API", "G-TLS", "G-H2", "G-REND", "G-ENV"]

# 六冻结项（§三 invariants）：演化中绝不允许变化的 persona 冻结参数
DRIFT_PACK_INVARIANTS = [
    "os_platform", "gpu_renderer", "fonts", "screen", "region", "farbling_seed",
]

DRIFT_PACK_SCHEMA = {
    "version": 1,
    "required_top": ["from", "to", "stable_release_date", "groups", "invariants"],
    "groups": DRIFT_PACK_GROUPS,
    # 各组键结构（§三 JSON 示例）；值为占位说明，真值由流水线 diff/真机抽测填充
    "group_keys": {
        "G-UA": ["ua_string", "sec_ch_ua", "ua_reduction_kv"],
        "G-JSVER": ["v8_features_changed"],
        "G-API": ["added", "removed", "source"],
        "G-TLS": ["ja4_expected"],
        "G-H2": ["h2_fingerprint_changed"],
        "G-REND": ["canvas_changed", "angle_backend_changed"],
        "G-ENV": [],
    },
    "invariants": DRIFT_PACK_INVARIANTS,
}

# 版本目录表：OS×版本合法组合（§四步骤 2 末条断言、§五多版本目录）。
# 当前内置 Chrome 138/139/140 三行**示例**；正式目录由镜像流水线随每版 stable
# 发布机器生成（既有 DEFAULT_STABLE_CHROME 机制升级为多版本目录），本表仅支撑
# 门禁纯函数的判定路径与测试。表外版本一律拒绝（未签发版本对禁止演化，§三）。
CHROME_VERSION_CATALOG = {
    "138.0.7204.0": {"os": ["linux"], "stable_release_date": "2026-07-08"},
    "139.0.7258.0": {"os": ["linux"], "stable_release_date": "2026-08-05"},
    "140.0.7312.0": {"os": ["linux"], "stable_release_date": "2026-09-02"},
}


def _as_date(v, field_label: str) -> date | None:
    """YYYY-MM-DD 字符串或 date → date；无法解析返回 None。"""
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    if _is_date_str(v):
        return datetime.strptime(v, "%Y-%m-%d").date()
    return None


# ---------------------------------------------------------------------------
# drift pack 校验（§三）
# ---------------------------------------------------------------------------

def validate_drift_pack(pack) -> list[str]:
    """校验 drift pack JSON 结构，返回中文错误列表（空列表=合法）。

    校验项：顶层必填、from/to 四段版本号且 from<to、stable_release_date 合法日期、
    groups 七组齐全且各组为映射、invariants 含六个冻结项。
    """
    errors: list[str] = []

    def err(field_path: str, msg: str) -> None:
        errors.append(f"{field_path}: {msg}")

    if not isinstance(pack, dict):
        return [f"drift pack 须为 JSON 映射，实际为 {type(pack).__name__}"]

    # 顶层必填
    for key in DRIFT_PACK_SCHEMA["required_top"]:
        if key not in pack:
            err(key, "drift pack 缺少必填字段")

    # from/to：四段版本号且 from<to（漂移方向单调增，§二硬约束）
    from_key = _chrome_version_key(pack.get("from"))
    to_key = _chrome_version_key(pack.get("to"))
    if "from" in pack and from_key is None:
        err("from", f"须为形如 138.0.7204.0 的四段版本号，实际为 {pack.get('from')!r}")
    if "to" in pack and to_key is None:
        err("to", f"须为形如 138.0.7204.0 的四段版本号，实际为 {pack.get('to')!r}")
    if from_key is not None and to_key is not None and from_key >= to_key:
        err("to", f"漂移方向须 from<to，实际 {pack.get('from')!r} → {pack.get('to')!r}")

    # stable_release_date：目标版官方 stable 发布日（不超前约束的基准）
    if "stable_release_date" in pack and not _is_date_str(pack["stable_release_date"]):
        err("stable_release_date",
            f"须为 YYYY-MM-DD 合法日期，实际为 {pack['stable_release_date']!r}")

    # groups：七组齐全，各组为映射
    groups = pack.get("groups")
    if "groups" in pack:
        if not isinstance(groups, dict):
            err("groups", f"须为映射，实际为 {groups!r}")
        else:
            for g in DRIFT_PACK_GROUPS:
                if g not in groups:
                    err(f"groups.{g}", f"七字段组缺少 {g}（与 CLR 清单分组词汇表对齐）")
                elif not isinstance(groups[g], dict):
                    err(f"groups.{g}", f"须为映射，实际为 {groups[g]!r}")

    # invariants：六个冻结项齐全
    invariants = pack.get("invariants")
    if "invariants" in pack:
        if not isinstance(invariants, list):
            err("invariants", f"须为冻结项列表，实际为 {invariants!r}")
        else:
            for inv in DRIFT_PACK_INVARIANTS:
                if inv not in invariants:
                    err("invariants", f"缺少冻结项 {inv}（六冻结项缺一不可）")

    return errors


# ---------------------------------------------------------------------------
# 时机门禁（§四步骤 0/2，纯函数）
# ---------------------------------------------------------------------------

def check_evolve_gate(persona_evolution, pack: dict,
                      today) -> tuple[bool, list[str]]:
    """演化时机门禁：返回 (是否放行, 中文失败原因列表)。

    四条断言（§四步骤 0/2）：
      1. today ≥ schedule.next_upgrade_not_before（时机闸门，未设闸门则放行）
      2. pack.to > persona.evolution.current_chrome（目标版严格高于当前，单调增）
      3. today ≥ pack.stable_release_date（版本不得超前官方 stable 发布日）
      4. OS×版本组合合法（版本目录表 CHROME_VERSION_CATALOG；os 字段来自 persona，
         本期恒 linux；表外版本=未签发，硬拒绝）

    persona_evolution 接受 Persona 或 Evolution：传 Persona 时 os 取自 persona.os.family；
    传 Evolution 时按本期恒 linux 处理。
    today 接受 YYYY-MM-DD 字符串或 date。
    """
    reasons: list[str] = []

    if isinstance(persona_evolution, Persona):
        ev: Evolution = persona_evolution.evolution
        os_family = persona_evolution.os.family
    else:
        ev = persona_evolution
        os_family = "linux"  # 本期 persona os.family 恒 linux（SPEC §2）

    today_date = _as_date(today, "today")
    if today_date is None:
        reasons.append(f"today 须为 YYYY-MM-DD 合法日期，实际为 {today!r}")
        return False, reasons

    # 断言 1：时机闸门（§四步骤 0）
    not_before = ev.schedule.next_upgrade_not_before
    if not_before is not None:
        nb = _as_date(not_before, "next_upgrade_not_before")
        if nb is None:
            reasons.append(
                f"时机闸门日期非法：evolution.schedule.next_upgrade_not_before={not_before!r}")
        elif today_date < nb:
            reasons.append(
                f"时机闸门未开启：today {today_date} 早于 "
                f"next_upgrade_not_before {nb}（delay_model={ev.schedule.delay_model}）")

    # 断言 2：目标版严格高于当前版（单调增，§四步骤 2）
    to_key = _chrome_version_key(pack.get("to")) if isinstance(pack, dict) else None
    current_key = _chrome_version_key(ev.current_chrome)
    if to_key is None:
        reasons.append(f"drift pack 目标版本非法：to={pack.get('to')!r}")
    elif current_key is not None and to_key <= current_key:
        reasons.append(
            f"目标版本 {pack['to']} 未高于当前版本 {ev.current_chrome}（单调增约束）")

    # 断言 3：不超前官方 stable 发布日（§四步骤 2）
    if isinstance(pack, dict):
        srd = _as_date(pack.get("stable_release_date"), "stable_release_date")
        if srd is None:
            reasons.append(
                f"drift pack stable_release_date 非法：{pack.get('stable_release_date')!r}")
        elif today_date < srd:
            reasons.append(
                f"目标版本尚未官方发布：today {today_date} 早于 "
                f"stable_release_date {srd}（不超前约束）")

    # 断言 4：OS×版本组合合法（版本目录表；表外=未签发，硬拒绝）
    if to_key is not None and isinstance(pack, dict):
        to_ver = pack["to"]
        catalog_row = CHROME_VERSION_CATALOG.get(to_ver)
        if catalog_row is None:
            reasons.append(
                f"版本目录表无 {to_ver}：该版本对的 drift pack 未签发，禁止演化（§三）")
        elif os_family not in catalog_row["os"]:
            reasons.append(
                f"OS×版本组合非法：{to_ver} 不支持 os.family={os_family!r}"
                f"（目录表支持 {catalog_row['os']}）")

    return (not reasons), reasons


# ---------------------------------------------------------------------------
# 生成器骨架（§三数据件）
# ---------------------------------------------------------------------------

def build_drift_pack_skeleton(from_ver: str, to_ver: str, release_date: str) -> dict:
    """生成 drift pack 骨架：七组空壳 + invariants 六冻结项预填。

    仅产出**结构骨架**，不编造任何真值：
      - G-UA/G-TLS 字符串占位为 null（真值由目标版真实 Chrome 提取）；
      - G-API.source 预填 "chromestatus diff" 占位——added/removed 真值来自
        chromestatus/MDN BCD 机器 diff（联网件，本件不联网，TODO：流水线补全）；
      - G-TLS/G-REND 真值来自真机抽测 harness 相邻版本对比（§三生成方式，
        TODO：流水线签发时回填）。
    参数非法（版本号格式错、from≥to、日期非法）抛 ValueError。
    """
    from_key = _chrome_version_key(from_ver)
    to_key = _chrome_version_key(to_ver)
    if from_key is None or to_key is None:
        raise ValueError(
            f"from/to 须为形如 138.0.7204.0 的四段版本号，实际 {from_ver!r} → {to_ver!r}")
    if from_key >= to_key:
        raise ValueError(f"漂移方向须 from<to，实际 {from_ver!r} → {to_ver!r}")
    if not _is_date_str(release_date):
        raise ValueError(f"release_date 须为 YYYY-MM-DD 合法日期，实际为 {release_date!r}")

    return {
        "from": from_ver,
        "to": to_ver,
        "stable_release_date": release_date,
        "groups": {
            "G-UA": {"ua_string": None, "sec_ch_ua": None, "ua_reduction_kv": None},
            "G-JSVER": {"v8_features_changed": []},
            "G-API": {
                "added": [],
                "removed": [],
                # TODO(流水线)：chromestatus/MDN BCD 机器 diff 回填真值（联网件）
                "source": "chromestatus diff",
            },
            # TODO(流水线)：真机抽测 harness 相邻版本对比回填 ja4/渲染面真值
            "G-TLS": {"ja4_expected": None},
            "G-H2": {"h2_fingerprint_changed": False},
            "G-REND": {"canvas_changed": False, "angle_backend_changed": False},
            "G-ENV": {},
        },
        "invariants": list(DRIFT_PACK_INVARIANTS),
    }
