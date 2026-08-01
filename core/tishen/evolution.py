"""漂移包（drift pack）schema 与演化时机门禁（演化方案 §三 / §四步骤 0·2）。

本模块只含**纯函数与数据件骨架**，不执行真实演化（门禁序列编排属 EVO-3，
见 evolve_seq.py）：

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

EVO-3 扩展（diff 审计器，§四步骤 5，纯函数）：

    GROUP_FIELDS: dict[str, frozenset[str]] —— 七字段组 → FingerprintCapture 键映射表
    diff_captures(old, new) -> dict[str, list[str]]
        两份 capture 递归对比，按七组返回变化字段路径列表
    audit_diff(old, new, pack) -> tuple[bool, list[str]]
        diff 审计双断言（§四-5）：变化字段集 ⊆ drift pack 白名单
        ∧ 变化字段集 ⊇ G-UA 必变集；违例返回中文错误列表

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


# ---------------------------------------------------------------------------
# diff 审计器（EVO-3，§四步骤 5，纯函数）
# ---------------------------------------------------------------------------

# 七字段组 → FingerprintCapture（SPEC-M4 §2，18 顶层键）字段路径映射表。
# 路径为点分前缀：变化路径 p 归属键 k 当且仅当 p == k 或 p 以 "k." 开头；
# 以下划线结尾的键为**前缀标记**（"features.js_" 匹配 features.js_* 一族——
# V8/JS 版本特征扩展键，SPEC-M4 §2 当前 capture 未含该族，为 G-JSVER 预留，
# 与方案 §三 G-JSVER.v8_features_changed 对应）。
# 归属仲裁取最长匹配键（如 tls_assert.h2 先于 tls_assert 命中 G-H2）。
#
# 与 SPEC-M4 §2 的 18 顶层键对齐情况：
#   navigator.userAgent / sec_ch_ua      → G-UA（UA 族，版本升级必变）
#   features.js_*（预留）                → G-JSVER
#   features（其余 API 面）              → G-API
#   tls_assert（ja3/ja4/source）         → G-TLS
#   tls_assert.h2（SPEC-M4 未含，若有）  → G-H2
#   canvas / audio / webgl / fonts       → G-REND（渲染面）
#   screen / intl / webrtc / cross_reads / media / permissions / storage → G-ENV
#   **未覆盖键一律兜底归入 G-ENV**：navigator 其余子键（platform/vendor/
#   languages/hardwareConcurrency 等环境画像）、cdp_traces 及未来新增键。
# capture_version / collected_at 为采集元数据（非指纹面），不参与 diff
# （collected_at 每份采集必不同，纳入会把一切演化误判为 G-ENV 漂移）。
GROUP_FIELDS: dict[str, frozenset[str]] = {
    "G-UA": frozenset({"navigator.userAgent", "sec_ch_ua"}),
    "G-JSVER": frozenset({"features.js_"}),
    "G-API": frozenset({"features"}),
    "G-TLS": frozenset({"tls_assert"}),
    "G-H2": frozenset({"tls_assert.h2"}),
    "G-REND": frozenset({"canvas", "audio", "webgl", "fonts"}),
    "G-ENV": frozenset({
        "screen", "intl", "webrtc", "cross_reads", "media", "permissions",
        "storage",
    }),
}

# 采集元数据键（SPEC-M4 §2 前两键）：非指纹面，diff 一律排除
CAPTURE_METADATA_KEYS = frozenset({"capture_version", "collected_at"})

# G-UA 必变集（§四-5「该变的必须变到位」）：Chrome 版本升级时 UA 字符串与
# Sec-CH-UA 族（brands/fullVersionList/uaFullVersion 含版本号）必须同步变化，
# 缺一即「演化没换到位」（只换镜像而 UA 面没跟上，或反之，都是跨层矛盾源，§一）。
G_UA_MUST_CHANGE = frozenset({"navigator.userAgent", "sec_ch_ua"})

_MISSING = object()  # 缺失键哨兵（缺失≠值为 None：缺失算变化，None 是合法值）


def _match_key(path: str, key: str) -> bool:
    """字段路径 path 是否归属映射键 k（精确 / "k." 前缀 / 下划线前缀标记）。"""
    if key.endswith("_"):  # 前缀标记：features.js_ 匹配 features.js_* 一族
        return path.startswith(key)
    return path == key or path.startswith(key + ".")


def group_of_path(path: str) -> str:
    """字段路径 → 七字段组名。最长匹配键优先；未覆盖键兜底 G-ENV（见上表注释）。"""
    best_group, best_len = "G-ENV", -1
    for group, keys in GROUP_FIELDS.items():
        for key in keys:
            if _match_key(path, key) and len(key) > best_len:
                best_group, best_len = group, len(key)
    return best_group


def _diff_value(old, new, path: str, out: list[str]) -> None:
    """递归值对比：dict 逐键下钻；其余（含 list、标量、缺失）整体比较。

    变化路径记在当前层级——list 不逐元素下钻（list 是有序整体值，
    如 fonts/sec_ch_ua.brands，任一元素不同即记该 list 路径）。
    """
    if isinstance(old, dict) and isinstance(new, dict):
        for k in sorted(old.keys() | new.keys()):
            _diff_value(old.get(k, _MISSING), new.get(k, _MISSING),
                        f"{path}.{k}" if path else k, out)
    elif old is _MISSING or new is _MISSING or old != new:
        out.append(path)


def diff_captures(old: dict, new: dict) -> dict[str, list[str]]:
    """两份 FingerprintCapture 递归对比，按七字段组返回变化字段路径列表。

    值递归对比（dict 下钻、list/标量整体比较），**缺失键算变化**（§四-5
    「不许白名单外任何变化」含结构增减）；capture_version/collected_at
    采集元数据不参与。返回 dict 恒含七组键（无变化的组为空列表），
    各组路径按字典序排序（确定性输出，供审计留痕）。
    """
    if not isinstance(old, dict):
        old = {}
    if not isinstance(new, dict):
        new = {}
    paths: list[str] = []
    for key in sorted(old.keys() | new.keys()):
        if key in CAPTURE_METADATA_KEYS:
            continue
        _diff_value(old.get(key, _MISSING), new.get(key, _MISSING), key, paths)
    result: dict[str, list[str]] = {g: [] for g in GROUP_FIELDS}
    for p in paths:
        result[group_of_path(p)].append(p)
    return result


def _group_decl_active(decl) -> bool:
    """drift pack 单组声明是否「声明了漂移」（§三各组值语义）。

    判定：组映射内存在至少一个**活跃值**（非 None/False/空 list/空 dict/空串）。
    "source" 键为出处元数据（chromestatus diff 等），非漂移声明，不参与判定。
    例：{"h2_fingerprint_changed": false} → 未声明；{"ja4_expected": "t13d…"}
    → 声明 TLS 面允许漂移；{} → 未声明（G-ENV 常态）。
    """
    if not isinstance(decl, dict):
        return False
    for k, v in decl.items():
        if k == "source":
            continue
        if v is None or v is False or v == [] or v == {} or v == "":
            continue
        return True
    return False


def pack_allowed_groups(pack: dict) -> frozenset[str]:
    """drift pack 白名单（组级）：本 pack 允许发生漂移的字段组集合。

    G-UA 恒在白名单内——版本升级的唯一合法演化事件就是 UA 族漂移（§一），
    且 G-UA 漂移同时是必变义务（G_UA_MUST_CHANGE）；其余各组按
    _group_decl_active 判定（组级粒度，与 CLR 清单分组词汇表对齐，§三）。
    pack 缺 groups 或结构残缺时保守处理：仅 G-UA 允许。
    """
    groups = pack.get("groups") if isinstance(pack, dict) else None
    if not isinstance(groups, dict):
        groups = {}
    allowed = {"G-UA"}
    for g in GROUP_FIELDS:
        if g != "G-UA" and _group_decl_active(groups.get(g)):
            allowed.add(g)
    return frozenset(allowed)


def audit_diff(old: dict, new: dict, pack: dict) -> tuple[bool, list[str]]:
    """diff 审计双断言（§四步骤 5，本案核心创新）：返回 (是否通过, 中文错误列表)。

      断言一（⊆）：F_old→F_new 变化字段集 ⊆ drift pack 白名单
          （pack_allowed_groups 声明漂移的组所映射的 capture 键，
          不许白名单外任何变化——冻结面动了即露馅）；
      断言二（⊇）：变化字段集 ⊇ G-UA 必变集 G_UA_MUST_CHANGE
          （UA/Sec-CH-UA 该变的必须变到位，没变=演化未兑现）。

    纯函数；pack 结构合法性由 validate_drift_pack 前置把关，本函数对
    残缺 pack 保守处理（仅 G-UA 白名单）。
    """
    diff = diff_captures(old, new)
    changed = [p for paths in diff.values() for p in paths]
    allowed_keys = [k for g in pack_allowed_groups(pack) for k in GROUP_FIELDS[g]]
    errors: list[str] = []

    # 断言一：白名单外变化即违例
    for p in sorted(changed):
        if not any(_match_key(p, k) for k in allowed_keys):
            errors.append(
                f"白名单外变化：{p}（属 {group_of_path(p)}，drift pack "
                f"未声明该组漂移——不许白名单外任何变化，§四-5）")

    # 断言二：G-UA 必变集逐项核对（该变的必须变到位）
    for k in sorted(G_UA_MUST_CHANGE):
        if not any(_match_key(p, k) for p in changed):
            errors.append(
                f"G-UA 必变集未变到位：{k}（版本升级 UA 族必变，"
                f"该变的必须变到位，§四-5）")

    return (not errors), errors
