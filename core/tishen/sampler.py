"""采样器（SPEC §4）：browserforge 优先 + 离线兜底 + 约束过滤 + create_persona。

契约接口：
    generate_candidates(n, region, rng) -> list[dict]
    create_persona(name, region, stable_chrome, ip_region=None, seed=None) -> Persona

流程：采样 N 组候选 → 约束过滤（V1 同族 / V4 / V5 / V7 硬条件）→
      填充 schema 全字段 → lint_persona 复验（须零错误）→ 返回 Persona。
"""

from __future__ import annotations

import random
import secrets
from datetime import datetime, timezone, timedelta

from .linter import (LintContext, lint_persona, COMMON_RESOLUTIONS,
                     HARDWARE_MEMORY_PAIRS, FONT_PACKS_BY_OS)
from .persona import (Persona, Meta, Region, Os, Hardware, Gpu, Display, Fonts,
                      Webrtc, Farbling, Evolution, Storage, Monitoring, Lifecycle)
from .regions import REGION_PROFILES

# 采样候选组数（M1 方案 §5：browserforge 采样 N=20 组候选参数）
CANDIDATE_POOL_SIZE = 20

# ---------------------------------------------------------------------------
# browserforge 可选依赖：try-import，缺失走 BUNDLED_DISTRIBUTION 离线兜底
# ---------------------------------------------------------------------------
try:  # pragma: no cover - 环境通常不装，覆盖离线兜底路径即可
    from browserforge.fingerprints import FingerprintGenerator as _BFGenerator

    _HAS_BROWSERFORGE = True
except Exception:  # noqa: BLE001 - 可选依赖，任何导入失败都降级
    _BFGenerator = None
    _HAS_BROWSERFORGE = False

# ---------------------------------------------------------------------------
# 离线兜底静态分布表（近似分布，后续以真实数据替换）
# 权重依据公开桌面设备统计的经验估计；所有取值必须落在 linter 合法集内。
# ---------------------------------------------------------------------------
BUNDLED_DISTRIBUTION = {
    # (width, height) -> 权重；全集 ⊆ COMMON_RESOLUTIONS
    "resolution": [
        ((1920, 1080), 0.35), ((1536, 864), 0.15), ((1366, 768), 0.15),
        ((1440, 900), 0.10), ((1600, 900), 0.10), ((2560, 1440), 0.07),
        ((1280, 720), 0.05), ((3840, 2160), 0.03),
    ],
    # hardwareConcurrency -> 权重；全集 ⊆ {2,4,6,8,12,16}
    "hardwareConcurrency": [(2, 0.10), (4, 0.25), (6, 0.15), (8, 0.30),
                            (12, 0.10), (16, 0.10)],
    # deviceMemory -> 权重；全集 ⊆ {2,4,8,16}
    "deviceMemory": [(2, 0.10), (4, 0.30), (8, 0.40), (16, 0.20)],
    # devicePixelRatio -> 权重；全集 ⊆ {1.0,1.25,1.5,2.0}
    "dpr": [(1.0, 0.60), (1.25, 0.10), (1.5, 0.15), (2.0, 0.15)],
    # 字体包 -> 权重；全集 ⊆ FONT_PACKS_BY_OS["linux"]
    "font_pack": [("linux-noto-standard", 0.70), ("linux-liberation-dejavu", 0.30)],
}


def _weighted_choice(rng: random.Random, table: list[tuple[object, float]]):
    """按权重表抽样。"""
    values = [v for v, _ in table]
    weights = [w for _, w in table]
    return rng.choices(values, weights=weights, k=1)[0]


def generate_candidates(n: int, region: str, rng: random.Random) -> list[dict]:
    """采样 n 组候选参数。

    优先使用 browserforge（若安装）；缺失时走 BUNDLED_DISTRIBUTION 离线兜底。
    每个候选 dict 字段：
        width / height / dpr / hardwareConcurrency / deviceMemory / font_pack
        locale / timezone   （属地族字段，供约束过滤做 V1 同族检查）
    """
    profile = REGION_PROFILES.get(region)
    if profile is None:
        raise ValueError(f"未知属地 {region!r}，已知属地：{sorted(REGION_PROFILES)}")

    default_locale = profile.get("default_locale", sorted(profile["locales"])[0])
    default_timezone = profile.get("default_timezone", sorted(profile["timezones"])[0])
    candidates: list[dict] = []
    if _HAS_BROWSERFORGE:  # pragma: no cover - 依赖可选，默认环境走兜底
        # browserforge 提供真实指纹分布；此处取其屏幕/硬件维度，
        # locale/timezone 仍以本地域表为准（属地一致性不可外包）。
        generator = _BFGenerator()
        for _ in range(n):
            fp = generator.generate()
            candidates.append({
                "width": fp.screen.width,
                "height": fp.screen.height,
                "dpr": fp.screen.device_pixel_ratio,
                "hardwareConcurrency": fp.navigator.hardware_concurrency,
                "deviceMemory": fp.navigator.device_memory,
                "font_pack": "linux-noto-standard",
                "locale": default_locale,
                "timezone": default_timezone,
            })
    else:
        # 离线兜底：加权静态表（近似分布，后续以真实数据替换）
        for _ in range(n):
            (w, h) = _weighted_choice(rng, BUNDLED_DISTRIBUTION["resolution"])
            candidates.append({
                "width": w,
                "height": h,
                "dpr": _weighted_choice(rng, BUNDLED_DISTRIBUTION["dpr"]),
                "hardwareConcurrency": _weighted_choice(
                    rng, BUNDLED_DISTRIBUTION["hardwareConcurrency"]),
                "deviceMemory": _weighted_choice(
                    rng, BUNDLED_DISTRIBUTION["deviceMemory"]),
                "font_pack": _weighted_choice(rng, BUNDLED_DISTRIBUTION["font_pack"]),
                "locale": default_locale,
                "timezone": default_timezone,
            })
    return candidates


def _passes_constraints(c: dict, region: str) -> bool:
    """硬约束过滤（SPEC §4 / M1 方案 §5）：

    - V1 同族：timezone / locale 必须落在属地族表内；
    - V4：分辨率 ∈ COMMON_RESOLUTIONS，dpr ∈ {1.0,1.25,1.5,2.0}；
    - V5：hardwareConcurrency 与 deviceMemory 搭配合法；
    - V7：字体包 ∈ FONT_PACKS_BY_OS["linux"]（本期 os.family 恒 linux）。
    """
    profile = REGION_PROFILES[region]
    if c.get("timezone") not in profile["timezones"]:
        return False
    if c.get("locale") not in profile["locales"]:
        return False
    try:
        wh = (int(c["width"]), int(c["height"]))
        dpr = float(c["dpr"])
        hc = int(c["hardwareConcurrency"])
        dm = int(c["deviceMemory"])
    except (KeyError, TypeError, ValueError):
        return False
    if wh not in COMMON_RESOLUTIONS or dpr not in {1.0, 1.25, 1.5, 2.0}:
        return False
    if dm not in HARDWARE_MEMORY_PAIRS.get(hc, set()):
        return False
    if c.get("font_pack") not in FONT_PACKS_BY_OS.get("linux", set()):
        return False
    return True


def _build_languages(locale: str) -> list[str]:
    """由 locale 派生 Accept-Language 列表：首项 = locale，附语言前缀与英文兜底。"""
    prefix = locale.split("-")[0]
    langs = [locale]
    if prefix != locale:
        langs.append(prefix)
    for fallback in ("en-US", "en"):
        if fallback not in langs:
            langs.append(fallback)
    return langs


def create_persona(name: str, region: str, stable_chrome: str,
                   ip_region: str | None = None, seed: int | None = None) -> Persona:
    """创建全流程：采样 → 约束过滤 → 填充 schema 全字段 → lint 复验（须零错误）。

    - region="auto" 时用 ip_region；仍为 None 则默认 "CN" 并在 meta.note 注释；
    - seed 参数仅用于测试复现（驱动采样 rng）；farbling.seed 恒为
      secrets.token_hex(16)，生产路径不依赖 seed。
    """
    note: str | None = None
    if region == "auto":
        if ip_region:
            region = ip_region
        else:
            region = "CN"
            note = ("region=auto 且未提供实测 IP 属地，已默认按 CN 生成；"
                    "上线前请以实测属地重建或修正本替身")
    if region not in REGION_PROFILES:
        raise ValueError(f"未知属地 {region!r}，已知属地：{sorted(REGION_PROFILES)}")

    rng = random.Random(seed)
    profile = REGION_PROFILES[region]

    # 采样 → 硬约束过滤
    candidates = generate_candidates(CANDIDATE_POOL_SIZE, region, rng)
    valid = [c for c in candidates if _passes_constraints(c, region)]
    if not valid:
        raise RuntimeError(
            f"采样 {CANDIDATE_POOL_SIZE} 组候选无一通过约束过滤（属地 {region}），"
            f"请检查 BUNDLED_DISTRIBUTION 与 linter 合法集是否一致")
    chosen = rng.choice(valid)

    # 身份标识：时间戳 + 随机短缀，匹配 ^p_[a-z0-9_]{4,32}$
    now = datetime.now(timezone(timedelta(hours=8)))  # 展示用东八区时间戳
    persona_id = f"p_{now:%Y%m%d}_{secrets.token_hex(2)}"
    (w, h) = (int(chosen["width"]), int(chosen["height"]))
    locale = chosen["locale"]

    persona = Persona(
        version=1,
        meta=Meta(
            id=persona_id,
            name=name,
            created_at=now.isoformat(timespec="seconds"),
            note=note,
        ),
        region=Region(
            follow_ip=True,
            detected_ip_region=region,
            locale=locale,
            timezone=chosen["timezone"],
            languages=_build_languages(locale),
        ),
        os=Os(family="linux", distro="ubuntu-24.04", chrome_channel="stable"),
        hardware=Hardware(
            gpu=Gpu(mode="host_passthrough", renderer_string_source="real"),
            hardwareConcurrency=int(chosen["hardwareConcurrency"]),
            deviceMemory=int(chosen["deviceMemory"]),
        ),
        display=Display(width=w, height=h, dpr=float(chosen["dpr"])),
        fonts=Fonts(
            pack=chosen["font_pack"],
            # 属地族需要 CJK 时激活 cjk 附加包（V7）
            extras=["cjk"] if profile["cjk"] else [],
        ),
        webrtc=Webrtc(ip_handling_policy="disable_non_proxied_udp"),
        farbling=Farbling(
            # 生产种子恒为密码学随机；seed 参数只影响采样，不影响本种子
            seed=secrets.token_hex(16),
            scope=["canvas_readback", "webgl_readback", "audio"],
        ),
        evolution=Evolution(
            strategy="anchor_chrome_version",
            baseline_chrome=stable_chrome,
            drift_policy="follow_stable_diff",
        ),
        proxy=None,  # 本期恒 null
        storage=Storage(
            profile_volume=f"ts_{persona_id}_profile",
            log_volume=f"ts_{persona_id}_logs",
            retain_days=30,
        ),
        monitoring=Monitoring(keylog=True, log_encryption="age"),
        lifecycle=Lifecycle(state="creating"),
    )

    # 出场门禁复验：零错误才允许返回（SPEC §4）
    ctx = LintContext(current_stable_chrome=stable_chrome, detected_ip_region=region)
    errors = lint_persona(persona, ctx)
    if errors:
        detail = "；".join(f"[{e.code}] {e.field} {e.message}" for e in errors)
        raise RuntimeError(f"采样生成的 persona 未通过出场门禁（不应发生）：{detail}")
    return persona
