"""出场门禁 linter（SPEC §3）：规则 V1–V10。

契约接口（Coder A 烘焙器直接 import，签名不可变）：
    @dataclass LintContext(current_stable_chrome: str, detected_ip_region: str | None)
    @dataclass LintError(code, field, message)
    lint_persona(p: Persona, ctx: LintContext) -> list[LintError]

错误消息一律中文，并说明"为何矛盾"。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .persona import Persona
from .regions import REGION_PROFILES

# V4：常见真实分辨率分布集（奇葩分辨率是自动化指纹的典型破绽）
COMMON_RESOLUTIONS = {
    (1920, 1080), (1536, 864), (1366, 768), (1440, 900),
    (2560, 1440), (1600, 900), (1280, 720), (3840, 2160),
}

# V4：合法 devicePixelRatio
DPR_CHOICES = {1.0, 1.25, 1.5, 2.0}

# V5：hardwareConcurrency → 允许的 deviceMemory 集合（真实硬件搭配）
HARDWARE_MEMORY_PAIRS = {
    2: {2, 4},
    4: {2, 4, 8},
    6: {4, 8},
    8: {4, 8, 16},
    12: {8, 16},
    16: {16},
}

# V7：os.family → 合法字体包集
FONT_PACKS_BY_OS = {
    "linux": {"linux-noto-standard", "linux-liberation-dejavu"},
}

# V8：farbling 种子格式（128-bit 小写十六进制）
FARBLING_SEED_RE = re.compile(r"^[0-9a-f]{32}$")

# V10：用户自带代理端点格式（本期 proxy 应为 None）
PROXY_RE = re.compile(r"^(socks5|http)://[^\s]+:\d{1,5}$")

# V7：CJK 附加字体包的语言依据前缀
_CJK_LANG_PREFIXES = ("zh", "ja", "ko")


@dataclass
class LintContext:
    current_stable_chrome: str          # 当前 stable 版本，如 "138.0.7204.50"
    detected_ip_region: str | None      # 创建时实测属地（校验期可 None=跳过 V1 属地锚）


@dataclass
class LintError:
    code: str        # LINT_V1 .. LINT_V10
    field: str       # 出错字段路径
    message: str     # 中文，说明为何矛盾


def _major(version: str) -> int | None:
    """取四段版本号的主版本；解析失败返回 None。"""
    try:
        return int(str(version).split(".")[0])
    except (ValueError, IndexError):
        return None


def lint_persona(p: Persona, ctx: LintContext) -> list[LintError]:
    """对 persona 跑 V1–V10 全规则，返回错误列表（空 = 通过门禁）。"""
    errors: list[LintError] = []

    def err(code: str, field_path: str, msg: str) -> None:
        errors.append(LintError(code=code, field=field_path, message=msg))

    # ---------------- V1 属地族一致 ----------------
    # 锚点是「创建时实测属地」ctx.detected_ip_region；None 表示校验期跳过属地锚。
    if ctx.detected_ip_region is not None:
        anchor = ctx.detected_ip_region
        profile = REGION_PROFILES.get(anchor)
        if profile is None:
            err("LINT_V1", "region.detected_ip_region",
                f"实测属地 {anchor!r} 不在已知属地族表内，无法证明时区/locale/语言与其同族")
        else:
            if p.region.timezone not in profile["timezones"]:
                err("LINT_V1", "region.timezone",
                    f"实测 IP 属地为 {anchor}，该族合法时区为 {sorted(profile['timezones'])}，"
                    f"却配置 {p.region.timezone!r}——时区与属地矛盾，是典型指纹破绽")
            if p.region.locale not in profile["locales"]:
                err("LINT_V1", "region.locale",
                    f"实测 IP 属地为 {anchor}，该族合法 locale 为 {sorted(profile['locales'])}，"
                    f"却配置 {p.region.locale!r}——locale 与属地矛盾")
            langs = p.region.languages
            if not langs:
                err("LINT_V1", "region.languages",
                    "Accept-Language 列表为空，无法与属地族比对，且真实浏览器不会发送空列表")
            elif not any(str(langs[0]).startswith(pre) for pre in profile["lang_prefixes"]):
                err("LINT_V1", "region.languages",
                    f"实测 IP 属地为 {anchor}，Accept-Language 首项应以 "
                    f"{list(profile['lang_prefixes'])} 之一开头，实际首项为 {langs[0]!r}"
                    f"——语言偏好与属地矛盾")
        # persona 自报属地应与实测锚一致，否则两个字段互相打架
        if p.region.detected_ip_region != anchor:
            err("LINT_V1", "region.detected_ip_region",
                f"persona 自报属地 {p.region.detected_ip_region!r} 与创建时实测属地 "
                f"{anchor!r} 不一致——同一份身份两个属地，必然矛盾")

    # ---------------- V2 OS 锁定 ----------------
    if p.os.family != "linux":
        err("LINT_V2", "os.family",
            f"本期平台锁定 linux（镜像内为真实 Linux Chrome），却声明 {p.os.family!r}"
            f"——声明的 OS 与真实运行环境不符，会被 UA/平台检测当场拆穿")

    # ---------------- V3 GPU 禁撒谎 ----------------
    if p.hardware.gpu.mode != "host_passthrough":
        err("LINT_V3", "hardware.gpu.mode",
            f"GPU 必须为 host_passthrough（/dev/dri 透传宿主真实 GPU），实际为 "
            f"{p.hardware.gpu.mode!r}——软渲染/虚拟 GPU 的 WebGL 指纹与真实用户不符")
    if p.hardware.gpu.renderer_string_source != "real":
        err("LINT_V3", "hardware.gpu.renderer_string_source",
            f"渲染器字符串来源必须为 real（读取宿主真实 ANGLE 字符串），实际为 "
            f"{p.hardware.gpu.renderer_string_source!r}——自定义 GPU 字符串属于撒谎，"
            f"与透传出的真实 GPU 信息自相矛盾")

    # ---------------- V4 分辨率真实 ----------------
    wh = (p.display.width, p.display.height)
    if wh not in COMMON_RESOLUTIONS:
        err("LINT_V4", "display",
            f"分辨率 {wh[0]}×{wh[1]} 不在常见真实分辨率集 {sorted(COMMON_RESOLUTIONS)} 内"
            f"——奇葩分辨率是自动化/虚拟环境的典型特征")
    dpr = p.display.dpr
    dpr_ok = isinstance(dpr, (int, float)) and not isinstance(dpr, bool) \
        and float(dpr) in DPR_CHOICES
    if not dpr_ok:
        err("LINT_V4", "display.dpr",
            f"devicePixelRatio {dpr!r} 不在 {sorted(DPR_CHOICES)} 内"
            f"——真实设备几乎只使用这几个缩放比")

    # ---------------- V5 硬件搭配合理 ----------------
    hc = p.hardware.hardwareConcurrency
    dm = p.hardware.deviceMemory
    allowed = HARDWARE_MEMORY_PAIRS.get(hc)
    if allowed is None:
        err("LINT_V5", "hardware.hardwareConcurrency",
            f"hardwareConcurrency={hc!r} 不在 {sorted(HARDWARE_MEMORY_PAIRS)} 内"
            f"——核数本身就不是真实设备的常见档位")
    elif dm not in allowed:
        err("LINT_V5", "hardware.deviceMemory",
            f"{hc} 核 CPU 的真实设备内存档位为 {sorted(allowed)}GB，却搭配 {dm}GB"
            f"——核数与内存搭配不合理，与真实硬件分布矛盾")

    # ---------------- V6 版本新鲜 ----------------
    base_major = _major(p.evolution.baseline_chrome)
    cur_major = _major(ctx.current_stable_chrome)
    if base_major is None:
        err("LINT_V6", "evolution.baseline_chrome",
            f"基线版本 {p.evolution.baseline_chrome!r} 无法解析主版本号，"
            f"无法证明其不落后于当前 stable")
    elif cur_major is not None and base_major < cur_major - 1:
        err("LINT_V6", "evolution.baseline_chrome",
            f"基线 Chrome 主版本 {base_major} 落后当前 stable 主版本 {cur_major} 超过 1 个版本"
            f"——真实用户的 Chrome 会自动更新，长期停留旧版本本身就是异常信号")

    # ---------------- V7 字体包匹配 ----------------
    packs = FONT_PACKS_BY_OS.get(p.os.family)
    if packs is None:
        # os.family 未知由 V2 负责拦截，V7 跳过，避免同一根因重复报错
        pass
    elif p.fonts.pack not in packs:
        err("LINT_V7", "fonts.pack",
            f"os.family={p.os.family!r} 的合法字体包为 {sorted(packs)}，却配置 "
            f"{p.fonts.pack!r}——字体包与 OS 族不匹配，fc-list 输出会与声明平台矛盾")
    if "cjk" in (p.fonts.extras or []):
        # CJK 附加包仅当：属地族需要 CJK，或任一声明语言以 zh/ja/ko 开头
        profile = REGION_PROFILES.get(p.region.detected_ip_region)
        region_needs_cjk = bool(profile and profile["cjk"])
        lang_needs_cjk = any(
            str(lang).startswith(_CJK_LANG_PREFIXES) for lang in (p.region.languages or []))
        if not (region_needs_cjk or lang_needs_cjk):
            err("LINT_V7", "fonts.extras",
                f"属地 {p.region.detected_ip_region!r} 非 CJK 地区，声明语言 "
                f"{p.region.languages!r} 也不含 zh/ja/ko，却激活 CJK 字体附加包"
                f"——字体集与语言/属地画像矛盾")

    # ---------------- V8 种子合法 ----------------
    if not isinstance(p.farbling.seed, str) or not FARBLING_SEED_RE.match(p.farbling.seed):
        err("LINT_V8", "farbling.seed",
            f"farbling 种子须为 32 位小写十六进制（128-bit），实际为 {p.farbling.seed!r}"
            f"——空种子/弱种子会让 canvas/WebGL/audio 噪声可预测，失去反指纹意义")

    # ---------------- V9 WebRTC 禁泄露 ----------------
    if p.webrtc.ip_handling_policy != "disable_non_proxied_udp":
        err("LINT_V9", "webrtc.ip_handling_policy",
            f"WebRTC IP 处理策略须为 disable_non_proxied_udp，实际为 "
            f"{p.webrtc.ip_handling_policy!r}——宽松策略会经 WebRTC 泄露本机真实 IP，"
            f"与替身隐藏真实出口的目标直接矛盾")

    # ---------------- V10 代理边界 ----------------
    if p.proxy is not None:
        if not isinstance(p.proxy, str) or not PROXY_RE.match(p.proxy):
            err("LINT_V10", "proxy",
                f"代理端点须为 null（本期）或形如 socks5://host:port / http://host:port，"
                f"实际为 {p.proxy!r}——非法代理配置会让流量走向不可控路径，破坏属地一致性前提")

    return errors
