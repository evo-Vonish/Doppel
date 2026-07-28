"""CLR 跨层一致性清单 v1（SPEC-M4 §3，清单版本 clr-checklist-v1）。

78 条断言，id 前缀分组配额：UA 10 / TZ 8 / SCR 8 / GPU 10 / FONT 6 /
HW 6 / BOT 10 / FEAT 8 / NET 6 / NOISE 6。每条标注五选一来源
（creepjs / sannysoft / browserleaks / incolumitas / tishen）：
- creepjs      ：CreepJS lies 思想（多路径读值不一致、列表被改写的痕迹、resistance 模式）；
- sannysoft    ：bot.sannysoft.com 红项（webdriver、CDP 痕迹、headless UA、空 languages 等）；
- browserleaks ：BrowserLeaks 各面板内部/面板间交叉断言（屏幕、时区、WebGL、字体、媒体设备）；
- incolumitas  ：incolumitas 式 TLS↔UA↔Sec-CH-UA 跨层互洽；
- tishen       ：本项目自研项（HC→DM 合法对表、Linux+ANGLE 特征、噪声撞 hash 等，沿用出厂 V4/V5/V7 口径）。

check 函数协议（R-Gate 执行语义，SPEC-M4 §3）：
    fn(capture) -> None   —— 所需字段缺失或为 null：记 skipped（reason=field_missing），不计命中；
    fn(capture) -> "pass" —— 值存在且自洽；
    fn(capture) -> dict   —— 命中，返回证据 {字段路径: 实际值}（值必须 JSON 可序列化）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Union

from ..linter import COMMON_RESOLUTIONS, DPR_CHOICES, HARDWARE_MEMORY_PAIRS

# check 返回：None=skipped / "pass"=通过 / dict=命中证据
CheckVerdict = Union[str, dict, None]
CheckFn = Callable[[dict], CheckVerdict]


@dataclass(frozen=True)
class ClrCheck:
    """单条 CLR 断言（SPEC-M4 §3 契约字段 id/layers/source/assertion/severity + 可执行 check）。"""

    id: str                     # CLR-<族>-<序号>
    layers: list[str]           # 涉及的 FingerprintCapture 字段路径
    source: str                 # creepjs|sannysoft|browserleaks|incolumitas|tishen
    assertion: str              # 中文断言，说明两层信息怎样算矛盾
    severity: str               # critical|major|minor
    check: CheckFn = field(compare=False, repr=False)


_MISSING = object()


def _dig(capture: dict, path: str):
    """按点分路径取值；任一层缺键或值为 null 返回 _MISSING（false/0/空串/空表仍是有效值）。"""
    node = capture
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
        if node is None:
            return _MISSING
    return node


def _need(capture: dict, *paths: str):
    """批量取必需字段；任一缺失返回 None（调用方应返回 None 记 skipped），否则返回值列表。"""
    vals = []
    for p in paths:
        v = _dig(capture, p)
        if v is _MISSING:
            return None
        vals.append(v)
    return vals


# ---------------------------------------------------------------------------
# 公共解析辅助
# ---------------------------------------------------------------------------

_CHROME_MAJOR_RE = re.compile(r"Chrome/(\d+)\.")


def _ua_chrome_major(ua: str):
    """UA 声称的 Chrome 主版本；未声称（非 Chrome UA）返回 None。"""
    m = _CHROME_MAJOR_RE.search(ua)
    return int(m.group(1)) if m else None


def _ua_os(ua: str):
    """从 UA 解析 OS 族；无法解析返回 None。"""
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Windows" in ua:
        return "Windows"
    if "CrOS" in ua:
        return "Chrome OS"
    if "Mac OS X" in ua or "Macintosh" in ua:
        return "macOS"
    if "Linux" in ua or "X11" in ua:
        return "Linux"
    return None


def _platform_os(platform: str):
    """从 navigator.platform 解析 OS 族；无法解析返回 None。"""
    if platform.startswith(("iPhone", "iPad")):
        return "iOS"
    if platform.startswith("Win"):
        return "Windows"
    if platform.startswith("Mac"):
        return "macOS"
    if platform.startswith("Android"):
        return "Android"
    if platform.startswith("Linux"):
        # Android WebView 的 platform 常见为 Linux armv8l
        if "arm" in platform or "aarch" in platform:
            return "Android"
        return "Linux"
    if platform.startswith("CrOS"):
        return "Chrome OS"
    return None


def _sec_ch_platform_os(value: str):
    """Sec-CH-UA-Platform 值规范化；未知值返回 None。"""
    known = {"Windows", "macOS", "Linux", "Android", "Chrome OS", "iOS"}
    return value if value in known else None


def _chromium_brand_version(brands) -> str | None:
    """从 brands/fullVersionList 中找 Chromium/Google Chrome 条目的版本串。"""
    if not isinstance(brands, list):
        return None
    for entry in brands:
        if isinstance(entry, dict) and entry.get("brand") in ("Chromium", "Google Chrome"):
            return entry.get("version")
    return None


def _lang_tag(lang) -> str:
    """取 BCP47 语言子标签（小写）。"""
    return re.split(r"[-_]", str(lang), maxsplit=1)[0].lower()


def _locale_region(locale: str) -> str | None:
    """取 locale 的地区子标签（大写）；无地区段返回 None。"""
    parts = re.split(r"[-_]", str(locale))
    for part in parts[1:]:
        if len(part) == 2 and part.isalpha():
            return part.upper()
    return None


# TZ-01：常见 IANA 时区 → 合法 getTimezoneOffset 分钟数集（含 DST 双值；
# getTimezoneOffset = -（本地相对 UTC 的偏移分钟），如 UTC+8 → -480）
_TZ_OFFSETS = {
    "Asia/Shanghai": {-480}, "Asia/Hong_Kong": {-480}, "Asia/Singapore": {-480},
    "Asia/Taipei": {-480}, "Asia/Tokyo": {-540}, "Asia/Seoul": {-540},
    "Asia/Kolkata": {-330}, "Asia/Dubai": {-240}, "Asia/Bangkok": {-420},
    "Europe/London": {0, -60}, "Europe/Berlin": {-60, -120}, "Europe/Paris": {-60, -120},
    "Europe/Madrid": {-60, -120}, "Europe/Moscow": {-180}, "Europe/Istanbul": {-180},
    "America/New_York": {300, 240}, "America/Toronto": {300, 240},
    "America/Chicago": {360, 300}, "America/Denver": {420, 360},
    "America/Los_Angeles": {480, 420}, "America/Sao_Paulo": {180, 240},
    "America/Mexico_City": {360, 300},
    "Australia/Sydney": {-600, -660}, "Pacific/Auckland": {-720, -780},
    "UTC": {0}, "Etc/UTC": {0},
}

# TZ-05：时区 → （地区码， 当地语言前缀集）；用于「时区与 locale 矛盾且无语言链解释」判定
_TZ_REGION_LANGS = {
    "Asia/Shanghai": ("CN", {"zh"}), "Asia/Hong_Kong": ("HK", {"zh", "en"}),
    "Asia/Taipei": ("TW", {"zh"}), "Asia/Singapore": ("SG", {"zh", "en", "ms"}),
    "Asia/Tokyo": ("JP", {"ja"}), "Asia/Seoul": ("KR", {"ko"}),
    "Asia/Kolkata": ("IN", {"hi", "en"}), "Asia/Dubai": ("AE", {"ar", "en"}),
    "Europe/London": ("GB", {"en"}), "Europe/Berlin": ("DE", {"de"}),
    "Europe/Paris": ("FR", {"fr"}), "Europe/Madrid": ("ES", {"es"}),
    "Europe/Moscow": ("RU", {"ru"}),
    "America/New_York": ("US", {"en"}), "America/Chicago": ("US", {"en"}),
    "America/Denver": ("US", {"en"}), "America/Los_Angeles": ("US", {"en"}),
    "America/Toronto": ("CA", {"en", "fr"}), "America/Sao_Paulo": ("BR", {"pt"}),
    "America/Mexico_City": ("MX", {"es"}),
    "Australia/Sydney": ("AU", {"en"}), "Pacific/Auckland": ("NZ", {"en"}),
}

_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
_IANA_TZ_RE = re.compile(r"^(UTC|[A-Za-z_]+/[A-Za-z0-9_+\-/]+)$")

# FONT-02：OS 独占字体（出现在声明的 Linux 桌面即矛盾）
_WIN_ONLY_FONTS = {"Segoe UI", "Calibri", "Cambria", "Consolas", "MS Gothic"}
_MAC_ONLY_FONTS = {"San Francisco", "Monaco", "Menlo", "Apple Chancery"}

# FONT-03：Linux 桌面常见字体（至少应命中一款）
_LINUX_COMMON_FONTS = {
    "DejaVu Sans", "DejaVu Serif", "Liberation Sans", "Liberation Serif",
    "Noto Sans", "Noto Serif", "Ubuntu", "Cantarell", "FreeSans",
    "Droid Sans", "WenQuanYi Micro Hei",
}

# FONT-04：CJK 字体名关键词（locale 为 zh/ja/ko 时字体集应能解释 CJK 渲染）
_CJK_FONT_KEYWORDS = (
    "CJK", "WenQuanYi", "YaHei", "PingFang", "SimSun", "SimHei",
    "Hiragino", "Source Han", "Droid Sans Fallback", "Noto Sans SC",
    "Noto Sans JP", "Noto Sans KR", "Noto Serif SC", "Malgun",
    "Meiryo", "Yu Gothic", "MS Gothic", "AR PL",
)

# BOT-08：UA 中的已知自动化框架标识
_AUTOMATION_UA_RE = re.compile(
    r"PhantomJS|SlimerJS|CasperJS|Selenium|WebDriver|Puppeteer|Playwright|jsdom",
    re.IGNORECASE,
)

# NET-02/03：JA3 五段逗号分隔 / JA4 三段下划线（tls.peet.ws 产出形状）
_JA3_RE = re.compile(r"^\d{3},[\d\-]*,[\d\-]*,[\d\-]*,[\d\-]*$")
_JA4_RE = re.compile(r"^[tq]\d{2}[dq]\d{4}h[12]_[0-9a-f]{12}_[0-9a-f]{12}$")

# TLS GREASE 值（0x?A?A 一族，十进制），JA3 比对前剔除
_GREASE = {257 * (16 * k + 10) for k in range(16)}

# FEAT-06：完整 IPv4 四段（candidates 契约要求打码末段，出现完整地址即泄露）
_FULL_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

_VIDEO_CODECS_EXPECTED = {"vp8", "vp9", "av1", "h264", "h265", "hevc"}
_AUDIO_CODECS_EXPECTED = {"opus", "vorbis", "aac", "mp3", "flac", "pcm"}

_PERMISSION_STATES = {"granted", "denied", "prompt"}


# ---------------------------------------------------------------------------
# UA / Sec-CH-UA 族（CLR-UA-*，10 条）
# ---------------------------------------------------------------------------

def _ua01(capture):
    vals = _need(capture, "navigator.userAgent", "sec_ch_ua.brands")
    if vals is None:
        return None
    ua, brands = vals
    major = _ua_chrome_major(ua)
    if major is None:
        return "pass"      # 未声称 Chrome 主版本，本条不适用（非 Chrome UA 由 BOT-07/08 族覆盖）
    brand_ver = _chromium_brand_version(brands)
    if brand_ver is None or not str(brand_ver).split(".")[0].isdigit() \
            or int(str(brand_ver).split(".")[0]) != major:
        return {"navigator.userAgent": ua, "sec_ch_ua.brands": brands}
    return "pass"


def _ua02(capture):
    vals = _need(capture, "navigator.userAgent", "navigator.platform")
    if vals is None:
        return None
    ua, platform = vals
    a, b = _ua_os(ua), _platform_os(platform)
    if a is not None and b is not None and a != b:
        return {"navigator.userAgent": ua, "navigator.platform": platform}
    return "pass"


def _ua03(capture):
    vals = _need(capture, "sec_ch_ua.platform", "navigator.platform")
    if vals is None:
        return None
    sec_plat, platform = vals
    a, b = _sec_ch_platform_os(sec_plat), _platform_os(platform)
    if a is not None and b is not None and a != b:
        return {"sec_ch_ua.platform": sec_plat, "navigator.platform": platform}
    return "pass"


def _ua04(capture):
    vals = _need(capture, "navigator.userAgent", "sec_ch_ua.platform")
    if vals is None:
        return None
    ua, sec_plat = vals
    a, b = _ua_os(ua), _sec_ch_platform_os(sec_plat)
    if a is not None and b is not None and a != b:
        return {"navigator.userAgent": ua, "sec_ch_ua.platform": sec_plat}
    return "pass"


def _ua05(capture):
    vals = _need(capture, "navigator.userAgent", "sec_ch_ua.uaFullVersion")
    if vals is None:
        return None
    ua, full = vals
    major = _ua_chrome_major(ua)
    if major is None:
        return "pass"
    head = str(full).split(".")[0]
    if not head.isdigit() or int(head) != major:
        return {"navigator.userAgent": ua, "sec_ch_ua.uaFullVersion": full}
    return "pass"


def _ua06(capture):
    vals = _need(capture, "navigator.userAgent", "cross_reads.ua_worker")
    if vals is None:
        return None
    ua, ua_worker = vals
    if ua != ua_worker:
        return {"navigator.userAgent": ua, "cross_reads.ua_worker": ua_worker}
    return "pass"


def _ua07(capture):
    vals = _need(capture, "navigator.userAgent", "cross_reads.ua_iframe")
    if vals is None:
        return None
    ua, ua_iframe = vals
    if ua != ua_iframe:
        return {"navigator.userAgent": ua, "cross_reads.ua_iframe": ua_iframe}
    return "pass"


def _ua08(capture):
    vals = _need(capture, "navigator.userAgent", "sec_ch_ua.mobile")
    if vals is None:
        return None
    ua, mobile = vals
    if ("Mobile" in ua) != bool(mobile):
        return {"navigator.userAgent": ua, "sec_ch_ua.mobile": mobile}
    return "pass"


def _ua09(capture):
    vals = _need(capture, "navigator.userAgent", "navigator.vendor")
    if vals is None:
        return None
    ua, vendor = vals
    if _ua_chrome_major(ua) is not None and vendor != "Google Inc.":
        return {"navigator.userAgent": ua, "navigator.vendor": vendor}
    return "pass"


def _ua10(capture):
    vals = _need(capture, "sec_ch_ua.fullVersionList", "sec_ch_ua.uaFullVersion")
    if vals is None:
        return None
    fvl, full = vals
    brand_ver = _chromium_brand_version(fvl)
    if brand_ver is None or str(brand_ver) != str(full):
        return {"sec_ch_ua.fullVersionList": fvl, "sec_ch_ua.uaFullVersion": full}
    return "pass"


# ---------------------------------------------------------------------------
# 时区 / locale 族（CLR-TZ-*，8 条）
# ---------------------------------------------------------------------------

def _tz01(capture):
    vals = _need(capture, "intl.timeZone", "intl.tzOffsetMinutes")
    if vals is None:
        return None
    tz, off = vals
    legal = _TZ_OFFSETS.get(tz)
    if legal is not None and off not in legal:
        return {"intl.timeZone": tz, "intl.tzOffsetMinutes": off}
    return "pass"


def _tz02(capture):
    vals = _need(capture, "intl.timeZone", "cross_reads.tz_iframe")
    if vals is None:
        return None
    tz, tz_iframe = vals
    if tz != tz_iframe:
        return {"intl.timeZone": tz, "cross_reads.tz_iframe": tz_iframe}
    return "pass"


def _tz03(capture):
    vals = _need(capture, "navigator.languages", "intl.locale")
    if vals is None:
        return None
    langs, locale = vals
    if not isinstance(langs, list) or not langs:
        return None     # 空 languages 由 BOT-06 负责，避免同一根因重复报错
    if _lang_tag(langs[0]) != _lang_tag(locale):
        return {"navigator.languages": langs, "intl.locale": locale}
    return "pass"


def _tz04(capture):
    vals = _need(capture, "navigator.languages", "cross_reads.languages_worker")
    if vals is None:
        return None
    langs, langs_worker = vals
    if list(langs) != list(langs_worker):
        return {"navigator.languages": langs, "cross_reads.languages_worker": langs_worker}
    return "pass"


def _tz05(capture):
    vals = _need(capture, "intl.timeZone", "intl.locale", "navigator.languages")
    if vals is None:
        return None
    tz, locale, langs = vals
    anchor = _TZ_REGION_LANGS.get(tz)
    region = _locale_region(locale)
    if anchor is None or region is None:
        return "pass"   # 表外时区/无地区段 locale 无法判定，不作有罪推定
    tz_region, tz_langs = anchor
    if region == tz_region:
        return "pass"
    lang_prefixes = {_lang_tag(l) for l in langs} if isinstance(langs, list) else set()
    if lang_prefixes & tz_langs:
        return "pass"   # 语言链能解释（如人在美国但讲中文）
    return {"intl.timeZone": tz, "intl.locale": locale, "navigator.languages": langs}


def _tz06(capture):
    vals = _need(capture, "intl.tzOffsetMinutes")
    if vals is None:
        return None
    off = vals[0]
    if not isinstance(off, int) or isinstance(off, bool) \
            or off % 15 != 0 or off > 720 or off < -840:
        return {"intl.tzOffsetMinutes": off}
    return "pass"


def _tz07(capture):
    vals = _need(capture, "navigator.languages")
    if vals is None:
        return None
    langs = vals[0]
    if not isinstance(langs, list):
        return {"navigator.languages": langs}
    if len(langs) != len(set(langs)) \
            or any(not isinstance(l, str) or not _BCP47_RE.match(l) for l in langs):
        return {"navigator.languages": langs}
    return "pass"


def _tz08(capture):
    vals = _need(capture, "intl.timeZone")
    if vals is None:
        return None
    tz = vals[0]
    if not isinstance(tz, str) or not _IANA_TZ_RE.match(tz):
        return {"intl.timeZone": tz}
    return "pass"


# ---------------------------------------------------------------------------
# 屏幕 / DPR 族（CLR-SCR-*，8 条）
# ---------------------------------------------------------------------------

def _scr01(capture):
    vals = _need(capture, "screen.width", "screen.height",
                 "screen.availWidth", "screen.availHeight")
    if vals is None:
        return None
    w, h, aw, ah = vals
    if aw > w or ah > h:
        return {"screen.width": w, "screen.height": h,
                "screen.availWidth": aw, "screen.availHeight": ah}
    return "pass"


def _scr02(capture):
    vals = _need(capture, "screen.colorDepth", "screen.pixelDepth")
    if vals is None:
        return None
    cd, pd = vals
    if cd != pd:
        return {"screen.colorDepth": cd, "screen.pixelDepth": pd}
    return "pass"


def _scr03(capture):
    vals = _need(capture, "screen.innerWidth", "screen.innerHeight",
                 "screen.outerWidth", "screen.outerHeight")
    if vals is None:
        return None
    iw, ih, ow, oh = vals
    if iw > ow or ih > oh:
        return {"screen.innerWidth": iw, "screen.innerHeight": ih,
                "screen.outerWidth": ow, "screen.outerHeight": oh}
    return "pass"


def _scr04(capture):
    vals = _need(capture, "screen.outerWidth", "screen.outerHeight",
                 "screen.width", "screen.height")
    if vals is None:
        return None
    ow, oh, w, h = vals
    if ow > w or oh > h:
        return {"screen.outerWidth": ow, "screen.outerHeight": oh,
                "screen.width": w, "screen.height": h}
    return "pass"


def _scr05(capture):
    vals = _need(capture, "screen.devicePixelRatio")
    if vals is None:
        return None
    dpr = vals[0]
    ok = isinstance(dpr, (int, float)) and not isinstance(dpr, bool) \
        and float(dpr) in DPR_CHOICES
    if not ok:
        return {"screen.devicePixelRatio": dpr}
    return "pass"


def _scr06(capture):
    vals = _need(capture, "screen.width", "screen.height")
    if vals is None:
        return None
    w, h = vals
    if (w, h) not in COMMON_RESOLUTIONS:
        return {"screen.width": w, "screen.height": h}
    return "pass"


def _scr07(capture):
    vals = _need(capture, "screen.width", "screen.height")
    if vals is None:
        return None
    w, h = vals
    if (w, h) == (800, 600):
        return {"screen.width": w, "screen.height": h}
    return "pass"


def _scr08(capture):
    vals = _need(capture, "screen.colorDepth")
    if vals is None:
        return None
    cd = vals[0]
    if cd not in (15, 16, 24, 30, 32):
        return {"screen.colorDepth": cd}
    return "pass"


# ---------------------------------------------------------------------------
# GPU / WebGL 族（CLR-GPU-*，10 条）
# ---------------------------------------------------------------------------

def _gpu01(capture):
    vals = _need(capture, "webgl.version")
    if vals is None:
        return None
    v = vals[0]
    if not isinstance(v, str) or not v.startswith("WebGL "):
        return {"webgl.version": v}
    return "pass"


def _gpu02(capture):
    vals = _need(capture, "webgl.glslVersion")
    if vals is None:
        return None
    v = vals[0]
    if not isinstance(v, str) or "WebGL GLSL ES" not in v:
        return {"webgl.glslVersion": v}
    return "pass"


def _gpu03(capture):
    vals = _need(capture, "webgl.version", "webgl.glslVersion")
    if vals is None:
        return None
    ver, glsl = vals
    ver_gen = 2 if "WebGL 2.0" in ver else (1 if "WebGL 1.0" in ver else None)
    glsl_gen = 3 if "GLSL ES 3.0" in glsl else (1 if "GLSL ES 1.0" in glsl else None)
    if ver_gen is None or glsl_gen is None:
        return "pass"   # 形状异常由 GPU-01/02 负责，避免同一根因重复报错
    if {1: 1, 2: 3}[ver_gen] != glsl_gen:
        return {"webgl.version": ver, "webgl.glslVersion": glsl}
    return "pass"


def _gpu04(capture):
    vals = _need(capture, "navigator.platform", "webgl.unmaskedRenderer")
    if vals is None:
        return None
    platform, renderer = vals
    if _platform_os(platform) != "Linux":
        return "pass"   # 非 Linux 平台不适用本特征
    if not isinstance(renderer, str) or not renderer.startswith("ANGLE ("):
        return {"navigator.platform": platform, "webgl.unmaskedRenderer": renderer}
    return "pass"


def _gpu05(capture):
    vals = _need(capture, "navigator.userAgent",
                 "webgl.unmaskedVendor", "webgl.unmaskedRenderer")
    if vals is None:
        return None
    ua, vendor, renderer = vals
    if _ua_chrome_major(ua) is None:
        return "pass"   # 非 Chrome UA 不适用 Chrome 掩码对形状
    m = re.match(r"^Google Inc\. \((.+)\)$", str(vendor))
    if m is None or m.group(1).lower() not in str(renderer).lower():
        return {"webgl.unmaskedVendor": vendor, "webgl.unmaskedRenderer": renderer}
    return "pass"


def _gpu06(capture):
    vals = _need(capture, "webgl.maxTextureSize")
    if vals is None:
        return None
    v = vals[0]
    ok = isinstance(v, int) and not isinstance(v, bool) \
        and 2048 <= v <= 32768 and (v & (v - 1)) == 0
    if not ok:
        return {"webgl.maxTextureSize": v}
    return "pass"


def _gpu07(capture):
    vals = _need(capture, "webgl.maxViewportDims")
    if vals is None:
        return None
    dims = vals[0]
    ok = isinstance(dims, list) and len(dims) == 2 and all(
        isinstance(d, int) and not isinstance(d, bool) and 2048 <= d <= 65536
        for d in dims)
    if not ok:
        return {"webgl.maxViewportDims": dims}
    return "pass"


def _gpu08(capture):
    vals = _need(capture, "webgl.maxVertexAttribs")
    if vals is None:
        return None
    v = vals[0]
    if v not in (8, 16, 32):
        return {"webgl.maxVertexAttribs": v}
    return "pass"


def _gpu09(capture):
    vals = _need(capture, "webgl.maxCombinedTextureImageUnits")
    if vals is None:
        return None
    v = vals[0]
    ok = isinstance(v, int) and not isinstance(v, bool) and 8 <= v <= 256
    if not ok:
        return {"webgl.maxCombinedTextureImageUnits": v}
    return "pass"


def _gpu10(capture):
    vals = _need(capture, "webgl.extensions")
    if vals is None:
        return None
    ext = vals[0]
    if not isinstance(ext, list) or not ext \
            or len(ext) != len(set(ext)) or ext != sorted(ext):
        return {"webgl.extensions": ext}
    return "pass"


# ---------------------------------------------------------------------------
# 字体族（CLR-FONT-*，6 条）
# ---------------------------------------------------------------------------

def _font01(capture):
    vals = _need(capture, "fonts")
    if vals is None:
        return None
    fonts = vals[0]
    if isinstance(fonts, list) and len(fonts) != len(set(fonts)):
        return {"fonts": fonts}
    return "pass"


def _font02(capture):
    vals = _need(capture, "navigator.platform", "fonts")
    if vals is None:
        return None
    platform, fonts = vals
    if _platform_os(platform) != "Linux" or not isinstance(fonts, list):
        return "pass"
    leaked = sorted(set(fonts) & (_WIN_ONLY_FONTS | _MAC_ONLY_FONTS))
    if leaked:
        return {"navigator.platform": platform, "fonts": leaked}
    return "pass"


def _font03(capture):
    vals = _need(capture, "navigator.platform", "fonts")
    if vals is None:
        return None
    platform, fonts = vals
    if _platform_os(platform) != "Linux" or not isinstance(fonts, list) or not fonts:
        return "pass"   # 空列表由 FONT-05 负责
    if not (set(fonts) & _LINUX_COMMON_FONTS):
        return {"navigator.platform": platform, "fonts": fonts}
    return "pass"


def _font04(capture):
    vals = _need(capture, "intl.locale", "fonts")
    if vals is None:
        return None
    locale, fonts = vals
    if _lang_tag(locale) not in ("zh", "ja", "ko") or not isinstance(fonts, list):
        return "pass"
    if not any(kw in f for f in fonts for kw in _CJK_FONT_KEYWORDS):
        return {"intl.locale": locale, "fonts": fonts}
    return "pass"


def _font05(capture):
    vals = _need(capture, "fonts")
    if vals is None:
        return None
    fonts = vals[0]
    if isinstance(fonts, list) and not fonts:
        return {"fonts": fonts}
    return "pass"


def _font06(capture):
    vals = _need(capture, "fonts")
    if vals is None:
        return None
    fonts = vals[0]
    if not isinstance(fonts, list) \
            or any(not isinstance(f, str) or not f.strip() for f in fonts):
        return {"fonts": fonts}
    return "pass"


# ---------------------------------------------------------------------------
# 硬件并发 / 内存 / 跨路径读值族（CLR-HW-*，6 条）
# ---------------------------------------------------------------------------

def _hw01(capture):
    vals = _need(capture, "navigator.hardwareConcurrency", "navigator.deviceMemory")
    if vals is None:
        return None
    hc, dm = vals
    allowed = HARDWARE_MEMORY_PAIRS.get(hc)
    if allowed is None:
        return "pass"   # 核数档位本身异常由 HW-02 负责，避免同一根因重复报错
    if dm not in allowed:
        return {"navigator.hardwareConcurrency": hc, "navigator.deviceMemory": dm}
    return "pass"


def _hw02(capture):
    vals = _need(capture, "navigator.hardwareConcurrency")
    if vals is None:
        return None
    hc = vals[0]
    if isinstance(hc, bool) or not isinstance(hc, int) \
            or hc not in HARDWARE_MEMORY_PAIRS:
        return {"navigator.hardwareConcurrency": hc}
    return "pass"


def _hw03(capture):
    vals = _need(capture, "navigator.hardwareConcurrency", "cross_reads.hwc_worker")
    if vals is None:
        return None
    hc, hc_worker = vals
    if hc != hc_worker:
        return {"navigator.hardwareConcurrency": hc, "cross_reads.hwc_worker": hc_worker}
    return "pass"


def _hw04(capture):
    vals = _need(capture, "navigator.hardwareConcurrency", "cross_reads.hwc_iframe")
    if vals is None:
        return None
    hc, hc_iframe = vals
    if hc != hc_iframe:
        return {"navigator.hardwareConcurrency": hc, "cross_reads.hwc_iframe": hc_iframe}
    return "pass"


def _hw05(capture):
    vals = _need(capture, "navigator.platform", "cross_reads.platform_worker")
    if vals is None:
        return None
    platform, platform_worker = vals
    if platform != platform_worker:
        return {"navigator.platform": platform,
                "cross_reads.platform_worker": platform_worker}
    return "pass"


def _hw06(capture):
    vals = _need(capture, "navigator.platform", "cross_reads.platform_iframe")
    if vals is None:
        return None
    platform, platform_iframe = vals
    if platform != platform_iframe:
        return {"navigator.platform": platform,
                "cross_reads.platform_iframe": platform_iframe}
    return "pass"


# ---------------------------------------------------------------------------
# webdriver / CDP / 自动化痕迹族（CLR-BOT-*，10 条）
# ---------------------------------------------------------------------------

def _bot01(capture):
    vals = _need(capture, "navigator.webdriver")
    if vals is None:
        return None
    wd = vals[0]
    if wd is not False:
        return {"navigator.webdriver": wd}
    return "pass"


def _bot02(capture):
    vals = _need(capture, "cdp_traces.runtimeEnableArtifacts")
    if vals is None:
        return None
    v = vals[0]
    if v is not False:
        return {"cdp_traces.runtimeEnableArtifacts": v}
    return "pass"


def _bot03(capture):
    vals = _need(capture, "cdp_traces.consoleLogArtifacts")
    if vals is None:
        return None
    v = vals[0]
    if v is not False:
        return {"cdp_traces.consoleLogArtifacts": v}
    return "pass"


def _bot04(capture):
    vals = _need(capture, "cdp_traces.stackTracesContainCdp")
    if vals is None:
        return None
    v = vals[0]
    if v is not False:
        return {"cdp_traces.stackTracesContainCdp": v}
    return "pass"


def _bot05(capture):
    vals = _need(capture, "navigator.pdfViewerEnabled")
    if vals is None:
        return None
    v = vals[0]
    if v is not True:
        return {"navigator.pdfViewerEnabled": v}
    return "pass"


def _bot06(capture):
    vals = _need(capture, "navigator.languages")
    if vals is None:
        return None
    langs = vals[0]
    if not isinstance(langs, list) or not langs:
        return {"navigator.languages": langs}
    return "pass"


def _bot07(capture):
    vals = _need(capture, "navigator.userAgent")
    if vals is None:
        return None
    ua = vals[0]
    if "HeadlessChrome" in ua:
        return {"navigator.userAgent": ua}
    return "pass"


def _bot08(capture):
    vals = _need(capture, "navigator.userAgent")
    if vals is None:
        return None
    ua = vals[0]
    if _AUTOMATION_UA_RE.search(ua):
        return {"navigator.userAgent": ua}
    return "pass"


def _bot09(capture):
    vals = _need(capture, "navigator.userAgent", "sec_ch_ua.brands")
    if vals is None:
        return None
    ua, brands = vals
    if _ua_chrome_major(ua) is None:
        return "pass"
    if not isinstance(brands, list) or not any(
            isinstance(e, dict) and "not" in str(e.get("brand", "")).lower()
            for e in brands):
        return {"sec_ch_ua.brands": brands}
    return "pass"


def _bot10(capture):
    vals = _need(capture, "permissions")
    if vals is None:
        return None
    perms = vals[0]
    if not isinstance(perms, dict):
        return {"permissions": perms}
    bad = {k: v for k, v in perms.items() if v not in _PERMISSION_STATES}
    if bad:
        return {"permissions": bad}
    return "pass"


# ---------------------------------------------------------------------------
# 存储 / 权限 / 特性族（CLR-FEAT-*，8 条）
# ---------------------------------------------------------------------------

def _feat01(capture):
    vals = _need(capture, "features.pointerCoarse", "features.pointerFine")
    if vals is None:
        return None
    coarse, fine = vals
    if coarse is False and fine is False:
        return {"features.pointerCoarse": coarse, "features.pointerFine": fine}
    return "pass"


def _feat02(capture):
    vals = _need(capture, "sec_ch_ua.mobile", "features.pointerCoarse")
    if vals is None:
        return None
    mobile, coarse = vals
    if mobile is False and coarse is True:
        return {"sec_ch_ua.mobile": mobile, "features.pointerCoarse": coarse}
    return "pass"


def _feat03(capture):
    vals = _need(capture, "storage.localStorage", "storage.sessionStorage")
    if vals is None:
        return None
    local, session = vals
    if local != session:
        return {"storage.localStorage": local, "storage.sessionStorage": session}
    return "pass"


def _feat04(capture):
    vals = _need(capture, "media.devices", "permissions")
    if vals is None:
        return None
    devices, perms = vals
    if not isinstance(devices, list) or not isinstance(perms, dict):
        return "pass"
    kind_perm = {"audioinput": "microphone", "videoinput": "camera"}
    bad = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        perm_name = kind_perm.get(d.get("kind"))
        if perm_name and d.get("label") and perms.get(perm_name) == "denied":
            bad.append(d)
    if bad:
        return {"media.devices": bad, "permissions": perms}
    return "pass"


def _feat05(capture):
    vals = _need(capture, "media.videoCodecs", "media.audioCodecs")
    if vals is None:
        return None
    vc, ac = vals
    if not isinstance(vc, list) or not isinstance(ac, list):
        return {"media.videoCodecs": vc, "media.audioCodecs": ac}
    vc_l = {str(c).lower() for c in vc}
    ac_l = {str(c).lower() for c in ac}
    if not (vc_l & _VIDEO_CODECS_EXPECTED) or not (ac_l & _AUDIO_CODECS_EXPECTED):
        return {"media.videoCodecs": vc, "media.audioCodecs": ac}
    return "pass"


def _feat06(capture):
    vals = _need(capture, "webrtc.candidates")
    if vals is None:
        return None
    cands = vals[0]
    if not isinstance(cands, list):
        return {"webrtc.candidates": cands}
    leaked = [c for c in cands if isinstance(c, str) and _FULL_IPV4_RE.search(c)]
    if leaked:
        return {"webrtc.candidates": leaked}
    return "pass"


def _feat07(capture):
    vals = _need(capture, "features.batteryApi")
    if vals is None:
        return None
    v = vals[0]
    if v is not True:
        return {"features.batteryApi": v}
    return "pass"


def _feat08(capture):
    vals = _need(capture, "features.offscreenCanvas")
    if vals is None:
        return None
    v = vals[0]
    if v is not True:
        return {"features.offscreenCanvas": v}
    return "pass"


# ---------------------------------------------------------------------------
# TLS / 网络族（CLR-NET-*，6 条）
# ---------------------------------------------------------------------------

def _net01(capture):
    vals = _need(capture, "tls_assert.source")
    if vals is None:
        return None
    source = vals[0]
    if source not in ("tls.peet.ws", "local", "none"):
        return {"tls_assert.source": source}
    ja3 = _dig(capture, "tls_assert.ja3")
    ja4 = _dig(capture, "tls_assert.ja4")
    if source == "none" and (ja3 is not _MISSING or ja4 is not _MISSING):
        return {"tls_assert.source": source, "tls_assert.ja3": ja3,
                "tls_assert.ja4": ja4}
    if source != "none" and ja3 is _MISSING and ja4 is _MISSING:
        return {"tls_assert.source": source}
    return "pass"


def _net02(capture):
    vals = _need(capture, "tls_assert.ja3")
    if vals is None:
        return None
    ja3 = vals[0]
    if not isinstance(ja3, str) or not _JA3_RE.match(ja3):
        return {"tls_assert.ja3": ja3}
    return "pass"


def _net03(capture):
    vals = _need(capture, "tls_assert.ja4")
    if vals is None:
        return None
    ja4 = vals[0]
    if not isinstance(ja4, str) or not _JA4_RE.match(ja4):
        return {"tls_assert.ja4": ja4}
    return "pass"


def _net04(capture):
    vals = _need(capture, "navigator.userAgent", "tls_assert.ja3")
    if vals is None:
        return None
    ua, ja3 = vals
    if _ua_chrome_major(ua) is None:
        return "pass"
    if not isinstance(ja3, str):
        return {"tls_assert.ja3": ja3}
    parts = ja3.split(",")
    if len(parts) != 5:
        return "pass"   # 形状异常由 NET-02 负责
    ciphers = [c for c in parts[1].split("-") if c.isdigit() and int(c) not in _GREASE]
    if ciphers[:3] != ["4865", "4866", "4867"]:
        return {"navigator.userAgent": ua, "tls_assert.ja3": ja3}
    return "pass"


def _net05(capture):
    vals = _need(capture, "navigator.userAgent", "tls_assert.ja4")
    if vals is None:
        return None
    ua, ja4 = vals
    major = _ua_chrome_major(ua)
    if major is None:
        return "pass"
    if not isinstance(ja4, str) or len(ja4) < 3 or not ja4[1:3].isdigit():
        return "pass"   # 形状异常由 NET-03 负责
    if major >= 80 and ja4[1:3] != "13":
        return {"navigator.userAgent": ua, "tls_assert.ja4": ja4}
    return "pass"


def _net06(capture):
    ja3 = _dig(capture, "tls_assert.ja3")
    ja4 = _dig(capture, "tls_assert.ja4")
    if ja3 is _MISSING and ja4 is _MISSING:
        return None     # 两者皆缺：由 NET-01 判定 source 口径，本条记 skipped
    if (ja3 is _MISSING) != (ja4 is _MISSING):
        return {"tls_assert.ja3": None if ja3 is _MISSING else ja3,
                "tls_assert.ja4": None if ja4 is _MISSING else ja4}
    return "pass"


# ---------------------------------------------------------------------------
# 噪声稳定性族（CLR-NOISE-*，6 条）
# ---------------------------------------------------------------------------

def _noise01(capture):
    vals = _need(capture, "canvas.hash_1", "canvas.hash_2")
    if vals is None:
        return None
    h1, h2 = vals
    if h1 != h2:
        return {"canvas.hash_1": h1, "canvas.hash_2": h2}
    return "pass"


def _noise02(capture):
    vals = _need(capture, "canvas.hash_1")
    if vals is None:
        return None
    h = vals[0]
    if not isinstance(h, str) or not h.strip():
        return {"canvas.hash_1": h}
    return "pass"


def _noise03(capture):
    vals = _need(capture, "canvas.hash_2")
    if vals is None:
        return None
    h = vals[0]
    if not isinstance(h, str) or not h.strip():
        return {"canvas.hash_2": h}
    return "pass"


def _noise04(capture):
    vals = _need(capture, "audio.hash")
    if vals is None:
        return None
    h = vals[0]
    if not isinstance(h, str) or not h.strip():
        return {"audio.hash": h}
    return "pass"


def _noise05(capture):
    vals = _need(capture, "canvas.hash_1", "audio.hash")
    if vals is None:
        return None
    h1, ha = vals
    if not isinstance(h1, str) or not isinstance(ha, str) or not h1 or not ha:
        return "pass"   # 空值由 NOISE-02/04 负责
    if h1 == ha:
        return {"canvas.hash_1": h1, "audio.hash": ha}
    return "pass"


def _noise06(capture):
    vals = _need(capture, "canvas.read_ms")
    if vals is None:
        return None
    ms = vals[0]
    if not isinstance(ms, int) or isinstance(ms, bool) or ms < 1200 or ms > 60000:
        return {"canvas.read_ms": ms}
    return "pass"


# ---------------------------------------------------------------------------
# 清单本体（78 条；配额 UA10/TZ8/SCR8/GPU10/FONT6/HW6/BOT10/FEAT8/NET6/NOISE6）
# ---------------------------------------------------------------------------

CHECKLIST_V1: list[ClrCheck] = [
    # ---- UA / Sec-CH-UA 族 ----
    ClrCheck("CLR-UA-01", ["navigator.userAgent", "sec_ch_ua.brands"], "creepjs",
             "UA 声称的 Chrome 主版本须在 Sec-CH-UA brands 的 Chromium/Google Chrome 条目中出现",
             "critical", _ua01),
    ClrCheck("CLR-UA-02", ["navigator.userAgent", "navigator.platform"], "browserleaks",
             "UA 声称的 OS 族须与 navigator.platform 指向的 OS 族一致"
             "（如 UA 称 Linux 而 platform 称 Win32 即矛盾）",
             "critical", _ua02),
    ClrCheck("CLR-UA-03", ["sec_ch_ua.platform", "navigator.platform"], "browserleaks",
             "Sec-CH-UA-Platform 与 navigator.platform 须指向同一 OS 族",
             "major", _ua03),
    ClrCheck("CLR-UA-04", ["navigator.userAgent", "sec_ch_ua.platform"], "incolumitas",
             "UA 声称的 OS 族须与 Sec-CH-UA-Platform 一致（UA↔客户端提示跨层互洽）",
             "major", _ua04),
    ClrCheck("CLR-UA-05", ["navigator.userAgent", "sec_ch_ua.uaFullVersion"], "creepjs",
             "uaFullVersion 的主版本须与 UA 声称的 Chrome 主版本一致",
             "major", _ua05),
    ClrCheck("CLR-UA-06", ["navigator.userAgent", "cross_reads.ua_worker"], "creepjs",
             "主线程与 Worker 读到的 userAgent 必须一致（多路径读值不一致即谎言）",
             "critical", _ua06),
    ClrCheck("CLR-UA-07", ["navigator.userAgent", "cross_reads.ua_iframe"], "creepjs",
             "主线程与同源 iframe 读到的 userAgent 必须一致",
             "critical", _ua07),
    ClrCheck("CLR-UA-08", ["navigator.userAgent", "sec_ch_ua.mobile"], "browserleaks",
             "UA 中的 Mobile 标记与 Sec-CH-UA-Mobile 布尔必须同真同假",
             "major", _ua08),
    ClrCheck("CLR-UA-09", ["navigator.userAgent", "navigator.vendor"], "browserleaks",
             "UA 声称 Chrome 时 navigator.vendor 必须为 Google Inc.",
             "major", _ua09),
    ClrCheck("CLR-UA-10", ["sec_ch_ua.fullVersionList", "sec_ch_ua.uaFullVersion"], "incolumitas",
             "fullVersionList 中 Chromium/Google Chrome 条目的完整版本须等于 uaFullVersion",
             "major", _ua10),
    # ---- 时区 / locale 族 ----
    ClrCheck("CLR-TZ-01", ["intl.timeZone", "intl.tzOffsetMinutes"], "browserleaks",
             "IANA 时区在采集日的合法 UTC 偏移（含 DST）须覆盖 tzOffsetMinutes 实读值",
             "critical", _tz01),
    ClrCheck("CLR-TZ-02", ["intl.timeZone", "cross_reads.tz_iframe"], "creepjs",
             "主线程与同源 iframe 读到的时区必须一致",
             "critical", _tz02),
    ClrCheck("CLR-TZ-03", ["navigator.languages", "intl.locale"], "browserleaks",
             "navigator.languages 首项的语言子标签须与 Intl locale 的语言子标签一致",
             "major", _tz03),
    ClrCheck("CLR-TZ-04", ["navigator.languages", "cross_reads.languages_worker"], "creepjs",
             "主线程与 Worker 读到的 languages 列表必须一致",
             "critical", _tz04),
    ClrCheck("CLR-TZ-05", ["intl.timeZone", "intl.locale", "navigator.languages"], "browserleaks",
             "时区地区与 locale 地区矛盾且语言链无法解释（如 Asia/Shanghai + en-US + 无 zh 语言链）",
             "major", _tz05),
    ClrCheck("CLR-TZ-06", ["intl.tzOffsetMinutes"], "browserleaks",
             "tzOffsetMinutes 须为 15 的倍数且落在真实时区偏移域 [-840, 720] 内",
             "major", _tz06),
    ClrCheck("CLR-TZ-07", ["navigator.languages"], "creepjs",
             "languages 列表不得有重复项，且每项须为合法 BCP47 形（真实浏览器语言列表无重复）",
             "major", _tz07),
    ClrCheck("CLR-TZ-08", ["intl.timeZone"], "browserleaks",
             "timeZone 须为合法 IANA 名形（含 '/' 或为 UTC），伪造时区常出现非法字符串",
             "minor", _tz08),
    # ---- 屏幕 / DPR 族 ----
    ClrCheck("CLR-SCR-01", ["screen.width", "screen.height", "screen.availWidth", "screen.availHeight"],
             "browserleaks",
             "可用屏幕区域不得大于物理屏幕（availWidth/availHeight ≤ width/height）",
             "major", _scr01),
    ClrCheck("CLR-SCR-02", ["screen.colorDepth", "screen.pixelDepth"], "browserleaks",
             "colorDepth 与 pixelDepth 必须一致（真实 Chrome 二者恒等，不一致是经典改写破绽）",
             "major", _scr02),
    ClrCheck("CLR-SCR-03", ["screen.innerWidth", "screen.innerHeight",
                            "screen.outerWidth", "screen.outerHeight"], "browserleaks",
             "窗口内部尺寸不得大于外部尺寸（inner ≤ outer）",
             "major", _scr03),
    ClrCheck("CLR-SCR-04", ["screen.outerWidth", "screen.outerHeight",
                            "screen.width", "screen.height"], "browserleaks",
             "窗口外部尺寸不得大于物理屏幕（outer ≤ screen，全屏允许相等）",
             "major", _scr04),
    ClrCheck("CLR-SCR-05", ["screen.devicePixelRatio"], "tishen",
             "devicePixelRatio 须在 {1.0, 1.25, 1.5, 2.0} 内（沿用出厂 V4：真实设备几乎只用这几档）",
             "major", _scr05),
    ClrCheck("CLR-SCR-06", ["screen.width", "screen.height"], "tishen",
             "分辨率须在常见真实分辨率集内（沿用出厂 V4：奇葩分辨率是自动化/虚拟环境典型特征）",
             "minor", _scr06),
    ClrCheck("CLR-SCR-07", ["screen.width", "screen.height"], "sannysoft",
             "分辨率不得为 800×600（旧版 headless Chrome 的默认窗口尺寸，经典 headless 红项）",
             "major", _scr07),
    ClrCheck("CLR-SCR-08", ["screen.colorDepth"], "browserleaks",
             "colorDepth 须为真实取值档（15/16/24/30/32 之一），诡异色深是伪造信号",
             "minor", _scr08),
    # ---- GPU / WebGL 族 ----
    ClrCheck("CLR-GPU-01", ["webgl.version"], "browserleaks",
             "WEBGL_version 字符串须以 \"WebGL \" 开头（真实 Chrome 形状：WebGL 1.0/2.0 (...)）",
             "major", _gpu01),
    ClrCheck("CLR-GPU-02", ["webgl.glslVersion"], "browserleaks",
             "SHADING_LANGUAGE_VERSION 字符串须含 \"WebGL GLSL ES\"",
             "major", _gpu02),
    ClrCheck("CLR-GPU-03", ["webgl.version", "webgl.glslVersion"], "browserleaks",
             "WebGL 代数与 GLSL 代数必须配套（WebGL 1.0↔GLSL ES 1.0，WebGL 2.0↔GLSL ES 3.0）",
             "major", _gpu03),
    ClrCheck("CLR-GPU-04", ["navigator.platform", "webgl.unmaskedRenderer"], "tishen",
             "Linux 平台真实 Chrome 的 unmaskedRenderer 必须以 \"ANGLE (\" 开头"
             "（Linux 容器 ANGLE 特征；裸 GL 渲染器字符串是软渲染/伪造信号）",
             "critical", _gpu04),
    ClrCheck("CLR-GPU-05", ["navigator.userAgent", "webgl.unmaskedVendor", "webgl.unmaskedRenderer"],
             "browserleaks",
             "Chrome 的 unmaskedVendor 须为 \"Google Inc. (<厂商>)\" 形，"
             "且括号内厂商名须出现在 unmaskedRenderer 中",
             "major", _gpu05),
    ClrCheck("CLR-GPU-06", ["webgl.maxTextureSize"], "browserleaks",
             "MAX_TEXTURE_SIZE 须为 2 的幂且落在 [2048, 32768] 真实 GPU 档位内",
             "minor", _gpu06),
    ClrCheck("CLR-GPU-07", ["webgl.maxViewportDims"], "browserleaks",
             "MAX_VIEWPORT_DIMS 须为两元素数组，每维落在 [2048, 65536] 内",
             "minor", _gpu07),
    ClrCheck("CLR-GPU-08", ["webgl.maxVertexAttribs"], "browserleaks",
             "MAX_VERTEX_ATTRIBS 须为真实档位（8/16/32，GLES2 实现几乎恒为 16）",
             "minor", _gpu08),
    ClrCheck("CLR-GPU-09", ["webgl.maxCombinedTextureImageUnits"], "browserleaks",
             "MAX_COMBINED_TEXTURE_IMAGE_UNITS 须落在 [8, 256] 真实区间内",
             "minor", _gpu09),
    ClrCheck("CLR-GPU-10", ["webgl.extensions"], "creepjs",
             "WebGL 扩展列表须非空、无重复且按字典序排列（真实 Chrome 返回有序去重列表，"
             "追加/乱序是扩展枚举被改写的痕迹）",
             "major", _gpu10),
    # ---- 字体族 ----
    ClrCheck("CLR-FONT-01", ["fonts"], "browserleaks",
             "探测到的字体列表不得含重复项（重复是探测脚本或伪造上报的痕迹）",
             "major", _font01),
    ClrCheck("CLR-FONT-02", ["navigator.platform", "fonts"], "browserleaks",
             "声明 Linux 平台不得出现 Windows/macOS 独占字体"
             "（Segoe UI、Calibri、Consolas、San Francisco、Monaco 等）",
             "critical", _font02),
    ClrCheck("CLR-FONT-03", ["navigator.platform", "fonts"], "browserleaks",
             "声明 Linux 平台时字体集应至少命中一款 Linux 桌面常见字体"
             "（DejaVu/Liberation/Noto/Ubuntu 等），全无命中与平台画像矛盾",
             "minor", _font03),
    ClrCheck("CLR-FONT-04", ["intl.locale", "fonts"], "tishen",
             "locale 为 zh/ja/ko 时字体集必须含 CJK 字体（沿用出厂 V7："
             "CJK 用户画像的系统必然装有 CJK 字体）",
             "major", _font04),
    ClrCheck("CLR-FONT-05", ["fonts"], "creepjs",
             "字体探测结果不得为空列表（真实桌面浏览器必然存在系统字体，"
             "空集是字体面被整体屏蔽的 resistance 痕迹）",
             "major", _font05),
    ClrCheck("CLR-FONT-06", ["fonts"], "creepjs",
             "字体列表元素均须为非空字符串（空串/空白项是伪造上报的痕迹）",
             "minor", _font06),
    # ---- 硬件并发 / 内存 / 跨路径读值族 ----
    ClrCheck("CLR-HW-01", ["navigator.hardwareConcurrency", "navigator.deviceMemory"], "tishen",
             "hardwareConcurrency→deviceMemory 必须落在合法对表 "
             "{(2,{2,4}),(4,{2,4,8}),(6,{4,8}),(8,{4,8,16}),(12,{8,16}),(16,{16})} 内"
             "（沿用出厂 V5：核数与内存搭配须符合真实硬件分布）",
             "critical", _hw01),
    ClrCheck("CLR-HW-02", ["navigator.hardwareConcurrency"], "tishen",
             "hardwareConcurrency 本身须为常见档位 {2,4,6,8,12,16}（沿用出厂 V5）",
             "major", _hw02),
    ClrCheck("CLR-HW-03", ["navigator.hardwareConcurrency", "cross_reads.hwc_worker"], "creepjs",
             "主线程与 Worker 读到的 hardwareConcurrency 必须一致",
             "critical", _hw03),
    ClrCheck("CLR-HW-04", ["navigator.hardwareConcurrency", "cross_reads.hwc_iframe"], "creepjs",
             "主线程与同源 iframe 读到的 hardwareConcurrency 必须一致",
             "critical", _hw04),
    ClrCheck("CLR-HW-05", ["navigator.platform", "cross_reads.platform_worker"], "creepjs",
             "主线程与 Worker 读到的 platform 必须一致",
             "critical", _hw05),
    ClrCheck("CLR-HW-06", ["navigator.platform", "cross_reads.platform_iframe"], "creepjs",
             "主线程与同源 iframe 读到的 platform 必须一致",
             "critical", _hw06),
    # ---- webdriver / CDP / 自动化痕迹族 ----
    ClrCheck("CLR-BOT-01", ["navigator.webdriver"], "sannysoft",
             "navigator.webdriver 必须为 false（true 是自动化驱动的直接红项）",
             "critical", _bot01),
    ClrCheck("CLR-BOT-02", ["cdp_traces.runtimeEnableArtifacts"], "sannysoft",
             "不得存在 CDP Runtime.enable 痕迹（测量零污染原则的对偶检查）",
             "critical", _bot02),
    ClrCheck("CLR-BOT-03", ["cdp_traces.consoleLogArtifacts"], "sannysoft",
             "console 序列化不得存在 CDP 痕迹",
             "major", _bot03),
    ClrCheck("CLR-BOT-04", ["cdp_traces.stackTracesContainCdp"], "sannysoft",
             "异常堆栈不得含 CDP 调用帧",
             "major", _bot04),
    ClrCheck("CLR-BOT-05", ["navigator.pdfViewerEnabled"], "sannysoft",
             "pdfViewerEnabled 必须为 true（真实桌面 Chrome 内置 PDF 查看器恒开；"
             "false 常见于 headless/篡改环境）",
             "minor", _bot05),
    ClrCheck("CLR-BOT-06", ["navigator.languages"], "sannysoft",
             "navigator.languages 必须非空（空 languages 是旧 headless/自动化环境的经典红项）",
             "major", _bot06),
    ClrCheck("CLR-BOT-07", ["navigator.userAgent"], "sannysoft",
             "UA 不得含 HeadlessChrome 字样",
             "critical", _bot07),
    ClrCheck("CLR-BOT-08", ["navigator.userAgent"], "creepjs",
             "UA 不得含已知自动化框架标识（PhantomJS/Selenium/Puppeteer/Playwright/jsdom 等）",
             "critical", _bot08),
    ClrCheck("CLR-BOT-09", ["navigator.userAgent", "sec_ch_ua.brands"], "incolumitas",
             "UA 声称 Chrome 时 brands 必须含 GREASE 的 \"Not\" 系品牌项"
             "（真实 Chrome 客户端提示恒带 GREASE 项，缺失=客户端提示为手工伪造）",
             "major", _bot09),
    ClrCheck("CLR-BOT-10", ["permissions"], "creepjs",
             "permissions 各值必须落在 {granted, denied, prompt} 值域内"
             "（越界值说明 Permissions API 被改写）",
             "major", _bot10),
    # ---- 存储 / 权限 / 特性族 ----
    ClrCheck("CLR-FEAT-01", ["features.pointerCoarse", "features.pointerFine"], "browserleaks",
             "pointerCoarse 与 pointerFine 不得同时为 false（任何真实设备至少匹配一种指针）",
             "minor", _feat01),
    ClrCheck("CLR-FEAT-02", ["sec_ch_ua.mobile", "features.pointerCoarse"], "browserleaks",
             "声称桌面端（mobile=false）不得报粗指针（pointerCoarse=true 与桌面画像矛盾）",
             "major", _feat02),
    ClrCheck("CLR-FEAT-03", ["storage.localStorage", "storage.sessionStorage"], "browserleaks",
             "localStorage 与 sessionStorage 可用性必须一致"
             "（同源 API 同受 cookie/站点数据开关控制，一开一关是选择性篡改）",
             "minor", _feat03),
    ClrCheck("CLR-FEAT-04", ["media.devices", "permissions"], "browserleaks",
             "媒体设备 label 非空时对应权限不得为 denied"
             "（真实浏览器在权限 denied 下枚举不到设备 label，二者同现即矛盾）",
             "major", _feat04),
    ClrCheck("CLR-FEAT-05", ["media.videoCodecs", "media.audioCodecs"], "browserleaks",
             "视频/音频编解码列表须至少命中一款真实浏览器常见编码（vp8/vp9/h264、opus/aac 等），"
             "全空或全生僻编码是媒体能力面被清空的信号",
             "minor", _feat05),
    ClrCheck("CLR-FEAT-06", ["webrtc.candidates"], "tishen",
             "WebRTC candidates 不得出现完整 IPv4 地址（采集契约要求打码末段；"
             "完整地址即真实出口/内网泄露）",
             "critical", _feat06),
    ClrCheck("CLR-FEAT-07", ["features.batteryApi"], "creepjs",
             "桌面 Chrome 原生具备 Battery API（batteryApi=false 是 API 被移除的 resistance 改写模式）",
             "minor", _feat07),
    ClrCheck("CLR-FEAT-08", ["features.offscreenCanvas"], "creepjs",
             "现代 Chrome 原生支持 OffscreenCanvas（offscreenCanvas=false 是 API 被移除的改写痕迹）",
             "minor", _feat08),
    # ---- TLS / 网络族 ----
    ClrCheck("CLR-NET-01", ["tls_assert.source", "tls_assert.ja3", "tls_assert.ja4"], "incolumitas",
             "tls_assert.source 须为 tls.peet.ws|local|none 合法值，且与 ja3/ja4 的有无自洽"
             "（source=none 却带指纹、或声称已采集却两指纹皆空，均为矛盾）",
             "major", _net01),
    ClrCheck("CLR-NET-02", ["tls_assert.ja3"], "incolumitas",
             "JA3 须为五段逗号分隔的数字串形（版本,密码套件,扩展,曲线,点格式）",
             "minor", _net02),
    ClrCheck("CLR-NET-03", ["tls_assert.ja4"], "incolumitas",
             "JA4 须为标准三段下划线形（如 t13d1516h2_xxxxxxxxxxxx_xxxxxxxxxxxx）",
             "minor", _net03),
    ClrCheck("CLR-NET-04", ["navigator.userAgent", "tls_assert.ja3"], "incolumitas",
             "UA 声称 Chrome 时 JA3 密码套件段（剔除 GREASE 后）须以 4865-4866-4867 开头"
             "（真实 Chrome ClientHello 的 TLS1.3 套件序，UA↔TLS 跨层互洽）",
             "critical", _net04),
    ClrCheck("CLR-NET-05", ["navigator.userAgent", "tls_assert.ja4"], "incolumitas",
             "UA 声称 Chrome ≥80 时 JA4 的 TLS 版本标记须为 13（现代 Chrome 恒提供 TLS1.3）",
             "major", _net05),
    ClrCheck("CLR-NET-06", ["tls_assert.ja3", "tls_assert.ja4"], "incolumitas",
             "JA3 与 JA4 必须同时存在（同一次 TLS 采集同时产出二者；"
             "只存在一个说明采集链被拼接）",
             "major", _net06),
    # ---- 噪声稳定性族 ----
    ClrCheck("CLR-NOISE-01", ["canvas.hash_1", "canvas.hash_2"], "creepjs",
             "同站同会话 canvas 双读 hash 必须一致（不一致=噪声每次随机化，"
             "违背 per-persona 种子语义且可被统计还原）",
             "critical", _noise01),
    ClrCheck("CLR-NOISE-02", ["canvas.hash_1"], "creepjs",
             "canvas 首次读值 hash 不得为空串/空白（空值是采集失败被原样上报或画布输出被清空）",
             "minor", _noise02),
    ClrCheck("CLR-NOISE-03", ["canvas.hash_2"], "creepjs",
             "canvas 第二次读值 hash 不得为空串/空白",
             "minor", _noise03),
    ClrCheck("CLR-NOISE-04", ["audio.hash"], "creepjs",
             "audio hash 不得为空串/空白（空值=音频指纹面被清空，resistance 全屏蔽模式）",
             "minor", _noise04),
    ClrCheck("CLR-NOISE-05", ["canvas.hash_1", "audio.hash"], "tishen",
             "canvas hash 与 audio hash 不得相同（不同原语的噪声输出撞 hash，"
             "说明被统一替换为常量，属 Breaking the Shield 式可还原伪造）",
             "major", _noise05),
    ClrCheck("CLR-NOISE-06", ["canvas.read_ms"], "tishen",
             "canvas 双读间隔须在 [1200, 60000]ms 内（探针契约要求双读间隔≥1200ms；"
             "过小说明双读形同虚设，过大说明上报被伪造）",
             "minor", _noise06),
]
