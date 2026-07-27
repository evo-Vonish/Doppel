"""persona.yaml Schema v1（SPEC §2）：dataclass + YAML 读写 + 结构校验。

契约接口（Coder A 烘焙器直接 import，签名不可变）：
    Persona                          —— 全字段 dataclass
    load(path) -> Persona            —— 读 YAML 构造 Persona
    dump(persona, path) -> None      —— 写 YAML
    validate_structure(persona) -> list[str]
        仅做类型 / 枚举 / 格式校验；跨字段一致性（属地族、硬件搭配、
        版本新鲜度等）属于 linter（tishen.linter）的职责，此处不查。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# 格式常量（SPEC §2 约束列）
# ---------------------------------------------------------------------------

PERSONA_ID_RE = re.compile(r"^p_[a-z0-9_]{4,32}$")          # meta.id
IP_REGION_RE = re.compile(r"^[A-Z]{2}$")                     # ISO 3166-1 alpha-2
CHROME_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")      # 形如 138.0.7204.0
FARBLING_SEED_RE = re.compile(r"^[0-9a-f]{32}$")             # 128-bit 十六进制

HARDWARE_CONCURRENCY_CHOICES = {2, 4, 6, 8, 12, 16}
DEVICE_MEMORY_CHOICES = {2, 4, 8, 16}
DPR_CHOICES = {1.0, 1.25, 1.5, 2.0}
FONT_EXTRAS_CHOICES = {"cjk"}
FARBLING_SCOPE_CHOICES = {"canvas_readback", "webgl_readback", "audio"}
LIFECYCLE_STATES = {"creating", "active", "suspended", "destroyed"}


# ---------------------------------------------------------------------------
# 嵌套 dataclass（与 §2 顶层字段一一对应，除标注可选外全部必填）
# ---------------------------------------------------------------------------

@dataclass
class Meta:
    id: str                  # ^p_[a-z0-9_]{4,32}$
    name: str                # 1–32 字符
    created_at: str          # ISO8601
    # 可选备注：sampler 在 region=auto 且无实测属地、默认 CN 时写入说明（SPEC §4）
    note: str | None = None


@dataclass
class Region:
    follow_ip: bool               # 本期恒 true
    detected_ip_region: str       # ISO 3166-1 alpha-2，如 CN
    locale: str                   # 如 zh-CN
    timezone: str                 # IANA 时区名
    languages: list[str]          # 非空，首项与 locale 一致


@dataclass
class Os:
    family: str              # 本期恒 linux
    distro: str              # 如 ubuntu-24.04
    chrome_channel: str      # 恒 stable


@dataclass
class Gpu:
    mode: str                       # 恒 host_passthrough
    renderer_string_source: str     # 恒 real


@dataclass
class Hardware:
    gpu: Gpu
    hardwareConcurrency: int   # {2,4,6,8,12,16}
    deviceMemory: int          # {2,4,8,16}


@dataclass
class Display:
    width: int
    height: int
    dpr: float                 # {1.0, 1.25, 1.5, 2.0}


@dataclass
class Fonts:
    pack: str                     # 字体包集，与 os.family 匹配（linter V7）
    extras: list[str] = field(default_factory=list)   # 可空，元素 ∈ {cjk}


@dataclass
class Webrtc:
    ip_handling_policy: str    # 恒 disable_non_proxied_udp


@dataclass
class Farbling:
    seed: str                # 32 位十六进制（128-bit）
    scope: list[str]         # 子集 of {canvas_readback, webgl_readback, audio}


@dataclass
class Evolution:
    strategy: str            # 恒 anchor_chrome_version
    baseline_chrome: str     # 形如 138.0.7204.0
    drift_policy: str        # 恒 follow_stable_diff


@dataclass
class Storage:
    profile_volume: str      # docker 卷名（信誉资产）
    log_volume: str          # docker 卷名
    retain_days: int         # ≥1


@dataclass
class Monitoring:
    keylog: bool             # 恒 true
    log_encryption: str      # 恒 age


@dataclass
class Lifecycle:
    state: str               # ∈ {creating, active, suspended, destroyed}


@dataclass
class Persona:
    version: int             # 恒为 1
    meta: Meta
    region: Region
    os: Os
    hardware: Hardware
    display: Display
    fonts: Fonts
    webrtc: Webrtc
    farbling: Farbling
    evolution: Evolution
    proxy: str | None        # 本期恒 null
    storage: Storage
    monitoring: Monitoring
    lifecycle: Lifecycle


# ---------------------------------------------------------------------------
# YAML 读写
# ---------------------------------------------------------------------------

def _require(data: dict, key: str, path: str):
    """取必填字段；缺失时报中文错误并指出完整路径。"""
    if not isinstance(data, dict) or key not in data:
        raise ValueError(f"persona 缺少必填字段：{path}")
    return data[key]


def _coerce_created_at(v) -> str:
    """created_at 容错：YAML 会把未加引号的 ISO8601 时间解析成 datetime，
    统一归一为 ISO8601 字符串（schema 定义为 str）。"""
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def _from_dict(d: dict) -> Persona:
    """dict → Persona。只做结构装配，不做合法性校验（校验走 validate_structure）。"""
    meta = _require(d, "meta", "meta")
    region = _require(d, "region", "region")
    os_ = _require(d, "os", "os")
    hardware = _require(d, "hardware", "hardware")
    gpu = _require(hardware, "gpu", "hardware.gpu")
    display = _require(d, "display", "display")
    fonts = _require(d, "fonts", "fonts")
    webrtc = _require(d, "webrtc", "webrtc")
    farbling = _require(d, "farbling", "farbling")
    evolution = _require(d, "evolution", "evolution")
    storage = _require(d, "storage", "storage")
    monitoring = _require(d, "monitoring", "monitoring")
    lifecycle = _require(d, "lifecycle", "lifecycle")

    return Persona(
        version=_require(d, "version", "version"),
        meta=Meta(
            id=_require(meta, "id", "meta.id"),
            name=_require(meta, "name", "meta.name"),
            created_at=_coerce_created_at(_require(meta, "created_at", "meta.created_at")),
            note=meta.get("note"),  # 可选
        ),
        region=Region(
            follow_ip=_require(region, "follow_ip", "region.follow_ip"),
            detected_ip_region=_require(region, "detected_ip_region", "region.detected_ip_region"),
            locale=_require(region, "locale", "region.locale"),
            timezone=_require(region, "timezone", "region.timezone"),
            languages=_require(region, "languages", "region.languages"),
        ),
        os=Os(
            family=_require(os_, "family", "os.family"),
            distro=_require(os_, "distro", "os.distro"),
            chrome_channel=_require(os_, "chrome_channel", "os.chrome_channel"),
        ),
        hardware=Hardware(
            gpu=Gpu(
                mode=_require(gpu, "mode", "hardware.gpu.mode"),
                renderer_string_source=_require(
                    gpu, "renderer_string_source", "hardware.gpu.renderer_string_source"),
            ),
            hardwareConcurrency=_require(hardware, "hardwareConcurrency", "hardware.hardwareConcurrency"),
            deviceMemory=_require(hardware, "deviceMemory", "hardware.deviceMemory"),
        ),
        display=Display(
            width=_require(display, "width", "display.width"),
            height=_require(display, "height", "display.height"),
            dpr=_require(display, "dpr", "display.dpr"),
        ),
        fonts=Fonts(
            pack=_require(fonts, "pack", "fonts.pack"),
            extras=fonts.get("extras") or [],  # 可空
        ),
        webrtc=Webrtc(
            ip_handling_policy=_require(webrtc, "ip_handling_policy", "webrtc.ip_handling_policy"),
        ),
        farbling=Farbling(
            seed=_require(farbling, "seed", "farbling.seed"),
            scope=_require(farbling, "scope", "farbling.scope"),
        ),
        evolution=Evolution(
            strategy=_require(evolution, "strategy", "evolution.strategy"),
            baseline_chrome=_require(evolution, "baseline_chrome", "evolution.baseline_chrome"),
            drift_policy=_require(evolution, "drift_policy", "evolution.drift_policy"),
        ),
        proxy=d.get("proxy"),  # 本期恒 null
        storage=Storage(
            profile_volume=_require(storage, "profile_volume", "storage.profile_volume"),
            log_volume=_require(storage, "log_volume", "storage.log_volume"),
            retain_days=_require(storage, "retain_days", "storage.retain_days"),
        ),
        monitoring=Monitoring(
            keylog=_require(monitoring, "keylog", "monitoring.keylog"),
            log_encryption=_require(monitoring, "log_encryption", "monitoring.log_encryption"),
        ),
        lifecycle=Lifecycle(
            state=_require(lifecycle, "state", "lifecycle.state"),
        ),
    )


def load(path) -> Persona:
    """从 YAML 文件加载 Persona。结构损坏（缺字段/YAML 非法）抛 ValueError。"""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"persona 文件不是合法的 YAML 映射：{p}")
    try:
        return _from_dict(data)
    except ValueError as e:
        raise ValueError(f"{p}: {e}") from e


def dump(persona: Persona, path) -> None:
    """Persona → YAML 文件。meta.note 为 None 时不落盘（保持 schema 最小集）。"""
    data = asdict(persona)
    if data["meta"].get("note") is None:
        del data["meta"]["note"]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# 结构校验：仅类型 / 枚举 / 格式，不查跨字段一致性（那是 linter 的事）
# ---------------------------------------------------------------------------

def _is_str(v) -> bool:
    return isinstance(v, str)


def _is_int(v) -> bool:
    # bool 是 int 子类，显式排除
    return isinstance(v, int) and not isinstance(v, bool)


def validate_structure(persona: Persona) -> list[str]:
    """返回结构错误列表（中文消息），空列表表示结构合法。"""
    errors: list[str] = []

    def err(field_path: str, msg: str) -> None:
        errors.append(f"{field_path}: {msg}")

    # version：恒为 1
    if not _is_int(persona.version) or persona.version != 1:
        err("version", f"必须为整数 1，实际为 {persona.version!r}")

    # meta
    m = persona.meta
    if not _is_str(m.id) or not PERSONA_ID_RE.match(m.id):
        err("meta.id", f"须匹配 ^p_[a-z0-9_]{{4,32}}$，实际为 {m.id!r}")
    if not _is_str(m.name) or not (1 <= len(m.name) <= 32):
        err("meta.name", f"须为 1–32 字符字符串，实际为 {m.name!r}")
    if not _is_str(m.created_at):
        err("meta.created_at", f"须为 ISO8601 字符串，实际为 {m.created_at!r}")
    else:
        try:
            datetime.fromisoformat(m.created_at)
        except ValueError:
            err("meta.created_at", f"不是合法的 ISO8601 时间：{m.created_at!r}")
    if m.note is not None and not _is_str(m.note):
        err("meta.note", f"可选备注须为字符串，实际为 {m.note!r}")

    # region
    r = persona.region
    if not isinstance(r.follow_ip, bool) or r.follow_ip is not True:
        err("region.follow_ip", f"本期恒为 true，实际为 {r.follow_ip!r}")
    if not _is_str(r.detected_ip_region) or not IP_REGION_RE.match(r.detected_ip_region):
        err("region.detected_ip_region",
            f"须为 ISO 3166-1 alpha-2（两位大写字母），实际为 {r.detected_ip_region!r}")
    if not _is_str(r.locale) or not r.locale:
        err("region.locale", f"须为非空字符串（如 zh-CN），实际为 {r.locale!r}")
    if not _is_str(r.timezone) or not r.timezone:
        err("region.timezone", f"须为 IANA 时区名，实际为 {r.timezone!r}")
    if not isinstance(r.languages, list) or not r.languages \
            or not all(_is_str(x) for x in r.languages):
        err("region.languages", f"须为非空字符串列表，实际为 {r.languages!r}")
    elif _is_str(r.locale) and r.languages[0] != r.locale:
        err("region.languages",
            f"首项须与 locale 一致（{r.locale!r}），实际首项为 {r.languages[0]!r}")

    # os
    o = persona.os
    if not _is_str(o.family) or o.family != "linux":
        err("os.family", f"本期恒为 linux，实际为 {o.family!r}")
    if not _is_str(o.distro) or not o.distro:
        err("os.distro", f"须为非空字符串（如 ubuntu-24.04），实际为 {o.distro!r}")
    if not _is_str(o.chrome_channel) or o.chrome_channel != "stable":
        err("os.chrome_channel", f"恒为 stable，实际为 {o.chrome_channel!r}")

    # hardware
    g = persona.hardware.gpu
    if not _is_str(g.mode) or g.mode != "host_passthrough":
        err("hardware.gpu.mode", f"恒为 host_passthrough，实际为 {g.mode!r}")
    if not _is_str(g.renderer_string_source) or g.renderer_string_source != "real":
        err("hardware.gpu.renderer_string_source",
            f"恒为 real（禁撒谎），实际为 {g.renderer_string_source!r}")
    hc = persona.hardware.hardwareConcurrency
    if not _is_int(hc) or hc not in HARDWARE_CONCURRENCY_CHOICES:
        err("hardware.hardwareConcurrency",
            f"须为 {sorted(HARDWARE_CONCURRENCY_CHOICES)} 之一，实际为 {hc!r}")
    dm = persona.hardware.deviceMemory
    if not _is_int(dm) or dm not in DEVICE_MEMORY_CHOICES:
        err("hardware.deviceMemory",
            f"须为 {sorted(DEVICE_MEMORY_CHOICES)} 之一，实际为 {dm!r}")

    # display（分辨率组合是否真实属跨字段判断，归 linter V4；此处只查类型与 dpr 枚举）
    d = persona.display
    if not _is_int(d.width) or d.width <= 0:
        err("display.width", f"须为正整数，实际为 {d.width!r}")
    if not _is_int(d.height) or d.height <= 0:
        err("display.height", f"须为正整数，实际为 {d.height!r}")
    if not isinstance(d.dpr, (int, float)) or isinstance(d.dpr, bool) \
            or float(d.dpr) not in DPR_CHOICES:
        err("display.dpr", f"须为 {sorted(DPR_CHOICES)} 之一，实际为 {d.dpr!r}")

    # fonts
    fo = persona.fonts
    if not _is_str(fo.pack) or not fo.pack:
        err("fonts.pack", f"须为非空字符串，实际为 {fo.pack!r}")
    if not isinstance(fo.extras, list) or not all(_is_str(x) for x in fo.extras) \
            or not set(fo.extras) <= FONT_EXTRAS_CHOICES:
        err("fonts.extras", f"元素须 ∈ {sorted(FONT_EXTRAS_CHOICES)}（可空），实际为 {fo.extras!r}")

    # webrtc（枚举值由 linter V9 判定；此处查类型）
    if not _is_str(persona.webrtc.ip_handling_policy):
        err("webrtc.ip_handling_policy",
            f"须为字符串，实际为 {persona.webrtc.ip_handling_policy!r}")

    # farbling
    fa = persona.farbling
    if not _is_str(fa.seed) or not FARBLING_SEED_RE.match(fa.seed):
        err("farbling.seed", f"须为 32 位小写十六进制（128-bit），实际为 {fa.seed!r}")
    if not isinstance(fa.scope, list) or not all(_is_str(x) for x in fa.scope) \
            or not set(fa.scope) <= FARBLING_SCOPE_CHOICES:
        err("farbling.scope",
            f"须为 {sorted(FARBLING_SCOPE_CHOICES)} 的子集，实际为 {fa.scope!r}")

    # evolution
    ev = persona.evolution
    if not _is_str(ev.strategy) or ev.strategy != "anchor_chrome_version":
        err("evolution.strategy", f"恒为 anchor_chrome_version，实际为 {ev.strategy!r}")
    if not _is_str(ev.baseline_chrome) or not CHROME_VERSION_RE.match(ev.baseline_chrome):
        err("evolution.baseline_chrome",
            f"须为形如 138.0.7204.0 的四段版本号，实际为 {ev.baseline_chrome!r}")
    if not _is_str(ev.drift_policy) or ev.drift_policy != "follow_stable_diff":
        err("evolution.drift_policy", f"恒为 follow_stable_diff，实际为 {ev.drift_policy!r}")

    # proxy：本期恒 null 或字符串（格式合法性归 linter V10）
    if persona.proxy is not None and not _is_str(persona.proxy):
        err("proxy", f"须为 null 或字符串，实际为 {persona.proxy!r}")

    # storage
    st = persona.storage
    if not _is_str(st.profile_volume) or not st.profile_volume:
        err("storage.profile_volume", f"须为 docker 卷名字符串，实际为 {st.profile_volume!r}")
    if not _is_str(st.log_volume) or not st.log_volume:
        err("storage.log_volume", f"须为 docker 卷名字符串，实际为 {st.log_volume!r}")
    if not _is_int(st.retain_days) or st.retain_days < 1:
        err("storage.retain_days", f"须为 ≥1 的整数，实际为 {st.retain_days!r}")

    # monitoring
    mo = persona.monitoring
    if not isinstance(mo.keylog, bool) or mo.keylog is not True:
        err("monitoring.keylog", f"恒为 true，实际为 {mo.keylog!r}")
    if not _is_str(mo.log_encryption) or mo.log_encryption != "age":
        err("monitoring.log_encryption", f"恒为 age，实际为 {mo.log_encryption!r}")

    # lifecycle
    if not _is_str(persona.lifecycle.state) \
            or persona.lifecycle.state not in LIFECYCLE_STATES:
        err("lifecycle.state",
            f"须 ∈ {sorted(LIFECYCLE_STATES)}，实际为 {persona.lifecycle.state!r}")

    return errors
