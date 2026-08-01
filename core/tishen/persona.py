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

# 演化枚举（演化方案 §二）：channel=发布通道画像，delay_model=升级时机画像
EVOLUTION_CHANNEL_CHOICES = {"stable", "extended_stable"}
EVOLUTION_DELAY_MODEL_CHOICES = {"mainstream", "laggard", "enterprise"}


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
class EvolutionSchedule:
    """升级时机画像（演化方案 §二 schedule 块）。整块可缺省，字段取缺省值。

    next_upgrade_not_before 为时机闸门日期（YYYY-MM-DD），None 表示未设闸门。
    """

    delay_model: str = "mainstream"              # mainstream / laggard / enterprise
    next_upgrade_not_before: str | None = None   # YYYY-MM-DD，可空


@dataclass
class Evolution:
    """演化数据模型（演化方案 §二）。

    前三字段为既有锚定字段；current_chrome/channel/schedule/history 为演化扩展，
    既有 persona.yaml（无新字段）加载后全部取缺省（current_chrome 回填 baseline_chrome）。
    缺省口径（§二）：schedule/history 整块可缺省——不仅 yaml 缺段，显式构造传 None
    （含 yaml 写 `schedule: null`）也在 __post_init__ 统一回填缺省实例
    （schedule=delay_model mainstream、无时机闸门；history=空表），下游消费方
    （校验/gate/CLI）可假设两字段永不为 None。
    history 为履历条目 dict 列表（审计链，键见 §二示例：from/to/at/stable_release_date/
    drift_pack/clr_after/diff_audit）；rollback=true 的回滚条目合法（方案 §七.3：
    回滚本身违反单调增，仅允许 24h 内且诚实留痕），结构校验不拒绝，
    由 count_rollbacks() 计数供 CLI/审计面警告展示。
    """

    strategy: str            # 恒 anchor_chrome_version
    baseline_chrome: str     # 形如 138.0.7204.0（出生基线，档案身份锚，不变）
    drift_policy: str        # 恒 follow_stable_diff
    current_chrome: str = ""               # 当前版本；空串占位，_from_dict 回填 baseline
    channel: str = "stable"                # stable / extended_stable
    schedule: EvolutionSchedule = field(default_factory=EvolutionSchedule)
    history: list[dict] = field(default_factory=list)   # 演化履历（审计链）

    def __post_init__(self) -> None:
        # current_chrome 缺省 = baseline_chrome（未演化的 persona 当前版=出生基线）
        if not self.current_chrome:
            self.current_chrome = self.baseline_chrome
        # schedule/history 整块缺省（None）统一回填缺省实例（§二缺省口径，
        # 见类 docstring）——加载期 _evolution_from_dict 与显式构造两条路径都覆盖
        if self.schedule is None:
            self.schedule = EvolutionSchedule()
        if self.history is None:
            self.history = []


def count_rollbacks(evolution: Evolution) -> int:
    """统计 history 中 rollback=true 的回滚条目数（演化方案 §七.3）。

    回滚=切回旧镜像（冻结参数不变），本身违反版本单调增，故仅允许演化后 24h 内
    且必须在 history 诚实留痕。结构校验不拒绝回滚条目，由本计数供 CLI/审计面
    给出警告展示（>0 即提示人工复核）。
    """
    return sum(1 for h in evolution.history
               if isinstance(h, dict) and h.get("rollback") is True)


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
    proxy: str | None        # 可选显式 http/socks5 代理（格式由 linter V10 约束）
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


def _chrome_version_key(v: str) -> tuple[int, ...] | None:
    """四段版本号 → 数值比较元组（如 138.0.7204.0 → (138, 0, 7204, 0)）。

    非法格式返回 None。版本比较一律走元组数值比较，禁止字符串比较
    （"138.0.7204.10" > "138.0.7204.2" 在字符串序下不成立）。
    """
    if not isinstance(v, str) or not CHROME_VERSION_RE.match(v):
        return None
    return tuple(int(seg) for seg in v.split("."))


def _is_date_str(v) -> bool:
    """YYYY-MM-DD 合法日期字符串判定。"""
    if not isinstance(v, str):
        return False
    try:
        datetime.strptime(v, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _coerce_created_at(v) -> str:
    """created_at 容错：YAML 会把未加引号的 ISO8601 时间解析成 datetime，
    统一归一为 ISO8601 字符串（schema 定义为 str）。"""
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def _evolution_from_dict(evolution: dict) -> Evolution:
    """dict → Evolution。扩展字段（§二）整块可缺省，缺省取默认值。"""
    baseline = _require(evolution, "baseline_chrome", "evolution.baseline_chrome")
    schedule_raw = evolution.get("schedule") or {}
    schedule = EvolutionSchedule(
        delay_model=schedule_raw.get("delay_model", "mainstream"),
        next_upgrade_not_before=schedule_raw.get("next_upgrade_not_before"),
    )
    return Evolution(
        strategy=_require(evolution, "strategy", "evolution.strategy"),
        baseline_chrome=baseline,
        drift_policy=_require(evolution, "drift_policy", "evolution.drift_policy"),
        current_chrome=evolution.get("current_chrome") or baseline,
        channel=evolution.get("channel", "stable"),
        schedule=schedule,
        history=list(evolution.get("history") or []),
    )


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
        # 演化扩展字段（§二）：整块可缺省，缺省取默认值；
        # current_chrome 缺省回填 baseline_chrome（未演化的 persona 当前版=出生基线）
        evolution=_evolution_from_dict(evolution),
        proxy=d.get("proxy"),
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

    # evolution（既有锚定字段 + §二演化扩展字段）
    ev = persona.evolution
    if not _is_str(ev.strategy) or ev.strategy != "anchor_chrome_version":
        err("evolution.strategy", f"恒为 anchor_chrome_version，实际为 {ev.strategy!r}")
    baseline_key = _chrome_version_key(ev.baseline_chrome)
    if baseline_key is None:
        err("evolution.baseline_chrome",
            f"须为形如 138.0.7204.0 的四段版本号，实际为 {ev.baseline_chrome!r}")
    if not _is_str(ev.drift_policy) or ev.drift_policy != "follow_stable_diff":
        err("evolution.drift_policy", f"恒为 follow_stable_diff，实际为 {ev.drift_policy!r}")

    # current_chrome：四段版本号，且 ≥ baseline（版本单调增语义，§二硬约束）
    current_key = _chrome_version_key(ev.current_chrome)
    if current_key is None:
        err("evolution.current_chrome",
            f"须为形如 138.0.7204.0 的四段版本号，实际为 {ev.current_chrome!r}")
    elif baseline_key is not None and current_key < baseline_key:
        err("evolution.current_chrome",
            f"版本单调增约束：current_chrome {ev.current_chrome!r} 不得小于 "
            f"baseline_chrome {ev.baseline_chrome!r}")

    # channel：发布通道画像枚举（§二）
    if not _is_str(ev.channel) or ev.channel not in EVOLUTION_CHANNEL_CHOICES:
        err("evolution.channel",
            f"须 ∈ {sorted(EVOLUTION_CHANNEL_CHOICES)}，实际为 {ev.channel!r}")

    # schedule：升级时机画像（整块可缺省，缺省已回填默认）
    sch = ev.schedule
    if not _is_str(sch.delay_model) or sch.delay_model not in EVOLUTION_DELAY_MODEL_CHOICES:
        err("evolution.schedule.delay_model",
            f"须 ∈ {sorted(EVOLUTION_DELAY_MODEL_CHOICES)}，实际为 {sch.delay_model!r}")
    if sch.next_upgrade_not_before is not None \
            and not _is_date_str(sch.next_upgrade_not_before):
        err("evolution.schedule.next_upgrade_not_before",
            f"须为 YYYY-MM-DD 合法日期或 null，实际为 {sch.next_upgrade_not_before!r}")

    # history：履历条目结构（rollback=true 条目合法——方案 §七.3 诚实留痕，
    # 此处不拒绝；回滚计数警告由 count_rollbacks() 提供）
    if not isinstance(ev.history, list):
        err("evolution.history", f"须为履历条目列表，实际为 {ev.history!r}")
    else:
        for i, h in enumerate(ev.history):
            prefix = f"evolution.history[{i}]"
            if not isinstance(h, dict):
                err(prefix, f"履历条目须为映射，实际为 {h!r}")
                continue
            from_key = _chrome_version_key(h.get("from"))
            to_key = _chrome_version_key(h.get("to"))
            if from_key is None:
                err(f"{prefix}.from",
                    f"须为形如 138.0.7204.0 的四段版本号，实际为 {h.get('from')!r}")
            if to_key is None:
                err(f"{prefix}.to",
                    f"须为形如 138.0.7204.0 的四段版本号，实际为 {h.get('to')!r}")
            if from_key is not None and to_key is not None and to_key <= from_key:
                err(f"{prefix}.to",
                    f"演化履历须 to>from（单调增），实际 {h.get('from')!r} → {h.get('to')!r}")
            at = h.get("at")
            # at 须为精确到秒的 ISO8601 时间（如 2026-08-20T09:30:00+08:00）
            if not _is_str(at) or not re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", at):
                err(f"{prefix}.at",
                    f"须为精确到秒的 ISO8601 时间字符串，实际为 {at!r}")
            else:
                try:
                    datetime.fromisoformat(at)
                except ValueError:
                    err(f"{prefix}.at", f"不是合法的 ISO8601 时间：{at!r}")
            if "stable_release_date" in h and not _is_date_str(h["stable_release_date"]):
                err(f"{prefix}.stable_release_date",
                    f"须为 YYYY-MM-DD 合法日期，实际为 {h['stable_release_date']!r}")

    # proxy：null 或字符串（格式合法性归 linter V10）
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
