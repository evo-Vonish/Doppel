"""E3 行为启发式（SPEC-E §4.1/§4.2）：挖矿与指纹信号检测 + 计分。

纪律（SPEC-E §0 / §9）：
- 纯标准库；本模块只依赖 tishen.observ.events.Event，
  不得 import engine.trackerdb / engine.entity / engine.rules；
- 铁律：单个可疑 API 调用永不触发高级告警——本模块只产出信号与分数，
  级别闸门由 scorer.decide_level 唯一裁决；
- api_call 事件的 API 名取自 summary 前缀（JS hook 层约定：
  summary 以 "<api名> ..." 开头，如 "canvas.getImageData w=..."）。
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from tishen.observ.events import Event

# ---------------------------------------------------------------------------
# 4.1 信号清单（常量，id 即证据链标签；注释与 SPEC-E §4.1 一致）
# ---------------------------------------------------------------------------

MINING_SIGNALS = frozenset({
    "mining.long_lived_worker",     # worker_spawn 后 ≥120s 无对应终止且窗口内 api_call 密度 ≥10/min
    "mining.wasm_compute",          # wasm_load 后同一 actor_script 持续 api_call ≥5/min
    "mining.hidden_active",         # visibility_probe(hidden) 之后事件密度不降（≥隐藏前的 80%）
    "mining.stack_repeat",          # 同一 actor_script 在窗口内相同 api_call 序列重复 ≥30%（滑窗 20 条）
    "mining.pool_domain",           # E2 命中矿池规则（category=cryptomining 或匹配池域名种子表）
})

FP_SIGNALS = frozenset({
    "fp.api_combo",                 # 单 actor_script 窗口内 ≥5 种指纹相关 api_call（常量表 FP_APIS）
    "fp.api_volume",                # 单 actor_script 窗口内 api_call ≥30 次
    "fp.cross_entity_fp_invasive",  # E1 双交集（is_tracking ∧ fingerprinting_score≥2），NC 包启用时可用
    "fp.exfil_to_third",            # 指纹 api_call 后同 actor 向第三方 target_host 发 request
})

# 清洗后矿池种子（CoinBlockerLists / ZeroDot1 去正规域名版，逐条注明来源）
POOL_DOMAINS = frozenset({
    "coinhive.com",           # CoinBlockerLists：CoinHive 主域
    "coin-hive.com",          # CoinBlockerLists：CoinHive 镜像域
    "cnhv.co",                # CoinBlockerLists：CoinHive 短链服务
    "authedmine.com",         # CoinBlockerLists：CoinHive 授权挖矿版
    "coinhivemanager.com",    # CoinBlockerLists：CoinHive 管理面板
    "jsecoin.com",            # CoinBlockerLists：JSEcoin 浏览器挖矿平台
    "coinimp.net",            # CoinBlockerLists：CoinIMP 矿池
    "minero.cc",              # CoinBlockerLists：Minero 矿池
    "crypto-loot.com",        # CoinBlockerLists：Crypto-Loot 矿池
    "cryptoloot.pro",         # CoinBlockerLists：Crypto-Loot 备用域
    "webmine.cz",             # CoinBlockerLists：Webmine 矿池（捷克）
    "coinnebula.com",         # CoinBlockerLists：CoinNebula 矿池
    "hashwin.com",            # CoinBlockerLists：HashWin 矿池
    "gridcash.net",           # CoinBlockerLists：GridCash 矿池
    "minemytraffic.com",      # CoinBlockerLists：MineMyTraffic 矿池
    "coinblind.com",          # CoinBlockerLists：CoinBlind 矿池
    "coinpirate.cf",          # CoinBlockerLists：CoinPirate 矿池
    "cryptobara.com",         # CoinBlockerLists：CryptoBara 矿池
    "ppoi.org",               # CoinBlockerLists：ProjectPoi 矿池
    "webmine.pro",            # CoinBlockerLists：WebMine.pro 矿池
    "coin-have.com",          # CoinBlockerLists：Coin-Have 矿池
    "miner.pr0gramm.com",     # CoinBlockerLists：pr0gramm 托管挖矿脚本
    "coinminingonline.com",   # CoinBlockerLists：CoinMiningOnline 矿池
    "service4refresh.com",    # CoinBlockerLists：伪装刷新服务的矿池域
})

# 指纹相关 api_call 名常量表（覆盖 canvas/webgl/audio/fonts/navigator 五类）
FP_APIS = frozenset({
    # canvas 类
    "canvas.getImageData",
    "canvas.toDataURL",
    "canvas.toBlob",
    "canvas.measureText",
    # webgl 类
    "webgl.getParameter",
    "webgl.getSupportedExtensions",
    "webgl.getExtension",
    "webgl.getShaderPrecisionFormat",
    "webgl.readPixels",
    # audio 类
    "audio.createDynamicsCompressor",
    "audio.createOscillator",
    "audio.offline.startRendering",
    # fonts 类
    "fonts.check",
    "fonts.load",
    "document.fonts.ready",
    # navigator / 环境探测类
    "navigator.userAgent",
    "navigator.platform",
    "navigator.hardwareConcurrency",
    "navigator.deviceMemory",
    "navigator.languages",
    "navigator.plugins",
    "screen.colorDepth",
})

# ---------------------------------------------------------------------------
# 4.2 接口
# ---------------------------------------------------------------------------


@dataclass
class ScoreResult:
    """§4.2：一次行为计分结果。"""

    subject: str        # actor_script 或 entity
    kind: str           # "mining" | "fingerprinting"
    score: int          # 0–100
    signals: list[str]  # 命中的信号 id（排序去重）


# ---- 内部工具 -------------------------------------------------------------

_LONG_WORKER_MS = 120_000      # §4.1 mining.long_lived_worker：≥120s
_MINING_DENSITY_PER_MIN = 10   # §4.1：api_call 密度 ≥10/min
_WASM_DENSITY_PER_MIN = 5      # §4.1：wasm 后持续 api_call ≥5/min
_HIDDEN_RATIO = 0.8            # §4.1：隐藏后密度 ≥ 隐藏前的 80%
_STACK_REPEAT_RATIO = 0.3      # §4.1：相同序列重复 ≥30%（滑窗 20 条）
_STACK_SPAN = 20               # §4.1：滑窗 20 条
_FP_COMBO_MIN = 5              # §4.1：≥5 种指纹 API
_FP_VOLUME_MIN = 30            # §4.1：窗口内 api_call ≥30 次


def _api_name(ev: Event) -> str | None:
    """从 api_call 事件 summary 提取 API 名（hook 层约定为首个 token）。"""
    if ev.event_type != "api_call" or not ev.summary:
        return None
    return ev.summary.split(None, 1)[0]


def _reg_domain(host: str | None) -> str | None:
    """注册域名近似（§2.2 口径：末两段，eTLD 精度不做）。"""
    if not host:
        return None
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _page_host(ev: Event) -> str | None:
    if not ev.page_url:
        return None
    return urlparse(ev.page_url).hostname


def _by_actor(events: list[Event]) -> dict[str, list[Event]]:
    """按 actor_script 聚合（§4.2），忽略不可归因事件。"""
    buckets: dict[str, list[Event]] = {}
    for ev in events:
        if ev.actor_script:
            buckets.setdefault(ev.actor_script, []).append(ev)
    for bucket in buckets.values():
        bucket.sort(key=lambda e: e.ts)
    return buckets


def _mining_signals(actor_events: list[Event], window_ms: int) -> set[str]:
    """单 actor 窗口内挖矿信号检测（阈值逐条对齐 §4.1）。"""
    signals: set[str] = set()
    api_calls = [ev for ev in actor_events if ev.event_type == "api_call"]
    window_min = window_ms / 60_000
    api_per_min = len(api_calls) / window_min if window_min else 0.0

    spawns = [ev for ev in actor_events if ev.event_type == "worker_spawn"]
    if spawns and api_per_min >= _MINING_DENSITY_PER_MIN:
        first_spawn = spawns[0].ts
        window_end = max(ev.ts for ev in actor_events)
        # 无 worker 终止事件类型（EVENT_TYPES），以窗口末端仍活跃近似"无对应终止"
        if window_end - first_spawn >= _LONG_WORKER_MS:
            signals.add("mining.long_lived_worker")

    wasm_loads = [ev for ev in actor_events if ev.event_type == "wasm_load"]
    if wasm_loads:
        after = [ev for ev in api_calls if ev.ts >= wasm_loads[0].ts]
        if len(after) / window_min >= _WASM_DENSITY_PER_MIN:
            signals.add("mining.wasm_compute")

    probes = [ev for ev in actor_events
              if ev.event_type == "visibility_probe" and "hidden" in ev.summary.lower()]
    if probes:
        t0 = probes[0].ts
        span_start = actor_events[0].ts
        span_end = actor_events[-1].ts
        before = [ev for ev in actor_events if span_start <= ev.ts < t0]
        after = [ev for ev in actor_events if ev.ts > t0]
        before_min = (t0 - span_start) / 60_000
        after_min = (span_end - t0) / 60_000
        if before and after and before_min > 0 and after_min > 0:
            rate_before = len(before) / before_min
            rate_after = len(after) / after_min
            if rate_before > 0 and rate_after >= _HIDDEN_RATIO * rate_before:
                signals.add("mining.hidden_active")

    # 滑窗 20 条：最近 20 条 api_call 中重复 summary 占比 ≥30%
    if len(api_calls) >= 2:
        window20 = api_calls[-_STACK_SPAN:]
        names = [ev.summary for ev in window20]
        repeated = sum(1 for n in names if names.count(n) > 1)
        if names and repeated / len(names) >= _STACK_REPEAT_RATIO:
            signals.add("mining.stack_repeat")

    hosts = {ev.target_host for ev in actor_events if ev.target_host}
    if any(h in POOL_DOMAINS or _reg_domain(h) in POOL_DOMAINS for h in hosts):
        signals.add("mining.pool_domain")

    return signals


def _fp_signals(actor_events: list[Event], window_ms: int) -> set[str]:
    """单 actor 窗口内指纹信号检测（阈值逐条对齐 §4.1）。"""
    del window_ms  # 阈值均为窗口内计数，无需单独换算
    signals: set[str] = set()
    api_calls = [ev for ev in actor_events if ev.event_type == "api_call"]

    fp_calls = [ev for ev in api_calls if _api_name(ev) in FP_APIS]
    if len({_api_name(ev) for ev in fp_calls}) >= _FP_COMBO_MIN:
        signals.add("fp.api_combo")

    if len(api_calls) >= _FP_VOLUME_MIN:
        signals.add("fp.api_volume")

    if fp_calls:
        first_fp_ts = fp_calls[0].ts
        page_host = next(
            (h for ev in actor_events if (h := _page_host(ev))), None)
        for ev in actor_events:
            if ev.event_type != "request" or ev.ts < first_fp_ts or not ev.target_host:
                continue
            if page_host is None:
                # 无 page 信息时无法判第三方，保守不置位（铁律方向）
                break
            if _reg_domain(ev.target_host) != _reg_domain(page_host):
                signals.add("fp.exfil_to_third")
                break

    return signals


def score_mining(events: list[Event], *, window_ms: int = 300_000) -> ScoreResult | None:
    """§4.2：挖矿计分。

    按 actor_script 聚合；无任何信号返回 None。
    计分：主信号（long_lived_worker/wasm_compute/stack_repeat）各 35，
    修正（hidden_active）+15，确认（pool_domain）+20，封顶 100。
    """
    best: ScoreResult | None = None
    for actor, actor_events in _by_actor(events).items():
        signals = _mining_signals(actor_events, window_ms)
        if not signals:
            continue
        score = 0
        for main in ("mining.long_lived_worker", "mining.wasm_compute",
                     "mining.stack_repeat"):
            if main in signals:
                score += 35
        if "mining.hidden_active" in signals:
            score += 15
        if "mining.pool_domain" in signals:
            score += 20
        result = ScoreResult(subject=actor, kind="mining",
                             score=min(score, 100),
                             signals=sorted(signals))
        if best is None or result.score > best.score:
            best = result
    return best


def score_fingerprinting(events: list[Event], entity_fp_invasive: bool = False,
                         *, window_ms: int = 300_000) -> ScoreResult | None:
    """§4.2：指纹计分。

    api_combo 40 / api_volume 25 / exfil_to_third 25 /
    cross_entity_fp_invasive +20，封顶 100；无任何信号返回 None。
    """
    best: ScoreResult | None = None
    for actor, actor_events in _by_actor(events).items():
        signals = _fp_signals(actor_events, window_ms)
        if entity_fp_invasive:
            signals.add("fp.cross_entity_fp_invasive")
        if not signals:
            continue
        score = 0
        if "fp.api_combo" in signals:
            score += 40
        if "fp.api_volume" in signals:
            score += 25
        if "fp.exfil_to_third" in signals:
            score += 25
        if "fp.cross_entity_fp_invasive" in signals:
            score += 20
        result = ScoreResult(subject=actor, kind="fingerprinting",
                             score=min(score, 100),
                             signals=sorted(signals))
        if best is None or result.score > best.score:
            best = result
    if best is None and entity_fp_invasive:
        # 无可归因脚本但实体级双交集成立：subject 以 "entity" 占位（§4.2 subject 允许 entity）
        return ScoreResult(subject="entity", kind="fingerprinting",
                           score=20, signals=["fp.cross_entity_fp_invasive"])
    return best
