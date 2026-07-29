"""E3 行为启发式测试（SPEC-E §4.1/§4.2，验收 §10-1 铁律支撑）。

fixture 直接用 tishen.observ.events.Event dataclass 构造；
api_call 的 API 名按 hook 层约定写在 summary 首个 token。
"""

from __future__ import annotations

from tishen.engine.behavior import (
    FP_APIS,
    FP_SIGNALS,
    MINING_SIGNALS,
    POOL_DOMAINS,
    score_fingerprinting,
    score_mining,
)
from tishen.observ.events import Event

ACTOR = "https://cdn.evil.com/miner.js"
WINDOW = 300_000  # 5 分钟


def ev(ts: int, event_type: str, summary: str = "s", *,
       actor: str | None = ACTOR, target_host: str | None = None,
       page_url: str | None = None) -> Event:
    return Event(persona_id="p1", ts=ts, session_id="sess1",
                 event_type=event_type, summary=summary,
                 evidence_ref="pcap:x#1", actor_script=actor,
                 target_host=target_host, page_url=page_url)


def api(ts: int, name: str = "crypto.hash", *, actor: str | None = ACTOR,
        page_url: str | None = None) -> Event:
    return ev(ts, "api_call", f"{name} args", actor=actor, page_url=page_url)


# ---- 常量表（§4.1） -------------------------------------------------------

def test_pool_domains_seed_size():
    """§4.1：POOL_DOMAINS ≥20 条。"""
    assert len(POOL_DOMAINS) >= 20


def test_fp_apis_covers_five_classes():
    """§4.1：FP_APIS 覆盖 canvas/webgl/audio/fonts/navigator 类。"""
    for prefix in ("canvas.", "webgl.", "audio.", "fonts.", "navigator."):
        assert any(a.startswith(prefix) for a in FP_APIS), prefix


def test_signal_ids_match_spec():
    """§4.1：信号 id 与 SPEC 一字一致。"""
    assert MINING_SIGNALS == {
        "mining.long_lived_worker", "mining.wasm_compute",
        "mining.hidden_active", "mining.stack_repeat", "mining.pool_domain",
    }
    assert FP_SIGNALS == {
        "fp.api_combo", "fp.api_volume",
        "fp.cross_entity_fp_invasive", "fp.exfil_to_third",
    }


# ---- score_mining（§4.2） --------------------------------------------------

def test_mining_none_on_benign():
    """§4.2：无任何信号返回 None（低密度普通事件流）。"""
    events = [api(t * 10_000, f"dom.api{t}") for t in range(5)]
    assert score_mining(events) is None


def test_mining_single_api_call_no_signal():
    """§10-1 铁律支撑：单一 api_call 事件流无任何挖矿信号。"""
    assert score_mining([api(0, "canvas.getImageData")]) is None


def test_mining_long_lived_worker():
    """§4.1：worker_spawn 后 ≥120s 且 api_call 密度 ≥10/min → 主信号 35 分。"""
    events = [ev(0, "worker_spawn", "new Worker")]
    # 50 次 api_call（5 分钟窗口 ≥10/min），跨度 150s
    events += [api(i * 3_000) for i in range(50)]
    result = score_mining(events, window_ms=WINDOW)
    assert result is not None
    assert "mining.long_lived_worker" in result.signals
    assert result.score >= 35
    assert result.kind == "mining" and result.subject == ACTOR


def test_mining_wasm_compute():
    """§4.1：wasm_load 后持续 api_call ≥5/min → wasm_compute 35 分。"""
    events = [ev(0, "wasm_load", "wasm module")]
    events += [api(1_000 + i * 1_000) for i in range(25)]  # 25 次/5min = 5/min
    result = score_mining(events, window_ms=WINDOW)
    assert result is not None
    assert "mining.wasm_compute" in result.signals
    assert result.score >= 35


def test_mining_stack_repeat():
    """§4.1：滑窗 20 条内相同 api_call 序列重复 ≥30% → stack_repeat。"""
    events = [api(i * 500, f"crypto.hash round={i % 4}") for i in range(20)]
    result = score_mining(events, window_ms=WINDOW)
    assert result is not None
    assert "mining.stack_repeat" in result.signals


def test_mining_pool_domain():
    """§4.1：目标命中矿池种子域 → pool_domain 确认信号 +20。"""
    events = [ev(0, "request", "GET", target_host="ws.coinhive.com"),
              api(1_000)]
    result = score_mining(events, window_ms=WINDOW)
    assert result is not None
    assert result.signals == ["mining.pool_domain"]
    assert result.score == 20


def test_mining_hidden_active():
    """§4.1：hidden 探针后事件密度不降（≥80%）→ hidden_active 修正 +15。"""
    # 前 100s 每 5s 一条，探针后 100s 每 5s 一条（密度 100%）
    before = [api(i * 5_000) for i in range(20)]
    probe = ev(100_000, "visibility_probe", "visibility:hidden")
    after = [api(100_000 + i * 5_000) for i in range(1, 21)]
    result = score_mining(before + [probe] + after, window_ms=WINDOW)
    assert result is not None
    assert "mining.hidden_active" in result.signals


def test_mining_full_combo_capped_100():
    """§4.2：主信号×3 + 修正 + 确认 = 140 → 封顶 100。"""
    events = [ev(0, "worker_spawn", "new Worker"),
              ev(0, "wasm_load", "wasm module"),
              ev(0, "request", "GET", target_host="coinhive.com"),
              ev(120_000, "visibility_probe", "visibility:hidden")]
    events += [api(i * 3_000, f"crypto.hash r={i % 3}") for i in range(50)]
    result = score_mining(events, window_ms=WINDOW)
    assert result is not None
    assert result.score == 100
    assert len(result.signals) == 5


def test_mining_signals_sorted_dedup():
    """§4.2：signals 排序去重。"""
    events = [ev(0, "request", "GET", target_host="jsecoin.com"),
              ev(1, "request", "GET", target_host="jsecoin.com")]
    result = score_mining(events, window_ms=WINDOW)
    assert result is not None
    assert result.signals == sorted(set(result.signals))


# ---- score_fingerprinting（§4.2） ------------------------------------------

def test_fp_none_on_benign():
    """§4.2：无指纹行为且无实体交集 → None。"""
    events = [api(t * 10_000, "dom.querySelector") for t in range(3)]
    assert score_fingerprinting(events) is None


def test_fp_api_combo():
    """§4.1：≥5 种指纹 API → api_combo 40 分。"""
    names = ["canvas.getImageData", "canvas.toDataURL", "webgl.getParameter",
             "audio.createOscillator", "fonts.check", "navigator.userAgent"]
    events = [api(i * 100, n) for i, n in enumerate(names)]
    result = score_fingerprinting(events, window_ms=WINDOW)
    assert result is not None
    assert "fp.api_combo" in result.signals
    assert result.score >= 40


def test_fp_api_volume():
    """§4.1：窗口内 api_call ≥30 次 → api_volume 25 分。"""
    events = [api(i * 100, "dom.querySelector") for i in range(30)]
    result = score_fingerprinting(events, window_ms=WINDOW)
    assert result is not None
    assert "fp.api_volume" in result.signals


def test_fp_exfil_to_third():
    """§4.1：指纹 api_call 后向第三方 target_host 发 request → exfil_to_third。"""
    page = "https://shop.example.com/item"
    events = [
        api(0, "canvas.getImageData", page_url=page),
        api(100, "webgl.getParameter", page_url=page),
        ev(200, "request", "POST", target_host="collect.tracker.net",
           page_url=page),
    ]
    result = score_fingerprinting(events, window_ms=WINDOW)
    assert result is not None
    assert "fp.exfil_to_third" in result.signals


def test_fp_exfil_first_party_not_flagged():
    """§4.1：同站请求不算外发（保守方向）。"""
    page = "https://shop.example.com/item"
    events = [
        api(0, "canvas.getImageData", page_url=page),
        ev(100, "request", "POST", target_host="api.shop.example.com",
           page_url=page),
    ]
    result = score_fingerprinting(events, window_ms=WINDOW)
    assert result is None or "fp.exfil_to_third" not in result.signals


def test_fp_entity_invasive():
    """§4.1：E1 双交集布尔参数 → cross_entity_fp_invasive +20。"""
    result = score_fingerprinting([], entity_fp_invasive=True)
    assert result is not None
    assert result.signals == ["fp.cross_entity_fp_invasive"]
    assert result.score == 20


def test_fp_combo_plus_volume_plus_invasive():
    """§4.2：combo 40 + volume 25 + entity 20 = 85。"""
    names = ["canvas.getImageData", "canvas.toDataURL", "webgl.getParameter",
             "audio.createOscillator", "fonts.check"]
    events = [api(i * 100, names[i % 5]) for i in range(30)]
    result = score_fingerprinting(events, entity_fp_invasive=True,
                                  window_ms=WINDOW)
    assert result is not None
    assert result.score == 85
    assert set(result.signals) == {
        "fp.api_combo", "fp.api_volume", "fp.cross_entity_fp_invasive"}
