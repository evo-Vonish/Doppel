"""L2 payload 接入 daemon 集成测试（SPEC-E4 件二 J1）。

铁律验收（方案 §二）：L2 只作确认加权，永不单独告警；L1 兜底——
payload_log 缺失/空则全链路无感降级。覆盖：矿工样本+挖矿行为 → L3 且
signals 含 mining.payload_confirmed；无样本同行为级别不升（对照）；
坏行跳过计数；payload_offset 游标续读；payload_log=None 降级；
alert_level 回写含确认信号标签；L2 单独不告警；worker_spawn 回退关联。

sha256 关联口径：Event schema 无哈希字段——wasm_load 从 summary 正则
提取（hook 写入 "sha256=<hex>"）；worker_spawn 以 (actor_script,
ts ±5s) 回退关联 samples.jsonl 的 source_url/ts。
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from tishen.engine.daemon import EngineConfig, EngineDaemon
from tishen.observ import store
from tishen.observ.events import Event

T0 = 1_700_000_000_000
PERSONA = "p_test"
MINER = "https://cdn.evil.example/miner.js"

# JS 矿工样本源码：cryptonight 签名（js.miner_signature 40）+
# eval(atob(...)) 链（js.eval_chain 25）→ score 65 ≥ 60 确认阈值
JS_MINER_CODE = "var s='cryptonight';var x=eval(atob('YQ=='));f(s,x);"


def _js_miner_bytes() -> bytes:
    return JS_MINER_CODE.encode("utf-8")


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _wasm_miner_bytes() -> bytes:
    """WASM 矿工样本：custom section 含 stratum 池串（wasm.pool_section 40）
    + 201 个 import 函数（import_bloat 20 + stripped 10）→ score 70。"""
    name = b"miner stratum+tcp://pool.example"
    custom_payload = _uleb(len(name)) + name
    custom = bytes([0]) + _uleb(len(custom_payload)) + custom_payload
    entry = _uleb(1) + b"a" + _uleb(1) + b"b" + bytes([0, 0])
    imports = _uleb(201) + entry * 201
    import_sec = bytes([2]) + _uleb(len(imports)) + imports
    return b"\x00asm\x01\x00\x00\x00" + custom + import_sec


def _sample(payload_bytes: bytes, kind: str, *, source_url=None, ts=None) -> dict:
    return {"sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "kind": kind, "size": len(payload_bytes),
            "head_b64": base64.b64encode(payload_bytes).decode("ascii"),
            "source_url": source_url,
            "ts": T0 // 1000 if ts is None else ts}


def _write_samples(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def _ev(ts, etype, summary, *, page="site-a.com", actor=MINER,
        target_host=None, target_url=None):
    return Event(persona_id=PERSONA, ts=ts, session_id="sess-1",
                 event_type=etype, summary=summary, evidence_ref="pcap:x#1",
                 page_url=f"https://{page}/" if page else None,
                 actor_script=actor, target_host=target_host,
                 target_url=target_url)


def _wasm_summary(payload_bytes: bytes) -> str:
    """hook 口径：wasm_load summary 内嵌 sha256=<hex>。"""
    return (f"WebAssembly.instantiate size={len(payload_bytes)}"
            f" sha256={hashlib.sha256(payload_bytes).hexdigest()}")


def _mining_events_full(payload_bytes: bytes) -> list[Event]:
    """合成挖矿序列（同 §10-2 口径）：5 信号满分 → 无 L2 亦 L3。"""
    evs = [_ev(T0, "worker_spawn", "worker spawn",
               target_host="cdn.evil.example",
               target_url="https://cdn.evil.example/miner.js"),
           _ev(T0 + 1_000, "wasm_load", _wasm_summary(payload_bytes))]
    for i in range(30):
        evs.append(_ev(T0 + 2_000 + i * 1_000, "api_call", "crypto.hash iter"))
    evs.append(_ev(T0 + 60_000, "visibility_probe", "visibilitychange hidden"))
    for i in range(40):
        evs.append(_ev(T0 + 61_000 + i * 2_000, "api_call", "crypto.hash iter",
                       target_host="coinhive.com",
                       target_url="wss://coinhive.com/proxy"))
    return evs


def _mining_events_mild(payload_bytes: bytes) -> list[Event]:
    """中度挖矿行为：long_lived_worker + wasm_compute（score 70）→ L2；
    摘要两两不同避免 stack_repeat，无 pool 域接触。"""
    evs = [_ev(T0, "worker_spawn", "worker spawn"),
           _ev(T0 + 1_000, "wasm_load", _wasm_summary(payload_bytes))]
    for i in range(50):  # 50 条/5min = 10/min，跨 150s（≥120s）
        evs.append(_ev(T0 + 2_000 + i * 3_000, "api_call", f"crypto.hash#{i}"))
    return evs


def _make_daemon(tmp_path, *, payload_log: Path | None = "default",
                 now=T0 + 600_000) -> EngineDaemon:
    if payload_log == "default":
        payload_log = tmp_path / "payload" / "samples.jsonl"
    cfg = EngineConfig(tishen_home=tmp_path / "home", persona_id=PERSONA,
                       events_db=tmp_path / "events.db",
                       trackerdb_db=tmp_path / "trackerdb.db",
                       engine_db=tmp_path / "engine.db",
                       payload_log=payload_log)
    return EngineDaemon(cfg, now_fn=lambda: now)


def _insert_events(db_path: Path, events: list[Event]) -> None:
    conn = store.connect(db_path)
    store.insert_events(conn, events)
    conn.close()


def _subject(d: EngineDaemon, subject: str):
    return d._engine.execute(
        "SELECT level, score, signals FROM subject_state WHERE subject = ?",
        (subject,)).fetchone()


def _payload_offset(d: EngineDaemon) -> int | None:
    row = d._engine.execute(
        "SELECT value FROM meta WHERE key = 'payload_offset'").fetchone()
    return int(row[0]) if row else None


@pytest.fixture()
def daemon_pair(tmp_path):
    d = _make_daemon(tmp_path)
    yield d, tmp_path
    d.close()


# ---- 端到端：矿工样本 + 挖矿行为 → L3 且 signals 含 payload_confirmed --------


def test_miner_sample_plus_mining_l3_with_payload_confirmed(daemon_pair):
    d, tmp = daemon_pair
    payload_bytes = _js_miner_bytes()
    _write_samples(tmp / "payload" / "samples.jsonl",
                   [json.dumps(_sample(payload_bytes, "js"))])
    _insert_events(tmp / "events.db", _mining_events_full(payload_bytes))
    stats = d.run_once()
    assert stats["gap"] is False

    row = _subject(d, f"mining:{MINER}")
    assert row is not None and row[0] == 3, "矿工样本确认下挖矿行为须达 L3"
    signals = json.loads(row[2])
    assert "mining.payload_confirmed" in signals
    assert {"mining.long_lived_worker", "mining.wasm_compute"} <= set(signals)

    # alert_level 回写含确认信号：事件 alert_level=3 + alert:L3:mining 标签，
    # subject_state signals（回写存档）含 mining.payload_confirmed
    conn = store.connect(tmp / "events.db")
    lvl = conn.execute(
        "SELECT MIN(alert_level) FROM events WHERE event_type = 'api_call'"
    ).fetchone()[0]
    assert lvl == 3
    tags = {r[0] for r in conn.execute(
        "SELECT engine_tags FROM events WHERE event_type = 'api_call' LIMIT 5")}
    assert all("alert:L3:mining" in json.loads(t) for t in tags)
    conn.close()


# ---- 对照：无样本 → 同行为级别不升、signals 无确认标签 ------------------------


def test_same_behavior_without_sample_not_upgraded(daemon_pair):
    d, tmp = daemon_pair
    payload_bytes = _js_miner_bytes()
    # payload_log 配置但文件为空（L1 兜底：无样本零影响）
    (tmp / "payload").mkdir(parents=True, exist_ok=True)
    (tmp / "payload" / "samples.jsonl").write_text("", encoding="utf-8")
    _insert_events(tmp / "events.db", _mining_events_full(payload_bytes))
    d.run_once()

    row = _subject(d, f"mining:{MINER}")
    assert row is not None and row[0] == 3, "同一行为级别须与有样本时一致（不升不降）"
    assert "mining.payload_confirmed" not in json.loads(row[2])


def test_mild_behavior_confirm_weight_no_level_jump(daemon_pair):
    """确认加权不越闸：中度行为（score 70，2 信号）+ 矿工样本 →
    signals 追加确认标签但级别仍 L2（score<80 不达 L3 闸）。"""
    d, tmp = daemon_pair
    payload_bytes = _wasm_miner_bytes()
    _write_samples(tmp / "payload" / "samples.jsonl",
                   [json.dumps(_sample(payload_bytes, "wasm"))])
    _insert_events(tmp / "events.db", _mining_events_mild(payload_bytes))
    d.run_once()

    row = _subject(d, f"mining:{MINER}")
    assert row is not None and row[0] == 2
    signals = json.loads(row[2])
    assert "mining.payload_confirmed" in signals
    assert len(signals) == 3  # 2 个 L1 信号 + 1 个 L2 确认信号


# ---- 铁律：L2 永不单独告警 ----------------------------------------------------


def test_payload_alone_never_alerts(daemon_pair):
    """仅有矿工样本命中、无 L1 行为信号（低密度）→ 无评级、无告警。"""
    d, tmp = daemon_pair
    payload_bytes = _js_miner_bytes()
    _write_samples(tmp / "payload" / "samples.jsonl",
                   [json.dumps(_sample(payload_bytes, "js"))])
    evs = [_ev(T0, "wasm_load", _wasm_summary(payload_bytes)),
           _ev(T0 + 1_000, "api_call", "crypto.hash once")]
    _insert_events(tmp / "events.db", evs)
    stats = d.run_once()

    assert stats["alerts"] == 0
    assert _subject(d, f"mining:{MINER}") is None, "L2 命中不得单独产出评级"
    conn = store.connect(tmp / "events.db")
    lvl = conn.execute("SELECT MAX(alert_level) FROM events").fetchone()[0]
    assert lvl == 0
    conn.close()


# ---- 坏行跳过计数 --------------------------------------------------------------


def test_bad_lines_skipped_and_counted(daemon_pair):
    d, tmp = daemon_pair
    good = json.dumps(_sample(_js_miner_bytes(), "js"))
    lines = ["not json", json.dumps({"kind": "js"}),  # 缺 head_b64
             json.dumps({"kind": "wat", "head_b64": "eA=="}),  # 未知 kind
             json.dumps({"kind": "js", "head_b64": "!!!"}),  # 坏 base64
             good]
    _write_samples(tmp / "payload" / "samples.jsonl", lines)
    _insert_events(tmp / "events.db", _mining_events_mild(_js_miner_bytes()))
    d.run_once()

    assert d.payload_skipped == 4, "4 条坏行须全部容错跳过并计数"
    assert hashlib.sha256(_js_miner_bytes()).hexdigest() in d._payload_cache


# ---- 游标增量续读 ---------------------------------------------------------------


def test_payload_offset_cursor_resume(daemon_pair):
    d, tmp = daemon_pair
    log_path = tmp / "payload" / "samples.jsonl"
    js = _js_miner_bytes()
    _write_samples(log_path, [json.dumps(_sample(js, "js"))])
    _insert_events(tmp / "events.db", _mining_events_mild(js))
    d.run_once()
    offset1 = _payload_offset(d)
    assert offset1 == log_path.stat().st_size, "游标须推进到文件末尾"
    assert d.payload_skipped == 0

    # 第二 tick：追加 wasm 样本 + 坏行 + 新事件，游标续读不重放
    wasm = _wasm_miner_bytes()
    _write_samples(log_path, ["broken line",
                              json.dumps(_sample(wasm, "wasm"))])
    evs = [_ev(T0 + 300_000, "wasm_load", _wasm_summary(wasm))]
    _insert_events(tmp / "events.db", evs)
    d.run_once()

    assert _payload_offset(d) == log_path.stat().st_size
    assert d.payload_skipped == 1, "上一 tick 的行不得重放重计"
    assert hashlib.sha256(js).hexdigest() in d._payload_cache
    assert hashlib.sha256(wasm).hexdigest() in d._payload_cache


# ---- payload_log=None 全链路降级 -------------------------------------------------


def test_payload_log_none_full_degradation(tmp_path):
    d = _make_daemon(tmp_path, payload_log=None)
    try:
        payload_bytes = _js_miner_bytes()
        _insert_events(tmp_path / "events.db",
                       _mining_events_full(payload_bytes))
        stats = d.run_once()
        assert stats["gap"] is False

        row = _subject(d, f"mining:{MINER}")
        assert row is not None and row[0] == 3, "L1 行为通道评级不受 L2 降级影响"
        assert "mining.payload_confirmed" not in json.loads(row[2])
        assert d.payload_skipped == 0
        assert not d._payload_cache and not d._payload_samples
        assert _payload_offset(d) is None, "payload_log=None 不得落游标"
    finally:
        d.close()


# ---- worker_spawn 回退关联（actor_script + ts ±5s ↔ source_url/ts）--------------


def test_worker_spawn_fallback_association(daemon_pair):
    """worker_spawn summary 无哈希：blob URL 进 summary 且样本 source_url
    与事件 actor/ts 窗口匹配 → 确认信号注入。"""
    d, tmp = daemon_pair
    js = _js_miner_bytes()
    blob = "blob:https://site-a.com/abcd-1234"
    _write_samples(tmp / "payload" / "samples.jsonl",
                   [json.dumps(_sample(js, "js", source_url=blob,
                                       ts=T0 // 1000))])
    evs = [_ev(T0, "worker_spawn", f"Worker {blob}"),
           _ev(T0 + 1_000, "wasm_load", "WebAssembly.instantiate size=8 sha256=n/a")]
    for i in range(50):  # long_lived_worker + wasm_compute → 有 L1 信号
        evs.append(_ev(T0 + 2_000 + i * 3_000, "api_call", f"crypto.hash#{i}"))
    _insert_events(tmp / "events.db", evs)
    d.run_once()

    row = _subject(d, f"mining:{MINER}")
    assert row is not None
    assert "mining.payload_confirmed" in json.loads(row[2]), \
        "worker_spawn 经 (actor_script, ts±5s) 回退关联命中矿工样本须确认"
