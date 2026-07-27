"""事件库落库/查询离线测试（store + query + events schema）。"""

import time

import pytest

from tishen.observ import store
from tishen.observ.events import EVENT_TYPES, Event, ulid
from tishen.observ.query import query_events


def _event(**kw):
    base = dict(persona_id="p_test01", ts=1_753_600_000_000,
                session_id="sess-1", event_type="request",
                summary="GET http://example.com/", evidence_ref="pcap:ring.pcap0#1",
                target_host="example.com", target_url="http://example.com/")
    base.update(kw)
    return Event(**base)


def test_event_types_match_m3_enum():
    """§3.2 枚举一字不动：16 个类型全集校验。"""
    assert EVENT_TYPES == {
        "request", "response", "redirect", "download", "ws_open", "ws_message",
        "cookie_set", "form_submit", "dns_query", "tls_handshake",
        "storage_write", "api_call", "worker_spawn", "wasm_load",
        "block_action", "visibility_probe"}


def test_ulid_format_and_order():
    """ULID：26 字符 Crockford，时间戳越大字典序越大。"""
    a, b = ulid(1000), ulid(2000)
    assert len(a) == 26 and len(b) == 26
    assert a < b
    with pytest.raises(ValueError):
        ulid(-1)


def test_event_validate_discipline():
    """校验纪律：alert_level 非零 / 非法类型 / 非法 decrypt_state 均报错。"""
    assert _event().validate() == []
    assert _event(alert_level=2).validate()          # 观测层永不置非零
    assert _event(event_type="nope").validate()
    assert _event(decrypt_state="partial").validate()
    assert _event(engine_tags="not-json").validate()


def test_insert_and_query_roundtrip(tmp_path):
    """批量插入 → query_events 按时间倒序返回 dict，event_type 过滤生效。"""
    db = tmp_path / "events.db"
    conn = store.connect(db)
    events = [
        _event(ts=1000, event_type="request", summary="第一条"),
        _event(ts=2000, event_type="response", status=200, summary="第二条"),
        _event(ts=3000, event_type="request", summary="第三条"),
    ]
    assert store.insert_events(conn, events) == 3
    conn.close()

    rows = query_events(str(db))
    assert [r["summary"] for r in rows] == ["第三条", "第二条", "第一条"]
    assert rows[0]["decrypt_state"] == "full"
    assert rows[0]["alert_level"] == 0
    assert set(rows[0]) >= {"event_id", "persona_id", "ts", "session_id",
                            "event_type", "target_host", "summary",
                            "evidence_ref", "engine_tags"}
    only_req = query_events(str(db), event_type="request", limit=1)
    assert len(only_req) == 1 and only_req[0]["event_type"] == "request"


def test_insert_skips_invalid_events(tmp_path):
    """不合法事件跳过不污染库，合法部分照常落库。"""
    conn = store.connect(tmp_path / "events.db")
    good = _event()
    bad = _event(alert_level=3)          # 违反观测层纪律
    assert store.insert_events(conn, [good, bad]) == 1
    assert len(query_events(str(tmp_path / "events.db"))) == 1


def test_cleanup_retain_days(tmp_path):
    """retain_days 滚动清理：超期事件删除，期内保留。"""
    now = time.time_ns() // 1_000_000
    conn = store.connect(tmp_path / "events.db")
    old = _event(ts=now - 31 * 86_400_000, summary="超期")
    fresh = _event(ts=now, summary="期内")
    store.insert_events(conn, [old, fresh])
    assert store.cleanup(conn, 30, now_ms=now) == 1
    rows = query_events(str(tmp_path / "events.db"))
    assert [r["summary"] for r in rows] == ["期内"]
    with pytest.raises(ValueError):
        store.cleanup(conn, 0)


def test_query_missing_db_returns_empty(tmp_path):
    """库文件不存在返回空列表（替身未产出事件属正常态）。"""
    assert query_events(str(tmp_path / "不存在.db")) == []


def test_shard_ledger(tmp_path):
    """processed_shards 台账：登记、幂等查询、覆盖。"""
    conn = store.connect(tmp_path / "events.db")
    assert not store.is_shard_processed(conn, "ring.pcap0")
    store.record_shard(conn, "ring.pcap0", "ok", "覆盖率 2/2")
    assert store.is_shard_processed(conn, "ring.pcap0")
    store.record_shard(conn, "ring.pcap0", "gap", "重处理覆盖")
    assert store.is_shard_processed(conn, "ring.pcap0")
