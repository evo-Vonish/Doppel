"""JS hook 事件总线离线测试（SPEC-E3 §2.1/§2.4）。

覆盖：合法事件落库全字段、非法 JSON/缺字段/未知 type 分桶丢弃、
背压 drop+千次留痕、socket 权限 600 与父目录自建、并发双连接不串、
python -m 独立运行冒烟。
"""

import json
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time

import pytest

from tishen.observ.hook_bus import (
    BUS_EVIDENCE_REF, HOOK_EVIDENCE_REF, BusConfig, HookBus,
)


def _msg(**event_kw):
    """构造 §1 协议的 event 消息行（bytes）。"""
    event = {
        "event_type": "api_call",
        "summary": "canvas.toDataURL 读取画布像素",
        "ts": 1_730_000_000_000,
        "page_url": "https://example.com/",
        "frame": "top",
        "actor_script": "https://example.com/x.js",
        "target_host": "example.com",
        "persona_id": "p_hook01",
        "session_id": "sess-hook-1",
    }
    event.update(event_kw)
    return (json.dumps({"v": 1, "type": "event", "event": event}) + "\n").encode("utf-8")


@pytest.fixture()
def bus(tmp_path):
    b = HookBus(BusConfig(socket_path=tmp_path / "hook.sock",
                          events_db=tmp_path / "events.db"))
    yield b
    b.close()


def _db_rows(db_path, where="1=1"):
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        f"SELECT persona_id, ts, session_id, event_type, summary, evidence_ref,"
        f" page_url, frame, actor_script, target_host, decrypt_state,"
        f" engine_tags, alert_level FROM events WHERE {where}").fetchall()
    conn.close()
    return rows


# ── 合法事件：handle_line 返回 ok 且全字段落库 ─────────────────────────────
def test_valid_event_returns_ok_and_lands(bus, tmp_path):
    assert bus.handle_line(_msg()) == "ok"
    assert bus.wait_idle()
    rows = _db_rows(tmp_path / "events.db")
    assert len(rows) == 1
    (pid, ts, sid, etype, summary, eref, purl, frame, actor, host,
     dstate, tags, alert) = rows[0]
    assert (pid, ts, sid, etype) == ("p_hook01", 1_730_000_000_000,
                                     "sess-hook-1", "api_call")
    assert summary == "canvas.toDataURL 读取画布像素"
    assert eref == HOOK_EVIDENCE_REF  # 总线补默认证据位
    assert (purl, frame, actor, host) == ("https://example.com/", "top",
                                          "https://example.com/x.js", "example.com")
    assert (dstate, tags, alert) == ("full", "[]", 0)  # schema 零改动默认值


def test_unknown_event_fields_ignored(bus, tmp_path):
    """hook 扩展字段（sampled/injected_late 若漏剥）不影响落库。"""
    assert bus.handle_line(_msg(sampled=True, injected_late=True)) == "ok"
    assert bus.wait_idle()
    assert len(_db_rows(tmp_path / "events.db")) == 1


# ── 分桶丢弃：json / type / validation ──────────────────────────────────────
def test_bad_json_dropped_json_bucket(bus):
    assert bus.handle_line(b"{not json\n") == "drop:json"
    assert bus.dropped == {"json": 1, "type": 0, "validation": 0}


def test_bad_utf8_dropped_json_bucket(bus):
    assert bus.handle_line(b"\xff\xfe\n") == "drop:json"
    assert bus.dropped["json"] == 1


def test_unknown_type_dropped_type_bucket(bus):
    line = json.dumps({"v": 1, "type": "payload_sample", "sha256": "x"}) .encode()
    assert bus.handle_line(line) == "drop:type"
    assert bus.dropped["type"] == 1


def test_missing_event_payload_dropped_type_bucket(bus):
    assert bus.handle_line(b'{"v": 1, "type": "event"}') == "drop:type"
    assert bus.dropped["type"] == 1


def test_invalid_event_type_dropped_validation_bucket(bus):
    assert bus.handle_line(_msg(event_type="not_a_type")) == "drop:validation"
    assert bus.dropped["validation"] == 1


def test_missing_persona_id_dropped_validation_bucket(bus):
    line = json.loads(_msg())
    del line["event"]["persona_id"]
    assert bus.handle_line(json.dumps(line).encode()) == "drop:validation"
    assert bus.dropped["validation"] == 1


def test_dropped_events_never_land(bus, tmp_path):
    bus.handle_line(b"garbage")
    bus.handle_line(b'{"type": "nope"}')
    bus.handle_line(_msg(event_type="bad"))
    assert bus.wait_idle()
    assert _db_rows(tmp_path / "events.db") == []


# ── 背压：队列满 drop 计数 + 每 1000 次留痕 ────────────────────────────────
def test_backlog_drop_counted_and_traced(tmp_path):
    bus = HookBus(BusConfig(socket_path=tmp_path / "hook.sock",
                            events_db=tmp_path / "events.db",
                            max_backlog=1))
    try:
        bus.dropped_backlog = 999  # 下一次 drop 即触发第 1000 次留痕
        with bus._db_lock:  # 卡住写库线程，队列必然积满
            results = [bus.handle_line(_msg(ts=i)) for i in range(10)]
        assert results.count("drop:backlog") >= 1
        assert bus.dropped_backlog == 999 + results.count("drop:backlog")
        assert bus.wait_idle()
        rows = _db_rows(tmp_path / "events.db", "event_type='block_action'")
        assert len(rows) == 1
        assert rows[0][4] == "hook_bus backlog drop 1000"  # 留痕记触发时刻计数
        assert rows[0][5] == BUS_EVIDENCE_REF
    finally:
        bus.close()


# ── socket 服务：权限 600 / 父目录自建 / 双连接不串 ────────────────────────
def _start_bus(tmp_path, sock_rel="hook.sock"):
    bus = HookBus(BusConfig(socket_path=tmp_path / sock_rel,
                            events_db=tmp_path / "events.db"))
    t = threading.Thread(target=bus.serve_forever, daemon=True)
    t.start()
    deadline = time.monotonic() + 5
    while not bus.config.socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    return bus


def test_socket_permission_600_and_parent_autocreated(tmp_path):
    bus = _start_bus(tmp_path, sock_rel="nested/dir/hook.sock")
    try:
        mode = stat.S_IMODE(bus.config.socket_path.stat().st_mode)
        assert mode == 0o600
    finally:
        bus.close()


def _send_lines(sock_path, lines):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(sock_path))
    try:
        s.sendall(b"".join(lines))
    finally:
        s.close()


def test_concurrent_two_connections_no_crossing(tmp_path):
    bus = _start_bus(tmp_path)
    try:
        a = [_msg(ts=1000 + i, summary=f"connA 事件{i}") for i in range(20)]
        b = [_msg(ts=2000 + i, summary=f"connB 事件{i}") for i in range(20)]
        ta = threading.Thread(target=_send_lines,
                              args=(bus.config.socket_path, a))
        tb = threading.Thread(target=_send_lines,
                              args=(bus.config.socket_path, b))
        ta.start(); tb.start(); ta.join(); tb.join()
        assert bus.wait_idle()
        rows = _db_rows(tmp_path / "events.db")
        assert len(rows) == 40  # 全到、不丢不串
        summaries = {r[4] for r in rows}
        assert summaries == {f"connA 事件{i}" for i in range(20)} | \
                            {f"connB 事件{i}" for i in range(20)}
        assert sum(bus.dropped.values()) == 0 and bus.dropped_backlog == 0
    finally:
        bus.close()


def test_close_cleans_up_socket(tmp_path):
    bus = _start_bus(tmp_path)
    path = bus.config.socket_path
    bus.close()
    assert not path.exists()


# ── python -m 独立运行冒烟 ─────────────────────────────────────────────────
def test_module_runnable_help():
    proc = subprocess.run([sys.executable, "-m", "tishen.observ.hook_bus", "--help"],
                          capture_output=True, text=True)
    assert proc.returncode == 0
    assert "--socket" in proc.stdout and "--events-db" in proc.stdout


def test_module_end_to_end_over_socket(tmp_path):
    """独立进程：socket 进事件 → events.db 落库（协议串通冒烟的最小环）。"""
    sock = tmp_path / "hook.sock"
    db = tmp_path / "events.db"
    proc = subprocess.Popen(
        [sys.executable, "-m", "tishen.observ.hook_bus",
         "--socket", str(sock), "--events-db", str(db)])
    try:
        deadline = time.monotonic() + 5
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        _send_lines(sock, [_msg()])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if _db_rows(db):
                break
            time.sleep(0.05)
        rows = _db_rows(db)
        assert len(rows) == 1 and rows[0][0] == "p_hook01"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
