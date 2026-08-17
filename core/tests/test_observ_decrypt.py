"""tshark JSON → Event 流离线测试（fixtures/observ/tshark_sample.json）。"""

import json
import subprocess
from pathlib import Path

import pytest

from tishen.observ import decrypt
from tishen.observ.decrypt import (
    TsharkError, extract_handshakes, load_tshark_json, packets_to_events,
    run_tshark,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "observ" / "tshark_sample.json"


def _events():
    packets = load_tshark_json(FIXTURE)
    return packets_to_events(
        packets, persona_id="p_test01", session_id="sess-1", shard="ring.pcap0")


def test_run_tshark_keeps_complete_packets_before_truncated_tail(
        monkeypatch, caplog):
    packets = [{"_source": {"layers": {"frame": {"frame.number": "1"}}}}]
    proc = subprocess.CompletedProcess(
        args=["tshark"], returncode=2, stdout=json.dumps(packets),
        stderr=("Running as user root.\n"
                "tshark: capture appears to have been cut short in the middle "
                "of a packet."))
    monkeypatch.setattr(decrypt.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(decrypt.subprocess, "run", lambda *args, **kwargs: proc)

    assert run_tshark("ring.pcap0") == packets
    assert "保留此前 1 个完整包" in caplog.text


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        ("[{}]", "tshark: permission denied"),
        ("[]", "tshark: file appears to have been cut short in the middle of a packet"),
    ],
)
def test_run_tshark_rejects_other_nonzero_or_empty_tail(
        monkeypatch, stdout, stderr):
    proc = subprocess.CompletedProcess(
        args=["tshark"], returncode=2, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(decrypt.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(decrypt.subprocess, "run", lambda *args, **kwargs: proc)

    with pytest.raises(TsharkError, match="tshark 退出码 2"):
        run_tshark("ring.pcap0")


def test_event_types_cover_fixture():
    """样例含 request/response/cookie_set/redirect/dns_query/tls_handshake 各至少一。"""
    types = {e.event_type for e in _events()}
    assert {"request", "response", "cookie_set", "redirect",
            "dns_query", "tls_handshake"} <= types


def test_request_fields():
    """request 事件：method/target_host/target_url/ts/evidence_ref/decrypt_state。"""
    req = next(e for e in _events() if e.event_type == "request"
               and e.method == "GET")
    assert req.target_host == "example.com"
    assert req.target_url == "http://example.com/index.html"
    assert req.ts == 1753600000250          # 采信 pcap 包时间戳
    assert req.evidence_ref == "pcap:ring.pcap0#3"
    assert req.decrypt_state == "full"
    assert req.alert_level == 0             # 观测层恒 0
    assert req.engine_tags == "[]"          # 初始为空
    assert req.validate() == []


def test_response_and_cookie_set():
    """response 200 + Set-Cookie 产 cookie_set（值不落库）。"""
    events = _events()
    resp = next(e for e in events if e.event_type == "response" and e.status == 200)
    assert resp.target_host == "example.com"
    cookie = next(e for e in events if e.event_type == "cookie_set")
    assert "sessionid" in cookie.summary
    assert "abc123" not in cookie.summary   # 值不落库


def test_redirect_and_metadata_states():
    """302 归 redirect；dns/tls_handshake 为 metadata_only。"""
    events = _events()
    red = next(e for e in events if e.event_type == "redirect")
    assert red.status == 302 and red.target_url == "http://example.com/landing"
    meta = [e for e in events if e.event_type in ("dns_query", "tls_handshake")]
    assert meta and all(e.decrypt_state == "metadata_only" for e in meta)
    dns = next(e for e in events if e.event_type == "dns_query")
    assert dns.target_host == "doubleclick.net"


def test_http2_request_and_cookie():
    """HTTP/2 headers 视图同样产 request/cookie_set。"""
    events = _events()
    h2 = next(e for e in events if e.event_type == "request" and e.method == "POST")
    assert h2.target_host == "google-analytics.com"
    assert h2.target_url == "https://google-analytics.com/collect"
    assert any(e.event_type == "cookie_set" and e.target_host == "google-analytics.com"
               for e in events)


def test_extract_handshakes():
    """ClientHello 提取：random 小写、SNI、帧号、流号。"""
    records = extract_handshakes(load_tshark_json(FIXTURE))
    assert len(records) == 1
    rec = records[0]
    assert rec.client_random == "1" * 64
    assert rec.sni == "example.com"
    assert rec.frame_number == 2
    assert rec.stream == "0"
    assert rec.ts_ms == 1753600000120


def test_extract_handshakes_normalizes_colon_random():
    packets = [{
        "_source": {"layers": {
            "frame": {"frame.number": "9", "frame.time_epoch": "1753600000.5"},
            "tcp": {"tcp.stream": "4"},
            "tls": {
                "tls.handshake.type": "1",
                "tls.handshake.random": ":".join(["AB"] * 32),
                "tls.handshake.extensions_server_name": "tls13.example",
            },
        }},
    }]

    rec = extract_handshakes(packets)[0]

    assert rec.client_random == "ab" * 32
    assert rec.sni == "tls13.example"


def test_event_id_ulid_ordered_unique():
    """全部事件 event_id 为 26 字符 ULID 且互不重复。"""
    ids = [e.event_id for e in _events()]
    assert all(len(i) == 26 for i in ids)
    assert len(set(ids)) == len(ids)
