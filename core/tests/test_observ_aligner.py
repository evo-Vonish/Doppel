"""对齐器离线测试（fixtures/observ/alignment_handshakes.json + sample.keylog）。"""

import json
from pathlib import Path

from tishen.observ import keylog
from tishen.observ.aligner import (
    HandshakeRecord,
    align,
    normalize_client_random,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "observ"


def _load_handshakes():
    with (FIXTURES / "alignment_handshakes.json").open(encoding="utf-8") as f:
        return [HandshakeRecord(**d) for d in json.load(f)]


def test_align_matched_and_no_key():
    """4 条握手：2 条命中 keylog，2 条 no_key（含 1 条无 SNI 归 (unknown)）。"""
    keylog_map = keylog.parse_keylog(FIXTURES / "sample.keylog")
    report = align(_load_handshakes(), keylog_map)
    assert report.total == 4
    assert report.matched == 2
    assert report.coverage == 0.5
    assert [r.frame_number for r in report.no_key] == [9, 15]


def test_align_per_host_coverage():
    """按 host 聚合：example.com 2/2，tracker.example.net 0/1，(unknown) 0/1。"""
    keylog_map = keylog.parse_keylog(FIXTURES / "sample.keylog")
    report = align(_load_handshakes(), keylog_map)
    assert report.per_host["example.com"].matched == 2
    assert report.per_host["example.com"].total == 2
    assert report.per_host["tracker.example.net"].gap_frames == [9]
    assert report.per_host["(unknown)"].total == 1


def test_align_case_insensitive_and_empty():
    """匹配不区分大小写；空握手清单覆盖率定义为 1.0（不制造假缺口）。"""
    rec = HandshakeRecord(client_random="A" * 64, sni="x.com", frame_number=1)
    report = align([rec], {"a" * 64: "b" * 64})
    assert report.matched == 1
    assert align([], {}).coverage == 1.0


def test_align_normalizes_tshark_colon_separated_random():
    """tshark 的 aa:bb 格式须与 NSS keylog 的无分隔十六进制命中。"""
    tshark_random = ":".join(["AB"] * 32)
    nss_random = "ab" * 32
    rec = HandshakeRecord(
        client_random=tshark_random, sni="tls13.example", frame_number=7)

    report = align([rec], {nss_random: "c" * 64})

    assert normalize_client_random(tshark_random) == nss_random
    assert report.matched == 1 and report.coverage == 1.0
    assert report.no_key == []


def test_align_report_as_dict_serializable():
    """as_dict 产物可 JSON 序列化（daemon 落对齐报告用）。"""
    report = align(_load_handshakes(), {})
    data = report.as_dict()
    json.dumps(data)
    assert data["total"] == 4 and data["matched"] == 0
    assert len(data["no_key"]) == 4
