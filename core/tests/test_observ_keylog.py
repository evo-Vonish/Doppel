"""keylog 解析离线测试（fixtures/observ/sample.keylog）。"""

from pathlib import Path

from tishen.observ import keylog

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "observ" / "sample.keylog"

R1 = "1" * 64
R2 = "2" * 64


def test_parse_keylog_client_random_only():
    """parse_keylog 只回 CLIENT_RANDOM 映射，坏行静默跳过。"""
    result = keylog.parse_keylog(FIXTURE)
    assert result == {R1: "a" * 64, R2: "b" * 64}


def test_parse_keylog_all_labels():
    """parse_keylog_all 按 label 分桶，含 TLS 1.3 扩展行。"""
    buckets = keylog.parse_keylog_all(FIXTURE)
    assert set(buckets) == {"CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET"}
    assert buckets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == {"3" * 64: "c" * 64}


def test_parse_keylog_missing_file(tmp_path):
    """文件不存在返回空 dict（缺钥走 no_key 口径，不 crash）。"""
    assert keylog.parse_keylog(tmp_path / "不存在.log") == {}


def test_parse_keylog_lines_tolerates_garbage():
    """空行/注释/列数不对/非十六进制全部跳过。"""
    lines = [
        "",
        "# 注释",
        "CLIENT_RANDOM",
        "CLIENT_RANDOM nothex " + "a" * 64,
        "CLIENT_RANDOM " + "f" * 64 + " " + "0" * 64 + " 多余列",
        "CLIENT_RANDOM " + "F" * 64 + " " + "e" * 64,  # 大写十六进制合法，键归一小写
    ]
    buckets = keylog.parse_keylog_lines(lines)
    assert buckets == {"CLIENT_RANDOM": {"f" * 64: "e" * 64}}
