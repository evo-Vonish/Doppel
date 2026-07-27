"""daemon 单轮循环离线测试：临时目录 + 假分片 + 注入解密/加密替身。"""

import os
import time
from pathlib import Path

import pytest

from tishen.observ import store
from tishen.observ.daemon import DaemonConfig, ObservDaemon
from tishen.observ.decrypt import load_tshark_json
from tishen.observ.query import query_events

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "observ"


@pytest.fixture
def sandbox(tmp_path):
    """搭容器内目录结构：pcap 假分片（mtime 递增，最新为活动分片）+ keylog。"""
    pcap_dir = tmp_path / "pcap"
    sslkeys_dir = tmp_path / "sslkeys"
    events_dir = tmp_path / "events"
    for d in (pcap_dir, sslkeys_dir, events_dir):
        d.mkdir()

    def make_shards(n: int) -> list[Path]:
        shards = []
        base = time.time() - 1000
        for i in range(n):
            shard = pcap_dir / f"ring.pcap{i}"
            shard.write_bytes(b"fake pcap bytes")
            os.utime(shard, (base + i * 60, base + i * 60))
            shards.append(shard)
        return shards

    keylog_path = sslkeys_dir / "sslkeys.log"
    keylog_path.write_text(
        (FIXTURES / "sample.keylog").read_text(encoding="utf-8"), encoding="utf-8")

    packets = load_tshark_json(FIXTURES / "tshark_sample.json")

    def make_daemon(**over):
        decrypt_fn = over.pop("decrypt_fn", None) or (lambda shard, kl: packets)
        cfg = DaemonConfig(
            persona_id="p_test01", session_id="sess-1",
            pcap_dir=pcap_dir, keylog_path=keylog_path, events_dir=events_dir,
            retain_days=3650,        # 样例 ts 为 2025 年，放大保留期防清理误删
            age_recipient="age1testrecipient", **over)
        encrypted = []

        def fake_encrypt(path, recipient):
            out = path.with_name(path.name + ".age")
            out.write_bytes(b"age-encrypted:" + path.read_bytes())
            encrypted.append(path.name)
            return out

        daemon = ObservDaemon(cfg, decrypt_fn=decrypt_fn, encrypt_fn=fake_encrypt)
        daemon._test_encrypted = encrypted   # 测试断言用
        return daemon

    return make_shards, make_daemon, events_dir


def test_run_once_processes_old_shards(sandbox):
    """活动分片跳过，旧分片全处理：事件落库、加密删明文、台账登记、幂等。"""
    make_shards, make_daemon, events_dir = sandbox
    shards = make_shards(3)                      # ring.pcap2 为活动分片
    daemon = make_daemon()
    stats = daemon.run_once()
    assert stats["processed"] == 2
    assert stats["events"] > 0
    rows = query_events(str(events_dir / "events.db"))
    assert {r["event_type"] for r in rows} >= {"request", "response",
                                               "cookie_set", "dns_query"}
    assert all(r["alert_level"] == 0 for r in rows)
    # 明文已删、密文就位；活动分片原样保留
    assert not shards[0].exists() and not shards[1].exists()
    assert shards[2].exists()
    assert (shards[0].parent / "ring.pcap0.age").exists()
    assert set(daemon._test_encrypted) == {"ring.pcap0", "ring.pcap1"}
    # 幂等：第二轮无待处理分片
    assert daemon.run_once()["processed"] == 0
    daemon.close()


def test_backpressure_skips_newest_with_gap(sandbox):
    """积压超限：只处理最旧 1 片，最新 2 片跳片并写 gap 事件标注区间。"""
    make_shards, make_daemon, events_dir = sandbox
    make_shards(4)                               # 活动 1 + 积压 3，上限 1
    daemon = make_daemon(backlog_limit=1)
    stats = daemon.run_once()
    assert stats["processed"] == 1
    assert stats["skipped"] == 2
    gaps = [r for r in query_events(str(events_dir / "events.db"), limit=200)
            if r["decrypt_state"] == "gap"]
    assert len(gaps) == 2
    assert all("背压跳片" in r["summary"] for r in gaps)
    # 跳片分片台账记 gap，不再重处理
    conn = store.connect(events_dir / "events.db")
    assert store.is_shard_processed(conn, "ring.pcap1")
    assert store.is_shard_processed(conn, "ring.pcap2")
    conn.close()
    daemon.close()


def test_decrypt_failure_writes_gap_and_continues(sandbox):
    """解密抛异常：转 gap 事件继续下一片，run_once 不抛出。"""
    make_shards, make_daemon, events_dir = sandbox
    shards = make_shards(3)

    def flaky(shard, kl):
        if shard.name == "ring.pcap0":
            raise RuntimeError("tshark 爆炸")
        return load_tshark_json(FIXTURES / "tshark_sample.json")

    daemon = make_daemon(decrypt_fn=flaky)
    stats = daemon.run_once()                    # 不抛出即通过一半
    assert stats["processed"] == 2
    rows = query_events(str(events_dir / "events.db"), limit=200)
    gaps = [r for r in rows if r["decrypt_state"] == "gap"]
    assert len(gaps) == 1 and "解密失败" in gaps[0]["summary"]
    assert gaps[0]["evidence_ref"] == "pcap:ring.pcap0"
    # 失败片也已加密删明文（处理闭环），正常片事件齐全
    assert not shards[0].exists()
    assert any(r["event_type"] == "request" for r in rows)
    daemon.close()


def test_no_key_handshake_marked_gap(sandbox):
    """keylog 缺失时握手逐条 no_key gap 标记（完整率口径分母）。"""
    make_shards, make_daemon, events_dir = sandbox
    make_shards(2)
    # keylog 换成空文件：样例里的 ClientHello 必然缺钥
    daemon = make_daemon()
    daemon.config.keylog_path.write_text("", encoding="utf-8")
    daemon.run_once()
    rows = query_events(str(events_dir / "events.db"), limit=200)
    gaps = [r for r in rows if r["decrypt_state"] == "gap"]
    assert len(gaps) == 1
    assert "缺密钥" in gaps[0]["summary"] and "example.com" in gaps[0]["summary"]
    assert gaps[0]["target_host"] == "example.com"
    # 元数据兜底事件照常产出（不隐藏不脑补）
    assert any(r["event_type"] == "tls_handshake"
               and r["decrypt_state"] == "metadata_only" for r in rows)
    daemon.close()


def test_encrypt_failure_keeps_plaintext(sandbox):
    """加密失败：明文保留不删（不可销毁未加密证据），事件照常落库。"""
    make_shards, make_daemon, events_dir = sandbox
    shards = make_shards(2)
    daemon = make_daemon()
    daemon.encrypt_fn = lambda path, recipient: (_ for _ in ()).throw(
        RuntimeError("age 缺席"))
    stats = daemon.run_once()
    assert stats["processed"] == 1
    assert shards[0].exists()                    # 明文保留
    assert query_events(str(events_dir / "events.db"))
    daemon.close()
