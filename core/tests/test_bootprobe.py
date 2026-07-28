"""R2 启动计时探针离线测试（SPEC-M5 §4/§8）：marks 解析 / compose 三档 / 写库 / wait_port 注入。

全程不依赖 docker；wait_port 就绪路径用本地临时监听套接字，超时路径注入假时钟。
"""

import socket
import sqlite3
import threading

import pytest

from tishen.resbench import bootprobe

_LOG = """[persona_bake] 门禁复验通过（镜像 Chrome stable=140.0）
[BOOT_MARK] segment=entry elapsed_ms=0
[BOOT_MARK] segment=lint_recheck elapsed_ms=120
[BOOT_MARK] segment=timezone elapsed_ms=135
[BOOT_MARK] segment=chrome_launch elapsed_ms=4210
"""


# ── parse_boot_marks：保序 / 忽略非 BOOT_MARK 行 / 非法行跳过 ───────────────
def test_parse_marks_keep_order():
    marks = bootprobe.parse_boot_marks(_LOG)
    assert marks == [("entry", 0), ("lint_recheck", 120),
                     ("timezone", 135), ("chrome_launch", 4210)]


def test_parse_marks_ignores_non_mark_lines():
    assert bootprobe.parse_boot_marks("hello\n[persona_bake] 错误：x\n") == []


def test_parse_marks_skips_malformed_lines():
    """格式非法（缺字段/非整数/负值）跳过不报错。"""
    text = "\n".join([
        "[BOOT_MARK] segment=entry elapsed_ms=abc",   # 非整数
        "[BOOT_MARK] segment=entry",                   # 缺 elapsed_ms
        "[BOOT_MARK] elapsed_ms=5",                    # 缺 segment
        "[BOOT_MARK] segment=entry elapsed_ms=-5",     # 负值非法
        "[BOOT_MARK] segment=fonts elapsed_ms=880",    # 唯一合法行
    ])
    assert bootprobe.parse_boot_marks(text) == [("fonts", 880)]


# ── compose_boot：三档枚举 / neko_ready 权威 / 末段兜底 / 空 marks ──────────
def test_compose_boot_three_modes():
    marks = [("entry", 0), ("chrome_launch", 4210)]
    for mode in ("cold-create", "cold-start", "warm-resume"):
        boot = bootprobe.compose_boot(marks, mode)
        assert boot["boot_mode"] == mode
        assert boot["segments"] == marks


def test_compose_boot_invalid_mode_raises_chinese():
    with pytest.raises(ValueError, match="boot_mode 非法"):
        bootprobe.compose_boot([], "hot-reboot")


def test_compose_boot_neko_ready_authoritative():
    """neko_ready_ms 有则权威，覆盖末段 elapsed_ms。"""
    marks = [("entry", 0), ("chrome_launch", 4210)]
    boot = bootprobe.compose_boot(marks, "cold-create", neko_ready_ms=5000)
    assert boot["total_ms"] == 5000


def test_compose_boot_falls_back_to_last_segment():
    marks = [("entry", 0), ("neko", 3210), ("chrome_launch", 4210)]
    assert bootprobe.compose_boot(marks, "cold-start")["total_ms"] == 4210


def test_compose_boot_empty_marks_total_none():
    """部分段缺失时不编造总和：空 marks 且无 neko_ready → total_ms=None。"""
    assert bootprobe.compose_boot([], "warm-resume")["total_ms"] is None


# ── write_boot：boots + boot_segments 落库行数 ──────────────────────────────
def test_write_boot_rows(tmp_path):
    db = str(tmp_path / "resbench.db")
    marks = [("entry", 0), ("neko", 3210), ("chrome_launch", 4210)]
    boot = bootprobe.compose_boot(marks, "cold-create")
    boot_id = bootprobe.write_boot(db, None, boot)  # run_id 可空
    conn = sqlite3.connect(db)
    brow = conn.execute(
        "SELECT run_id, boot_mode, total_ms FROM boots WHERE id = ?", (boot_id,)).fetchone()
    segs = conn.execute(
        "SELECT segment, elapsed_ms FROM boot_segments WHERE boot_id = ? ORDER BY id",
        (boot_id,)).fetchall()
    conn.close()
    assert brow == (None, "cold-create", 4210)
    assert segs == marks  # 段序保持


def test_write_boot_null_total(tmp_path):
    db = str(tmp_path / "resbench.db")
    boot = bootprobe.compose_boot([], "warm-resume")
    boot_id = bootprobe.write_boot(db, None, boot)
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT total_ms FROM boots WHERE id = ?", (boot_id,)).fetchone()
    conn.close()
    assert row == (None,)


# ── wait_port：注入 now/sleep 模拟超时与就绪 ────────────────────────────────
def test_wait_port_timeout_with_fake_clock():
    """闭端口 + 假时钟：超时返回 None；sleep 推进时钟实现快进。"""
    clock = {"t": 0.0}

    def now():
        return clock["t"]

    def sleep(s):
        clock["t"] += s

    # 找一个确定关闭的端口
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    assert bootprobe.wait_port("127.0.0.1", closed_port, 1.0,
                               sleep=sleep, now=now) is None
    assert clock["t"] >= 1.0


def test_wait_port_ready_returns_elapsed():
    """本地监听套接字：第三次探测就绪，返回就绪耗时秒。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        clock = {"t": 100.0, "probes": 0}
        real_connect = socket.create_connection

        def fake_connect(addr, timeout=None):
            clock["probes"] += 1
            if clock["probes"] < 3:
                raise ConnectionRefusedError("尚未就绪")
            return real_connect(addr, timeout=timeout)

        def now():
            return clock["t"]

        def sleep(s):
            clock["t"] += s

        orig = bootprobe.socket.create_connection
        bootprobe.socket.create_connection = fake_connect
        try:
            elapsed = bootprobe.wait_port("127.0.0.1", port, 10.0, sleep=sleep, now=now)
        finally:
            bootprobe.socket.create_connection = orig
        assert elapsed == pytest.approx(0.2)  # 两次失败 sleep(0.1) 后就绪
    finally:
        srv.close()


def test_wait_port_real_listening_socket():
    """真实监听端口（真时钟）：返回非负耗时浮点数。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        elapsed = bootprobe.wait_port("127.0.0.1", port, 2.0)
        assert isinstance(elapsed, float) and elapsed >= 0.0
    finally:
        srv.close()


def test_parse_then_compose_full_pipeline(tmp_path):
    """端到端纯函数链：日志 → marks → compose → 写库，段序与 total 一致。"""
    marks = bootprobe.parse_boot_marks(_LOG)
    boot = bootprobe.compose_boot(marks, "cold-create", neko_ready_ms=4800)
    db = str(tmp_path / "resbench.db")
    boot_id = bootprobe.write_boot(db, None, boot)
    conn = sqlite3.connect(db)
    n = conn.execute("SELECT COUNT(*) FROM boot_segments WHERE boot_id = ?",
                     (boot_id,)).fetchone()[0]
    total = conn.execute("SELECT total_ms FROM boots WHERE id = ?",
                         (boot_id,)).fetchone()[0]
    conn.close()
    assert n == 4 and total == 4800
