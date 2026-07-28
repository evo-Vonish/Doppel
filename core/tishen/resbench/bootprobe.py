"""R2 启动计时探针（SPEC-M5 §4）：BOOT_MARK 日志解析 + boots/boot_segments 落库 + 端口就绪探测。

口径（M5 方案 §一 BOOT）：三档分别计时不得混报——cold-create（无容器→docker run→首帧
可交互，验收线 ≤10s）/ cold-start（容器已存在→docker start，目标 ≤5s）/ warm-resume
（pause→unpause，目标 ≤1.5s）。cold-create 必须拆段（persona_bake 十步 BOOT_MARK，§5）。

纪律（SPEC-M5 §0/§4）：
- parse_boot_marks / compose_boot 为纯函数；行格式非法跳过不报错（日志解析不许崩流程）；
- total_ms 口径：neko_ready_ms 有则权威，无则末段 elapsed_ms，皆无则 None（不编造总和）。
"""

from __future__ import annotations

import re
import socket
import time

from .sampler import _connect, _now_iso

# boot_mode 三档枚举（M5 方案 §一 BOOT，口径不同不得混报）
BOOT_MODES = frozenset({"cold-create", "cold-start", "warm-resume"})

# persona_bake §5 打点行：[BOOT_MARK] segment=<seg> elapsed_ms=<ms>
_MARK_RE = re.compile(r"\[BOOT_MARK\]\s+segment=(\S+)\s+elapsed_ms=(\d+)")


def parse_boot_marks(log_text: str) -> list[tuple[str, int]]:
    """解析 BOOT_MARK 行 → [(segment, elapsed_ms)]，保序；非 BOOT_MARK 行忽略；
    行格式非法跳过不报错（日志里不许因解析崩流程）"""
    marks: list[tuple[str, int]] = []
    for line in log_text.splitlines():
        m = _MARK_RE.search(line)
        if m is None:
            continue
        marks.append((m.group(1), int(m.group(2))))
    return marks


def compose_boot(marks: list[tuple[str, int]], boot_mode: str,
                 neko_ready_ms: int | None = None) -> dict:
    """合成 boots+boot_segments 记录 dict：total_ms = neko_ready_ms（有则权威，
    无则末段 elapsed_ms，皆无则 None）；boot_mode 校验三档枚举，非法 ValueError"""
    if boot_mode not in BOOT_MODES:
        raise ValueError(
            f"boot_mode 非法：{boot_mode!r}（三档枚举：{sorted(BOOT_MODES)}，口径不同不得混报）")
    if neko_ready_ms is not None:
        total_ms = neko_ready_ms
    elif marks:
        total_ms = marks[-1][1]
    else:
        total_ms = None
    return {"boot_mode": boot_mode, "total_ms": total_ms, "segments": list(marks)}


def write_boot(db_path: str, run_id: int | None, boot: dict) -> int:
    """把 compose_boot 产物写 boots + boot_segments（同一事务），返回 boot id。"""
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO boots (run_id, boot_mode, total_ms, recorded_at) VALUES (?,?,?,?)",
            (run_id, boot["boot_mode"], boot["total_ms"], _now_iso()),
        )
        boot_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO boot_segments (boot_id, segment, elapsed_ms) VALUES (?,?,?)",
            [(boot_id, segment, elapsed_ms) for segment, elapsed_ms in boot["segments"]],
        )
        conn.commit()
        return boot_id
    finally:
        conn.close()


def wait_port(host: str, port: int, timeout_s: float,
              sleep=time.sleep, now=time.monotonic) -> float | None:
    """TCP 连接探测直到就绪或超时；返回就绪耗时秒（float），超时 None；now/sleep 可注入"""
    start = now()
    while True:
        try:
            with socket.create_connection((host, port), timeout=min(1.0, max(timeout_s, 0.1))):
                return now() - start
        except OSError:
            pass
        if now() - start >= timeout_s:
            return None
        sleep(0.1)
