"""events.db 落库（M3 方案 §3.1 全字段、§7.2 性能预算）。

- 单表 events，字段与 §3.1 字段表一一对应（列序即 EVENT_COLUMNS）；
- WAL 模式：面板查询与守护进程写入并发不互锁（§2.2 落库选型）；
- 批量插入：每批 ≤100 事件一事务（§7.2 写入延迟预算 P99 ≤ 50ms）；
- retain_days 清理：滚动删除超期事件（§7.3 磁盘策略的事件库侧）。
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .events import EVENT_COLUMNS, Event

# §3.1 字段表（与 EVENT_COLUMNS 顺序一致）
_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,   -- ULID，时间有序
    persona_id    TEXT NOT NULL,      -- 替身 id（persona.yaml meta.id）
    ts            INTEGER NOT NULL,   -- Unix 毫秒（pcap 包时间戳）
    session_id    TEXT NOT NULL,      -- 浏览会话 id
    event_type    TEXT NOT NULL,      -- §3.2 枚举
    page_url      TEXT,               -- 顶层文档 URL
    page_id       TEXT,               -- 页面实例 id
    frame         TEXT,               -- top / iframe
    actor_script  TEXT,               -- 脚本归因（不可归因 NULL）
    target_host   TEXT,               -- 目标域名
    target_url    TEXT,               -- 完整 URL（响应体不入此字段）
    method        TEXT,               -- request/response 专用
    status        INTEGER,            -- request/response 专用
    summary       TEXT NOT NULL,      -- 人类可读一句话
    evidence_ref  TEXT NOT NULL,      -- pcap:分片名#帧号 / payload:加密文件名
    decrypt_state TEXT NOT NULL,      -- full / metadata_only / gap
    engine_tags   TEXT NOT NULL DEFAULT '[]',  -- 判别引擎注入（JSON 数组）
    alert_level   INTEGER NOT NULL DEFAULT 0   -- 观测层恒 0，引擎回写
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts);

-- 守护进程分片处理台账（§3.1 之外的内部簿记，不属事件 Schema）
CREATE TABLE IF NOT EXISTS processed_shards (
    shard        TEXT PRIMARY KEY,    -- 分片代际 id（文件名@mtime_ns:大小）
    processed_at INTEGER NOT NULL,    -- 处理完成 Unix 毫秒
    status       TEXT NOT NULL,       -- ok / gap（异常或背压跳片）
    note         TEXT                 -- 说明（覆盖率、异常摘要）
);
"""

# 每事务最大事件数（§7.2：每批 100 事件一事务）
BATCH_SIZE = 100


def connect(db_path) -> sqlite3.Connection:
    """打开（必要时创建）事件库并初始化 schema。WAL + 外键关闭默认。"""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def insert_events(conn: sqlite3.Connection, events: list[Event]) -> int:
    """批量插入事件，返回实际写入条数。

    写入前逐条过 Event.validate()；不合法事件跳过（不污染库），
    合法部分照常落库——观测降级不可影响链路。
    """
    sql = (
        f"INSERT OR IGNORE INTO events ({', '.join(EVENT_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in EVENT_COLUMNS)})"
    )
    rows = [e.to_row() for e in events if not e.validate()]
    written = 0
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i:i + BATCH_SIZE]
        with conn:
            conn.executemany(sql, batch)
        written += len(batch)
    return written


def cleanup(conn: sqlite3.Connection, retain_days: int,
            now_ms: int | None = None) -> int:
    """删除早于 retain_days 天的事件，返回删除条数（§7.3 滚动清除）。"""
    if retain_days < 1:
        raise ValueError(f"retain_days 须 ≥1，实际为 {retain_days!r}")
    if now_ms is None:
        now_ms = time.time_ns() // 1_000_000
    cutoff = now_ms - retain_days * 86_400_000
    with conn:
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    return cur.rowcount


def record_shard(conn: sqlite3.Connection, shard: str, status: str,
                 note: str = "") -> None:
    """登记分片代际处理结果（幂等：同代重处理时覆盖旧记录）。"""
    now_ms = time.time_ns() // 1_000_000
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO processed_shards"
            " (shard, processed_at, status, note) VALUES (?, ?, ?, ?)",
            (shard, now_ms, status, note))


def is_shard_processed(conn: sqlite3.Connection, shard: str) -> bool:
    """查询分片代际是否已处理过（崩溃重启不重复解密）。"""
    cur = conn.execute(
        "SELECT 1 FROM processed_shards WHERE shard = ?", (shard,))
    return cur.fetchone() is not None
