"""trackerdb.db 建库与 meta 台账（SPEC-E §1.1，Coder A 拥有）。

数据集归一化库：rules（E2 规则）、domains / domain_sources（E1 底表）、
meta（schema_version 与各数据源 JSON 台账）。路径默认
`<tishen_home>/engine/trackerdb.db`（tishen.state.tishen_home() 解析）。
WAL 模式：引擎守护写入与面板/调试查询并发不互锁。
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from tishen.state import tishen_home

# SPEC-E §1.1 全量 schema（列序即契约）
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,            -- schema_version / source:<name> 的 JSON 台账
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (   -- E2 规则（ABP 子集解析产物）
    rule_id      TEXT PRIMARY KEY,   -- "<source>:<sha1(raw)[:12]>"
    raw          TEXT NOT NULL,      -- 原始规则行
    kind         TEXT NOT NULL,      -- block / exception
    pattern_type TEXT NOT NULL,      -- domain_anchor / substring
    host         TEXT,               -- domain_anchor 的锚定域名（可索引匹配键）
    path_pattern TEXT,               -- 域名之后的 path 通配（无则 NULL）
    third_party  INTEGER,            -- 1 仅第三方 / 0 仅第一方 / NULL 不限
    domain_modifier TEXT,            -- $domain= 白名单，'|' 分隔原样存
    source       TEXT NOT NULL       -- easyprivacy / trackerdb
);
CREATE INDEX IF NOT EXISTS idx_rules_host ON rules(host);
CREATE TABLE IF NOT EXISTS domains ( -- E1 域名→实体底表
    domain      TEXT PRIMARY KEY,
    entity      TEXT,                -- 实体名（NC 源提供；非 NC 源可为 NULL）
    category    TEXT,                -- advertising/analytics/fingerprinting/cryptomining/unknown
    fingerprinting_score INTEGER,    -- 0–3（仅 NC 包；未启用恒 NULL）
    prevalence  REAL,                -- whoTracks.me 流行度（无则 NULL）
    is_tracking INTEGER NOT NULL DEFAULT 0,
    source      TEXT NOT NULL        -- 多源合并时取优先级最高者，其余进 sources 列
);
CREATE TABLE IF NOT EXISTS domain_sources (  -- 多源命中留痕
    domain TEXT NOT NULL, source TEXT NOT NULL,
    PRIMARY KEY (domain, source)
);
"""

# SPEC-E §1.1：schema_version 台账值
SCHEMA_VERSION = 1


def default_db_path() -> Path:
    """默认库路径 `<tishen_home>/engine/trackerdb.db`（SPEC-E §1.1）。"""
    return tishen_home() / "engine" / "trackerdb.db"


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """打开（必要时创建）trackerdb.db 并初始化 schema，写 schema_version 台账。

    db_path 为 None 时走 default_db_path()；测试可注入临时路径。
    """
    p = Path(db_path) if db_path is not None else default_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),))
    return conn


def set_source_meta(conn: sqlite3.Connection, name: str, *,
                    license: str, nc: bool, attribution: str,
                    rows: int, enabled: bool,
                    imported_at: int | None = None) -> dict:
    """写数据源 JSON 台账 `source:<name>`（SPEC-E §1.1 meta 台账规范）。

    imported_at 为 Unix 毫秒，默认取当前时间；返回落库的台账 dict。
    """
    if imported_at is None:
        imported_at = time.time_ns() // 1_000_000
    entry = {
        "license": license,
        "nc": bool(nc),
        "attribution": attribution,
        "rows": int(rows),
        "imported_at": int(imported_at),
        "enabled": bool(enabled),
    }
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (f"source:{name}", json.dumps(entry, ensure_ascii=False, sort_keys=True)))
    return entry


def get_source_status(conn: sqlite3.Connection, name: str) -> dict | None:
    """读数据源台账 `source:<name>`；未导入返回 None（SPEC-E §1.1）。"""
    cur = conn.execute("SELECT value FROM meta WHERE key = ?", (f"source:{name}",))
    row = cur.fetchone()
    if row is None:
        return None
    return json.loads(row[0])
