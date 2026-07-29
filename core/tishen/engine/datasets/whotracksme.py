"""WhoTracks.me 月度 trackerdb 适配器（SPEC-E §6，Wave2 Coder B 拥有）。

CC BY 4.0（nc=False），非 NC 核心路径可用。本地文件注入，不真连网
（SPEC-E §10-6：下载/导入一律以本地 fixture 文件参数化）。

归一化 JSON 格式（data_dir/whotracksme.json）：
    {"domains": {"tracker.example": {"prevalence": 0.012,
                                      "entity": "Example Inc",      // 可省
                                      "category": "advertising"}}}  // 可省
导入：prevalence 写 domains；entity/category 仅在未占用时补充；
is_tracking=1；source 列取优先级最高者（NC 源已在则不被覆盖）。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..trackerdb import set_source_meta
from .licenses import LICENSE_MATRIX

_FILENAME = "whotracksme.json"
_LICENSE = LICENSE_MATRIX["whotracksme"]


def _read_dataset(data_dir: str | Path) -> dict[str, dict]:
    """读归一化 JSON，返回 {domain: {...}}；文件缺失抛 FileNotFoundError。"""
    path = Path(data_dir) / _FILENAME
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    domains = data.get("domains") if isinstance(data, dict) else None
    if not isinstance(domains, dict):
        raise ValueError(f"{path} 缺少 \"domains\" 对象（归一化格式见模块 docstring）")
    return domains


def import_whotracksme(conn: sqlite3.Connection, data_dir: str | Path) -> int:
    """导入 whoTracks.me 数据集（SPEC-E §6），返回写入的域名行数。

    prevalence 恒更新；entity/category 只补空（NC 源已提供时不覆盖）；
    source 列只在无 NC 源占用时写 "whotracksme"；多源命中留痕
    domain_sources；最后写 meta 台账 source:whotracksme。
    """
    domains = _read_dataset(data_dir)
    rows = 0
    with conn:
        for domain, info in sorted(domains.items()):
            if not isinstance(info, dict):
                continue
            domain = domain.lower().strip()
            if not domain:
                continue
            prevalence = info.get("prevalence")
            prevalence = float(prevalence) if prevalence is not None else None
            entity = info.get("entity") or None
            category = info.get("category") or None
            conn.execute(
                "INSERT INTO domains (domain, entity, category,"
                " fingerprinting_score, prevalence, is_tracking, source)"
                " VALUES (?, ?, ?, NULL, ?, 1, 'whotracksme')"
                " ON CONFLICT(domain) DO UPDATE SET"
                "   prevalence = excluded.prevalence,"
                "   is_tracking = 1,"
                "   entity = COALESCE(domains.entity, excluded.entity),"
                "   category = CASE WHEN domains.category IS NULL"
                "                   OR domains.category = 'unknown'"
                "              THEN COALESCE(excluded.category, domains.category)"
                "              ELSE domains.category END,"
                "   source = CASE WHEN domains.source IN"
                "                 ('tracker_radar', 'trackerdb')"
                "              THEN domains.source ELSE 'whotracksme' END",
                (domain, entity, category, prevalence))
            conn.execute(
                "INSERT OR IGNORE INTO domain_sources (domain, source)"
                " VALUES (?, 'whotracksme')", (domain,))
            rows += 1

    set_source_meta(conn, "whotracksme",
                    license=_LICENSE["license"], nc=_LICENSE["nc"],
                    attribution=_LICENSE["attribution"],
                    rows=rows, enabled=True)
    return rows
