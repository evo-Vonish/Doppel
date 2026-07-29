"""E1 实体归因（SPEC-E §5，Wave2 Coder B 拥有）。

域名 → 实体/类别/指纹分查询，底表为 trackerdb.db 的 domains /
domain_sources（SPEC-E §1.1）。要点：
- 精确匹配失败时逐级回退父域（a.b.c.com → b.c.com → c.com）；
- 全未命中返回空 EntityHit（is_tracking=False）；
- fingerprinting_score 仅 NC 包（Tracker Radar）提供：NC 未启用
  （meta 台账 source:tracker_radar enabled=false 或从未导入）时
  本模块一律视为 None，is_fp_invasive 恒 False（降级纯行为路径，
  SPEC-E §0 license 硬约束）；
- first_party_related：page_host 与 target 同实体（非 None）时豁免。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field


@dataclass
class EntityHit:
    """SPEC-E §5：一次实体归因结果。"""

    host: str
    entity: str | None
    category: str | None
    fingerprinting_score: int | None    # NC 未启用恒 None
    is_tracking: bool
    is_fp_invasive: bool                # is_tracking ∧ (fingerprinting_score>=2)
    first_party_related: bool           # 与 page_host 同实体（Mozilla entitylist 豁免）
    sources: list[str] = field(default_factory=list)


def _empty_hit(host: str) -> EntityHit:
    """全未命中的空 Hit（SPEC-E §5：is_tracking=False）。"""
    return EntityHit(host=host, entity=None, category=None,
                     fingerprinting_score=None, is_tracking=False,
                     is_fp_invasive=False, first_party_related=False,
                     sources=[])


def _parent_domains(host: str) -> list[str]:
    """父域回退链：a.b.c.com → [a.b.c.com, b.c.com, c.com]（SPEC-E §5）。"""
    labels = host.lower().rstrip(".").split(".")
    # 至少保留两段（注册域名精度不做 eTLD，与 rules.registered_domain 同口径）
    return [".".join(labels[i:]) for i in range(0, max(len(labels) - 1, 1))]


def _lookup(conn: sqlite3.Connection, host: str) -> tuple[dict, str] | None:
    """逐级回退查 domains 表；命中返回 (行 dict, 实际命中的域名)。"""
    for candidate in _parent_domains(host):
        cur = conn.execute(
            "SELECT domain, entity, category, fingerprinting_score,"
            " prevalence, is_tracking, source FROM domains WHERE domain = ?",
            (candidate,))
        row = cur.fetchone()
        if row is not None:
            cols = ("domain", "entity", "category", "fingerprinting_score",
                    "prevalence", "is_tracking", "source")
            return dict(zip(cols, row)), candidate
    return None


def _sources_of(conn: sqlite3.Connection, domain: str, primary: str) -> list[str]:
    """多源命中留痕（domain_sources），primary 兜底在列（SPEC-E §1.1）。"""
    cur = conn.execute(
        "SELECT source FROM domain_sources WHERE domain = ? ORDER BY source",
        (domain,))
    sources = [r[0] for r in cur.fetchall()]
    if primary and primary not in sources:
        sources.append(primary)
        sources.sort()
    return sources


def _nc_fingerprinting_enabled(conn: sqlite3.Connection) -> bool:
    """NC 包（Tracker Radar）是否启用：meta 台账 enabled=true 才算（§0/§6）。

    未启用（从未导入或 enabled=false）时 fingerprinting_score 一律按 None
    处理——即便库里残留历史值也不得参与 is_fp_invasive 判定。
    """
    cur = conn.execute(
        "SELECT value FROM meta WHERE key = 'source:tracker_radar'")
    row = cur.fetchone()
    if row is None:
        return False
    try:
        entry = json.loads(row[0])
    except json.JSONDecodeError:
        return False
    return bool(entry.get("enabled"))


def attribute(conn: sqlite3.Connection, host: str,
              page_host: str | None = None) -> EntityHit:
    """域名 → 实体归因（SPEC-E §5）。

    conn 为 trackerdb.db 连接；host 精确匹配失败时逐级回退父域；
    全未命中返回空 Hit。page_host 给出时判定 first_party_related
    （同实体且实体名非 None 才豁免——无实体信息不得乱豁免）。
    """
    if not host:
        return _empty_hit(host)
    host = host.lower().rstrip(".")

    found = _lookup(conn, host)
    if found is None:
        return _empty_hit(host)
    row, matched_domain = found

    is_tracking = bool(row["is_tracking"])
    # NC 闸：未启用时 fingerprinting_score 恒 None（is_fp_invasive 恒 False）
    fp_score: int | None = None
    if _nc_fingerprinting_enabled(conn) and row["fingerprinting_score"] is not None:
        fp_score = int(row["fingerprinting_score"])
    is_fp_invasive = is_tracking and fp_score is not None and fp_score >= 2

    first_party_related = False
    if page_host and row["entity"]:
        page_found = _lookup(conn, page_host.lower().rstrip("."))
        if page_found is not None and page_found[0]["entity"] == row["entity"]:
            first_party_related = True

    return EntityHit(
        host=host,
        entity=row["entity"],
        category=row["category"],
        fingerprinting_score=fp_score,
        is_tracking=is_tracking,
        is_fp_invasive=is_fp_invasive,
        first_party_related=first_party_related,
        sources=_sources_of(conn, matched_domain, row["source"]),
    )
