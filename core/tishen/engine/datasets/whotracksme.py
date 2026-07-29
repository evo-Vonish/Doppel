"""WhoTracks.me 月度 trackerdb 适配器（SPEC-E §6，Wave2 Coder B 拥有；
SPEC-E2 §D3 真实月度统计扩展，Wave3 Coder D 维护）。

CC BY 4.0（nc=False），非 NC 核心路径可用。下载经 datasets.downloader，
测试以 file:// 注入本地 fixture，不真连网。

**源优先级表（SPEC-E2 §D3，高优先级已写字段不被低优先级覆盖）**：
    tracker_radar > trackerdb > whotracksme > easyprivacy
本模块属第三优先级：prevalence 恒更新（月度统计语义），entity/category
只补空（高优先级源已写字段绝不覆盖），fingerprinting_score 本源不提供
恒不动。

真实数据布局（SPEC-E2 §D3，T6 §2.2）：
- 月度聚合包 `WHOTRACKSME_DATA`（URL 常量集中文件头，便于月度源变更时
  单点修改）下载至 `<data_dir>/whotracksme/trackerdb.json`；
- tracker 条目键：`name / category / website_url / domains[] /
  prevalence`（流行度字段名以 fixture 实测为准）；解析器**对缺失键宽容
  （跳过/置空）、对类型错误严格报错**（ValueError）。

兼容：data_dir 下无 whotracksme/trackerdb.json 时回退 B 版归一化格式
`whotracksme.json`（{"domains": {domain: {...}}}），签名与行为不变。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..trackerdb import set_source_meta
from .downloader import fetch
from .licenses import LICENSE_MATRIX

# SPEC-E2 §D3：月度聚合包 URL（月度源变更时单点修改）
WHOTRACKSME_DATA = ("https://github.com/whotracks/whotracks.me/raw/main/"
                    "whotracksme/data/assets/trackerdb.json")

_FILENAME = "whotracksme.json"
_LICENSE = LICENSE_MATRIX["whotracksme"]


def download_whotracksme(data_dir: str | Path, *,
                         url: str = WHOTRACKSME_DATA) -> Path:
    """下载 whoTracks.me 月度 trackerdb.json（SPEC-E2 §D3），返回文件路径。

    经 downloader.fetch（etag 侧车/304/重试/流式语义同 D1），落盘
    `<data_dir>/whotracksme/trackerdb.json`。非 NC 源，无包闸门。
    """
    dest = Path(data_dir) / "whotracksme"
    result = fetch(url, dest)
    return result.path


def _read_dataset(data_dir: str | Path) -> dict[str, dict]:
    """B 版归一化 JSON，返回 {domain: {...}}；文件缺失抛 FileNotFoundError。"""
    path = Path(data_dir) / _FILENAME
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    domains = data.get("domains") if isinstance(data, dict) else None
    if not isinstance(domains, dict):
        raise ValueError(f"{path} 缺少 \"domains\" 对象（归一化格式见模块 docstring）")
    return domains


def _read_trackerdb(data_dir: str | Path) -> list[tuple[str, dict]]:
    """读月度 trackerdb.json，展开为 [(domain, info)]（SPEC-E2 §D3）。

    tracker 条目键 name/category/website_url/domains[]/prevalence；
    缺失键宽容（domains 缺失则该条目无贡献，name/category/prevalence 缺失
    置 None），类型错误严格报错（条目非 dict / domains 非 list /
    prevalence 非数值 → ValueError）。
    """
    path = Path(data_dir) / "whotracksme" / "trackerdb.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    trackers = data.get("trackers") if isinstance(data, dict) else None
    if not isinstance(trackers, dict):
        raise ValueError(f"{path} 缺少 \"trackers\" 对象（月度 trackerdb schema）")
    rows: list[tuple[str, dict]] = []
    for tracker_id, entry in sorted(trackers.items()):
        if not isinstance(entry, dict):
            raise ValueError(f"{path} 条目 {tracker_id!r} 非对象（类型错误从严）")
        domains = entry.get("domains")
        if domains is None:
            continue  # 缺失键宽容：该 tracker 无域名贡献
        if not isinstance(domains, list):
            raise ValueError(
                f"{path} 条目 {tracker_id!r} 的 domains 非列表（类型错误从严）")
        prevalence = entry.get("prevalence")
        if prevalence is not None and (
                isinstance(prevalence, bool)
                or not isinstance(prevalence, (int, float))):
            raise ValueError(
                f"{path} 条目 {tracker_id!r} 的 prevalence 非数值（类型错误从严）")
        name = entry.get("name")
        category = entry.get("category")
        info = {
            "entity": name if isinstance(name, str) and name.strip() else None,
            "category": (category.strip().lower()
                         if isinstance(category, str) and category.strip()
                         else None),
            "prevalence": float(prevalence) if prevalence is not None else None,
        }
        for domain in domains:
            if isinstance(domain, str) and domain.strip():
                rows.append((domain.lower().strip(), info))
    return rows


def _upsert_domain(conn: sqlite3.Connection, domain: str, *,
                   entity: str | None, category: str | None,
                   prevalence: float | None) -> None:
    """单行 upsert：prevalence 恒更新；entity/category 只补空；
    source 列只在无高优先级源（tracker_radar/trackerdb）占用时写
    "whotracksme"（优先级表见模块 docstring，SPEC-E2 §D3）。"""
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


def import_whotracksme(conn: sqlite3.Connection, data_dir: str | Path) -> int:
    """导入 whoTracks.me 数据集（SPEC-E §6 / SPEC-E2 §D3），返回域名行数。

    月度布局（whotracksme/trackerdb.json 存在时）：tracker 条目展开为
    域名行；否则回退 B 版 whotracksme.json 归一化格式（行为不变）。

    prevalence 恒更新；entity/category 只补空（高优先级源已写字段不被
    覆盖，优先级表见模块 docstring）；多源命中留痕 domain_sources；
    最后写 meta 台账 source:whotracksme。
    """
    if (Path(data_dir) / "whotracksme" / "trackerdb.json").is_file():
        items = _read_trackerdb(data_dir)
    else:
        items = sorted(_read_dataset(data_dir).items())

    rows = 0
    with conn:
        for domain, info in items:
            if not isinstance(info, dict):
                continue
            domain = domain.lower().strip()
            if not domain:
                continue
            prevalence = info.get("prevalence")
            prevalence = float(prevalence) if prevalence is not None else None
            entity = info.get("entity") or None
            category = info.get("category") or None
            _upsert_domain(conn, domain, entity=entity, category=category,
                           prevalence=prevalence)
            rows += 1

    set_source_meta(conn, "whotracksme",
                    license=_LICENSE["license"], nc=_LICENSE["nc"],
                    attribution=_LICENSE["attribution"],
                    rows=rows, enabled=True)
    return rows
