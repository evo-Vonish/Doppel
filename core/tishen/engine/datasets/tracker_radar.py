"""DuckDuckGo Tracker Radar 适配器（SPEC-E §6 NC 包，Wave2 Coder B 拥有）。

CC BY-NC-SA 4.0（nc=True）——NC 可选包，受 settings.json
`packages.trackerRadar` 闸门控制（经 tishen.api.settings_io.read_settings
**只读**）：
- 未启用：跳过导入，domains 扩展列（entity/fingerprinting_score 等）
  保持原样（未导入过即恒 NULL），meta 台账写 enabled=false，返回 0；
- 启用：Tracker Radar JSON（data_dir/tracker_radar.json）→
  domains.entity / category / fingerprinting_score（0–3 评分）。

数据集格式（Tracker Radar 主干 schema 子集）：
    {"trackers": {"tracker.example": {"owner": {"name": "Example Inc"},
                                       "categories": ["Advertising"],
                                       "prevalence": 0.01,
                                       "fingerprinting": 2}}}
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from tishen.api.settings_io import read_settings

from ..trackerdb import set_source_meta
from .licenses import LICENSE_MATRIX

_FILENAME = "tracker_radar.json"
_LICENSE = LICENSE_MATRIX["tracker_radar"]

# Tracker Radar category → SPEC-E §1.1 category 枚举
_CATEGORY_MAP = {
    "advertising": "advertising",
    "analytics": "analytics",
    "audience measurement": "analytics",
    "fingerprinting": "fingerprinting",
    "cryptomining": "cryptomining",
}


def package_enabled() -> bool:
    """读 settings.json 的 packages.trackerRadar（只读；缺文件/损坏按未启用）。"""
    try:
        settings = read_settings()
    except Exception:  # 设置层任何异常一律按未启用降级（license 硬约束从严）
        return False
    packages = settings.get("packages") if isinstance(settings, dict) else None
    return bool(isinstance(packages, dict) and packages.get("trackerRadar") is True)


def _read_dataset(data_dir: str | Path) -> dict[str, dict]:
    path = Path(data_dir) / _FILENAME
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    trackers = data.get("trackers") if isinstance(data, dict) else None
    if not isinstance(trackers, dict):
        raise ValueError(f"{path} 缺少 \"trackers\" 对象（Tracker Radar schema）")
    return trackers


def _map_category(categories) -> str:
    if isinstance(categories, list):
        for cat in categories:
            mapped = _CATEGORY_MAP.get(str(cat).strip().lower())
            if mapped:
                return mapped
    return "unknown"


def _clamp_fp_score(value) -> int | None:
    """fingerprinting 0–3 评分（越界/缺失按 None，绝不脑补）。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return min(max(value, 0), 3)


def import_tracker_radar(conn: sqlite3.Connection, data_dir: str | Path) -> int:
    """导入 Tracker Radar（SPEC-E §6），返回写入的域名行数。

    NC 闸门：packages.trackerRadar 未启用时跳过导入且 meta 台账
    enabled=false、返回 0（domains 扩展列保持 NULL）。
    """
    if not package_enabled():
        set_source_meta(conn, "tracker_radar",
                        license=_LICENSE["license"], nc=True,
                        attribution=_LICENSE["attribution"],
                        rows=0, enabled=False)
        return 0

    trackers = _read_dataset(data_dir)
    rows = 0
    with conn:
        for domain, info in sorted(trackers.items()):
            if not isinstance(info, dict):
                continue
            domain = domain.lower().strip()
            if not domain:
                continue
            owner = info.get("owner")
            entity = None
            if isinstance(owner, dict):
                entity = owner.get("name") or None
            category = _map_category(info.get("categories"))
            fp_score = _clamp_fp_score(info.get("fingerprinting"))
            prevalence = info.get("prevalence")
            prevalence = float(prevalence) if prevalence is not None else None
            # NC 源优先级最高：entity/fingerprinting_score 直接覆盖，
            # source 列写 tracker_radar（其余源留痕 domain_sources）
            conn.execute(
                "INSERT INTO domains (domain, entity, category,"
                " fingerprinting_score, prevalence, is_tracking, source)"
                " VALUES (?, ?, ?, ?, ?, 1, 'tracker_radar')"
                " ON CONFLICT(domain) DO UPDATE SET"
                "   entity = COALESCE(excluded.entity, domains.entity),"
                "   category = excluded.category,"
                "   fingerprinting_score = excluded.fingerprinting_score,"
                "   prevalence = COALESCE(excluded.prevalence, domains.prevalence),"
                "   is_tracking = 1,"
                "   source = 'tracker_radar'",
                (domain, entity, category, fp_score, prevalence))
            conn.execute(
                "INSERT OR IGNORE INTO domain_sources (domain, source)"
                " VALUES (?, 'tracker_radar')", (domain,))
            rows += 1

    set_source_meta(conn, "tracker_radar",
                    license=_LICENSE["license"], nc=True,
                    attribution=_LICENSE["attribution"],
                    rows=rows, enabled=True)
    return rows
