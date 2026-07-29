"""数据源 license 矩阵与 NOTICE 汇总（SPEC-E §6，Wave2 Coder B 拥有）。

LICENSE_MATRIX 每源 {license, nc, attribution, url}：
- 核心路径只依赖非 NC 源（easyprivacy / whotracksme）；
- Tracker Radar / TrackerDB 为 NC 可选包，未启用不得进入核心判定
  （扩展列恒空、代码自动降级，SPEC-E §0）。

generate_notice(conn) 汇总 trackerdb.db meta 台账中已导入源的
NOTICE 片段，供镜像/发行物附带署名。
"""

from __future__ import annotations

import json
import sqlite3

# SPEC-E §6：license 矩阵常量（每源 license/nc/attribution/url）
LICENSE_MATRIX: dict[str, dict] = {
    "easyprivacy": {
        "license": "GPLv3+/CC BY-SA 3.0+",
        "nc": False,
        "attribution": "EasyPrivacy by EasyList authors (https://easylist.to/)",
        "url": "https://easylist.to/easylist/easyprivacy.txt",
    },
    "whotracksme": {
        "license": "CC BY 4.0",
        "nc": False,
        "attribution": "WhoTracks.me Tracker Database by Ghostery (CC BY 4.0)",
        "url": "https://whotracks.me/",
    },
    "tracker_radar": {
        "license": "CC BY-NC-SA 4.0",
        "nc": True,
        "attribution": "DuckDuckGo Tracker Radar (CC BY-NC-SA 4.0)",
        "url": "https://github.com/duckduckgo/tracker-radar",
    },
    "trackerdb": {
        "license": "CC BY-NC-SA 4.0",
        "nc": True,
        "attribution": "Ghostery Tracker Database (CC BY-NC-SA 4.0)",
        "url": "https://github.com/ghostery/trackerdb",
    },
}


def generate_notice(conn: sqlite3.Connection) -> str:
    """汇总已导入源的 NOTICE 片段（SPEC-E §6）。

    遍历 meta 台账 source:<name>，按 LICENSE_MATRIX 输出每源
    license / attribution / url / nc 标记与导入行数；未导入的源不出
    现。台账中 license/attribution 以导入时落库值为准（矩阵值兜底）。
    """
    cur = conn.execute(
        "SELECT key, value FROM meta WHERE key LIKE 'source:%' ORDER BY key")
    blocks: list[str] = ["Tishen Engine Data Sources NOTICE", "=" * 40, ""]
    for key, value in cur.fetchall():
        name = key.split(":", 1)[1]
        matrix = LICENSE_MATRIX.get(name, {})
        try:
            entry = json.loads(value)
        except json.JSONDecodeError:
            entry = {}
        license_name = entry.get("license") or matrix.get("license") or "unknown"
        attribution = entry.get("attribution") or matrix.get("attribution") or name
        nc = matrix.get("nc", bool(entry.get("nc", False)))
        url = matrix.get("url", "")
        rows = entry.get("rows", 0)
        enabled = bool(entry.get("enabled", False))
        blocks.append(f"Source: {name}")
        blocks.append(f"  License: {license_name}" + (" [NC 非商业限制]" if nc else ""))
        blocks.append(f"  Attribution: {attribution}")
        if url:
            blocks.append(f"  URL: {url}")
        blocks.append(f"  Imported rows: {rows}; enabled: {enabled}")
        blocks.append("")
    return "\n".join(blocks).rstrip() + "\n"
