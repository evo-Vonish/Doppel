"""Ghostery TrackerDB（.eno）适配器（SPEC-E §6 NC 包，Wave2 Coder B 拥有）。

CC BY-NC-SA 4.0（nc=True）——NC 可选包，受 settings.json
`packages.trackerDb` 闸门控制（read_settings 只读）：
- 未启用：跳过导入，meta 台账 enabled=false，返回 0；
- 启用：解析 ghostery/trackerdb 的 .eno 清单 → 服务级 category 补充
  进 domains + filters 转 ABP 子集经 rules.import_rules(source="trackerdb")
  导入（超出 §2.1 语法子集者由 parse_abp_lines 跳过计数，不报错）。

.eno 清单格式（缩进块；反引号为 eno 转义，导入前剥除）：

    name: DoubleClick
    category: advertising
    domains:
    - doubleclick.net
    filters:
    - `||doubleclick.net^$third-party`

data_dir 下接受单个 patterns.eno，或任意多个 *.eno 文件合并解析。
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from tishen.api.settings_io import read_settings

from ..rules import ParseStats, import_rules, parse_abp_lines
from ..trackerdb import set_source_meta
from .licenses import LICENSE_MATRIX

_LICENSE = LICENSE_MATRIX["trackerdb"]

# ghostery category → SPEC-E §1.1 category 枚举
_CATEGORY_MAP = {
    "advertising": "advertising",
    "site_analytics": "analytics",
    "analytics": "analytics",
    "fingerprinting": "fingerprinting",
    "cryptomining": "cryptomining",
}


@dataclass
class _Entry:
    """一个 .eno 服务条目（name/category/domains/filters）。"""

    name: str | None = None
    category: str | None = None
    domains: list[str] = field(default_factory=list)
    filters: list[str] = field(default_factory=list)


def package_enabled() -> bool:
    """读 settings.json 的 packages.trackerDb（只读；异常按未启用从严降级）。"""
    try:
        settings = read_settings()
    except Exception:
        return False
    packages = settings.get("packages") if isinstance(settings, dict) else None
    return bool(isinstance(packages, dict) and packages.get("trackerDb") is True)


def _strip_eno_quote(text: str) -> str:
    """剥除 eno 反引号/引号转义。"""
    text = text.strip()
    if len(text) >= 2 and text[0] == "`" and text.endswith("`"):
        return text[1:-1]
    return text


def parse_eno_lines(lines) -> list[_Entry]:
    """解析 .eno 行流为服务条目列表。

    只识别顶格 `name:` / `category:` / `domains:` / `filters:` 与
    `- item` 列表项；其余行一律忽略（eno 全语法不在本子集内，跳过
    不报错，与 SPEC-E §2.1 "不假装支持" 同纪律）。
    """
    entries: list[_Entry] = []
    current: _Entry | None = None
    section: str | None = None  # "domains" / "filters"

    def _flush() -> None:
        nonlocal current
        if current is not None and (current.domains or current.filters):
            entries.append(current)
        current = None

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped:
            continue
        indented = line[0] in (" ", "\t")
        if not indented and stripped.startswith("name:"):
            _flush()
            current = _Entry(name=_strip_eno_quote(stripped[len("name:"):]) or None)
            section = None
            continue
        if current is None:
            continue
        if not indented and stripped.startswith("category:"):
            current.category = _strip_eno_quote(
                stripped[len("category:"):]).lower() or None
            section = None
        elif not indented and stripped.rstrip() == "domains:":
            section = "domains"
        elif not indented and stripped.rstrip() == "filters:":
            section = "filters"
        elif stripped.startswith("-") and section:
            item = _strip_eno_quote(stripped[1:])
            if item:
                getattr(current, section).append(item)
        # 其余行（未知字段/嵌套块）忽略
    _flush()
    return entries


def _find_eno_files(data_dir: str | Path) -> list[Path]:
    """data_dir 下的 .eno 清单集合（patterns.eno 优先，其余 *.eno 合并）。"""
    base = Path(data_dir)
    single = base / "patterns.eno"
    if single.is_file():
        return [single]
    files = sorted(base.glob("*.eno"))
    if not files:
        raise FileNotFoundError(f"{base} 下无 patterns.eno 或任何 *.eno 清单")
    return files


def import_trackerdb_src(conn: sqlite3.Connection, data_dir: str | Path) -> int:
    """导入 ghostery/trackerdb（SPEC-E §6），返回写入 domains 的域名行数。

    NC 闸门：packages.trackerDb 未启用时跳过导入且 meta 台账
    enabled=false、返回 0（不写 domains、不动 rules 表）。
    """
    if not package_enabled():
        set_source_meta(conn, "trackerdb",
                        license=_LICENSE["license"], nc=True,
                        attribution=_LICENSE["attribution"],
                        rows=0, enabled=False)
        return 0

    entries: list[_Entry] = []
    for path in _find_eno_files(data_dir):
        entries.extend(parse_eno_lines(
            path.read_text(encoding="utf-8", errors="replace").splitlines()))

    # filters 转 ABP 子集 → import_rules(source="trackerdb")（幂等重导）
    all_filters = [f for e in entries for f in e.filters]
    rules, _stats = parse_abp_lines(all_filters, source="trackerdb")
    import_rules(conn, rules, source="trackerdb")

    rows = 0
    with conn:
        for entry in entries:
            category = _CATEGORY_MAP.get(entry.category or "", "unknown")
            for domain in sorted(set(entry.domains)):
                domain = domain.lower().strip()
                if not domain or "." not in domain:
                    continue
                # 服务级 category 补充：仅当现状为 NULL/unknown 时生效；
                # entity 不由本源提供（tracker_radar 优先）；source 列
                # 仅在无 tracker_radar 占用时写 trackerdb
                conn.execute(
                    "INSERT INTO domains (domain, entity, category,"
                    " fingerprinting_score, prevalence, is_tracking, source)"
                    " VALUES (?, NULL, ?, NULL, NULL, 1, 'trackerdb')"
                    " ON CONFLICT(domain) DO UPDATE SET"
                    "   is_tracking = 1,"
                    "   category = CASE WHEN domains.category IS NULL"
                    "                   OR domains.category = 'unknown'"
                    "              THEN excluded.category"
                    "              ELSE domains.category END,"
                    "   source = CASE WHEN domains.source = 'tracker_radar'"
                    "              THEN domains.source ELSE 'trackerdb' END",
                    (domain, category))
                conn.execute(
                    "INSERT OR IGNORE INTO domain_sources (domain, source)"
                    " VALUES (?, 'trackerdb')", (domain,))
                rows += 1

    set_source_meta(conn, "trackerdb",
                    license=_LICENSE["license"], nc=True,
                    attribution=_LICENSE["attribution"],
                    rows=rows, enabled=True)
    return rows


__all__ = ["import_trackerdb_src", "parse_eno_lines", "package_enabled",
           "ParseStats"]
