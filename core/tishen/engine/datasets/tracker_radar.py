"""DuckDuckGo Tracker Radar 适配器（SPEC-E §6 NC 包，Wave2 Coder B 拥有；
SPEC-E2 §D2 真实全量下载扩展，Wave3 Coder D 维护）。

CC BY-NC-SA 4.0（nc=True）——NC 可选包，受 settings.json
`packages.trackerRadar` 闸门控制（经 tishen.api.settings_io.read_settings
**只读**）：
- 未启用：download/import 均跳过，domains 扩展列（entity/
  fingerprinting_score 等）保持原样（未导入过即恒 NULL），meta 台账写
  enabled=false，返回 0；
- 启用：codeload tar.gz 全量归档 → 流式解压 domains/ + entities/ →
  全量 schema 映射入库。

真实数据布局（T6 研究报告 §2.1 实测）：
- 归档 `https://codeload.github.com/duckduckgo/tracker-radar/tar.gz/refs/heads/main`
  内为 `<repo>-<ref>/domains/**.json`（约 5 万，按区域分目录）与
  `<repo>-<ref>/entities/*.json`（约 1.9 万）；
- domain JSON 键：`domain / owner.name / displayName / categories[] /
  prevalence / fingerprinting(0–3) / cookies / subdomains[]`；
- entities JSON 键：`name / properties[] / prevalence`。

全量 schema 映射（SPEC-E2 §D2）：
- entity=owner.name；category=categories[0] 小写归一（多分类时首选映射后
  非 "unknown" 者）；fingerprinting_score=fingerprinting（0–3 clamp）；
- prevalence=prevalence；is_tracking=1 当 categories 含
  advertising/analytics/social 之一或 fingerprinting≥1；
- entities 的 properties[] 全部并入 domains（同实体多域名归并）。

兼容：data_dir 下无 tracker_radar/domains/ 时回退 B 版归一化子集
`tracker_radar.json`（{"trackers": {...}}），签名与行为不变。
"""

from __future__ import annotations

import json
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from tishen.api.settings_io import read_settings

from ..trackerdb import set_source_meta
from .downloader import fetch
from .licenses import LICENSE_MATRIX

# SPEC-E2 §D2：codeload tar.gz 全量归档（~百 MB 级）
TRACKER_RADAR_ARCHIVE = (
    "https://codeload.github.com/duckduckgo/tracker-radar/tar.gz/refs/heads/main")

_FILENAME = "tracker_radar.json"
_LICENSE = LICENSE_MATRIX["tracker_radar"]

# Tracker Radar category → SPEC-E §1.1 category 枚举（小写归一）
_CATEGORY_MAP = {
    "advertising": "advertising",
    "ad motivated tracking": "advertising",
    "analytics": "analytics",
    "audience measurement": "analytics",
    "session replay": "analytics",
    "fingerprinting": "fingerprinting",
    "cryptomining": "cryptomining",
}

# is_tracking=1 的原始类别判定词表（SPEC-E2 §D2：advertising/analytics/social）
_TRACKING_CATEGORIES = {
    "advertising", "ad motivated tracking",
    "analytics", "audience measurement",
    "social", "social networking",
}


def package_enabled() -> bool:
    """读 settings.json 的 packages.trackerRadar（只读；缺文件/损坏按未启用）。"""
    try:
        settings = read_settings()
    except Exception:  # 设置层任何异常一律按未启用降级（license 硬约束从严）
        return False
    packages = settings.get("packages") if isinstance(settings, dict) else None
    return bool(isinstance(packages, dict) and packages.get("trackerRadar") is True)


def download_tracker_radar(data_dir: str | Path, *,
                           url: str = TRACKER_RADAR_ARCHIVE) -> Path:
    """下载 Tracker Radar 全量归档并流式解压（SPEC-E2 §D2），返回根目录。

    经 downloader.fetch 拉 tar.gz → tarfile 流式遍历，仅提取
    `domains/**.json` 与 `entities/**.json`（剥去顶层仓库目录）到
    `<data_dir>/tracker_radar/{domains,entities}/`；成员名含 `..` 或绝对
    路径的一律拒绝（路径穿越防护），不创建任何归档外文件。

    NC 闸：packages.trackerRadar 未启用时跳过下载，直接返回根目录路径
    （目录不存在），meta 台账由 import 侧写 enabled=false（台账语义与
    B 版一致，download 侧无 conn 不碰库）。
    """
    root = Path(data_dir) / "tracker_radar"
    if not package_enabled():
        return root  # NC 闸：跳过下载

    with tempfile.TemporaryDirectory(prefix="tishen-tr-") as tmp:
        result = fetch(url, Path(tmp))
        _extract_archive(result.path, root)
    return root


def _extract_archive(archive: Path, root: Path) -> None:
    """流式解压 tar.gz，仅提取 domains/ 与 entities/ 下的 .json 成员。

    路径穿越防护：成员名含 `..` 分量或为绝对路径 → ValueError 拒绝
    整个归档（宁可不导，不写归档外路径）。
    """
    extracted = 0
    with tarfile.open(archive, mode="r|gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if not parts or parts[0] == "/" or ".." in parts:
                raise ValueError(
                    f"拒绝含路径穿越的 tar 成员：{member.name!r}")
            # 剥去顶层仓库目录（<repo>-<ref>/...）
            rel = parts[1:] if len(parts) > 1 else ()
            if len(rel) < 2 or rel[0] not in ("domains", "entities"):
                continue
            if rel[-1].endswith(".json") is False:
                continue
            src = tar.extractfile(member)
            if src is None:
                continue
            target = root.joinpath(*rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with src, target.open("wb") as f:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            extracted += 1
    if extracted == 0:
        raise ValueError(f"{archive} 中未找到 domains/ 或 entities/ JSON 成员")


def _read_dataset(data_dir: str | Path) -> dict[str, dict]:
    """B 版归一化子集（data_dir/tracker_radar.json {"trackers": {...}}）。"""
    path = Path(data_dir) / _FILENAME
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    trackers = data.get("trackers") if isinstance(data, dict) else None
    if not isinstance(trackers, dict):
        raise ValueError(f"{path} 缺少 \"trackers\" 对象（Tracker Radar schema）")
    return trackers


def _read_full_dataset(data_dir: str | Path) -> tuple[dict[str, dict], list[dict]]:
    """读全量布局 tracker_radar/{domains,entities}/（SPEC-E2 §D2）。

    返回 ({domain: info}, [entity_info])；domains/ 递归遍历（区域子目录），
    entities/ 只取顶层 *.json。坏 JSON 文件抛 ValueError（从严，不静默）。
    """
    root = Path(data_dir) / "tracker_radar"
    domains: dict[str, dict] = {}
    domains_dir = root / "domains"
    if domains_dir.is_dir():
        for path in sorted(domains_dir.rglob("*.json")):
            info = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(info, dict):
                continue
            domain = info.get("domain") or path.stem
            if isinstance(domain, str) and domain.strip():
                domains[domain.lower().strip()] = info
    entities: list[dict] = []
    entities_dir = root / "entities"
    if entities_dir.is_dir():
        for path in sorted(entities_dir.glob("*.json")):
            info = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(info, dict):
                entities.append(info)
    return domains, entities


def _map_category(categories) -> str:
    """categories[0] 小写归一；多分类时首选映射后非 "unknown" 者（§D2）。"""
    if isinstance(categories, list):
        for cat in categories:
            mapped = _CATEGORY_MAP.get(str(cat).strip().lower())
            if mapped:
                return mapped
    return "unknown"


def _is_tracking(categories, fp_score: int | None) -> int:
    """is_tracking=1 当 categories 含 advertising/analytics/social 之一
    或 fingerprinting≥1（SPEC-E2 §D2）。"""
    if isinstance(categories, list):
        lowered = {str(c).strip().lower() for c in categories}
        if lowered & _TRACKING_CATEGORIES:
            return 1
    return 1 if (fp_score or 0) >= 1 else 0


def _clamp_fp_score(value) -> int | None:
    """fingerprinting 0–3 评分（越界/缺失按 None，绝不脑补）。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return min(max(value, 0), 3)


def _owner_name(info: dict) -> str | None:
    owner = info.get("owner")
    if isinstance(owner, dict):
        return owner.get("name") or None
    return None


def _insert_domain(conn: sqlite3.Connection, domain: str, *,
                   entity: str | None, category: str,
                   fp_score: int | None, prevalence: float | None,
                   is_tracking: int) -> None:
    """单行 upsert（NC 源优先级最高：entity/fp 覆盖，source=tracker_radar）。"""
    conn.execute(
        "INSERT INTO domains (domain, entity, category,"
        " fingerprinting_score, prevalence, is_tracking, source)"
        " VALUES (?, ?, ?, ?, ?, ?, 'tracker_radar')"
        " ON CONFLICT(domain) DO UPDATE SET"
        "   entity = COALESCE(excluded.entity, domains.entity),"
        "   category = excluded.category,"
        "   fingerprinting_score = excluded.fingerprinting_score,"
        "   prevalence = COALESCE(excluded.prevalence, domains.prevalence),"
        "   is_tracking = excluded.is_tracking,"
        "   source = 'tracker_radar'",
        (domain, entity, category, fp_score, prevalence, is_tracking))
    conn.execute(
        "INSERT OR IGNORE INTO domain_sources (domain, source)"
        " VALUES (?, 'tracker_radar')", (domain,))


def import_tracker_radar(conn: sqlite3.Connection, data_dir: str | Path) -> int:
    """导入 Tracker Radar（SPEC-E §6 / SPEC-E2 §D2），返回写入的域名行数。

    全量布局（tracker_radar/domains/ 存在时）：domain JSON 全字段映射 +
    entities properties[] 并入；否则回退 B 版 tracker_radar.json 归一化
    子集（行为不变）。

    NC 闸门：packages.trackerRadar 未启用时跳过导入且 meta 台账
    enabled=false、返回 0（domains 扩展列保持 NULL）。
    """
    if not package_enabled():
        set_source_meta(conn, "tracker_radar",
                        license=_LICENSE["license"], nc=True,
                        attribution=_LICENSE["attribution"],
                        rows=0, enabled=False)
        return 0

    root = Path(data_dir) / "tracker_radar"
    if (root / "domains").is_dir():
        rows = _import_full(conn, root)
    else:
        rows = _import_legacy(conn, data_dir)

    set_source_meta(conn, "tracker_radar",
                    license=_LICENSE["license"], nc=True,
                    attribution=_LICENSE["attribution"],
                    rows=rows, enabled=True)
    return rows


def _import_legacy(conn: sqlite3.Connection, data_dir: str | Path) -> int:
    """B 版归一化子集导入（tracker_radar.json），签名与行为不变。"""
    trackers = _read_dataset(data_dir)
    rows = 0
    with conn:
        for domain, info in sorted(trackers.items()):
            if not isinstance(info, dict):
                continue
            domain = domain.lower().strip()
            if not domain:
                continue
            entity = _owner_name(info)
            category = _map_category(info.get("categories"))
            fp_score = _clamp_fp_score(info.get("fingerprinting"))
            prevalence = info.get("prevalence")
            prevalence = float(prevalence) if prevalence is not None else None
            is_tracking = _is_tracking(info.get("categories"), fp_score)
            _insert_domain(conn, domain, entity=entity, category=category,
                           fp_score=fp_score, prevalence=prevalence,
                           is_tracking=is_tracking)
            rows += 1
    return rows


def _import_full(conn: sqlite3.Connection, root: Path) -> int:
    """全量 schema 映射导入（SPEC-E2 §D2）：domains/ + entities/ 并入。"""
    domains, entities = _read_full_dataset(root.parent)
    rows = 0
    with conn:
        for domain, info in sorted(domains.items()):
            entity = _owner_name(info)
            category = _map_category(info.get("categories"))
            fp_score = _clamp_fp_score(info.get("fingerprinting"))
            prevalence = info.get("prevalence")
            prevalence = float(prevalence) if prevalence is not None else None
            is_tracking = _is_tracking(info.get("categories"), fp_score)
            _insert_domain(conn, domain, entity=entity, category=category,
                           fp_score=fp_score, prevalence=prevalence,
                           is_tracking=is_tracking)
            rows += 1
        # entities 的 properties[] 全部并入 domains（同实体多域名归并）；
        # 域名已在 domains/ 中出现的保留其自身字段，不覆盖。
        for entity_info in entities:
            name = entity_info.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            name = name.strip()
            prevalence = entity_info.get("prevalence")
            prevalence = float(prevalence) if prevalence is not None else None
            properties = entity_info.get("properties")
            if not isinstance(properties, list):
                continue
            for prop in properties:
                if not isinstance(prop, str):
                    continue
                domain = prop.lower().strip()
                if not domain or domain in domains:
                    continue
                _insert_domain(conn, domain, entity=name, category="unknown",
                               fp_score=None, prevalence=prevalence,
                               is_tracking=0)
                rows += 1
    return rows
