"""EasyPrivacy 适配器（SPEC-E §3，Coder A 拥有）。

非 NC 核心数据源：下载 easyprivacy.txt → parse_abp_lines →
import_rules(source="easyprivacy") → meta 台账 → domains 粗标注聚合
（category="unknown"、is_tracking=1、source="easyprivacy"，供 E1 非 NC 路径）。
"""

from __future__ import annotations

import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

from ..rules import ParseStats, import_rules, parse_abp_lines
from ..trackerdb import set_source_meta

EASYPRIVACY_URL = "https://easylist.to/easylist/easyprivacy.txt"

# SPEC-E §3 license 常量（非 NC，核心路径可用）
LICENSE = {"name": "GPLv3+/CC BY-SA 3.0+", "nc": False,
           "attribution": "EasyPrivacy by EasyList authors (https://easylist.to/)"}

_FILENAME = "easyprivacy.txt"


def download(dest_dir: str | Path, *, url: str = EASYPRIVACY_URL,
             etag_cache: bool = True) -> Path:
    """下载 easyprivacy.txt 到 dest_dir，返回文件路径（SPEC-E §3）。

    etag_cache=True 时：已存 .etag 文件则带 If-None-Match 请求，304 直接
    返回既有文件；200 落盘并更新 .etag。网络失败抛 RuntimeError（调用方
    决定降级）。测试用本地 fixture 文件以 file:// URL 注入，不真连网。
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / _FILENAME
    etag_file = dest / (_FILENAME + ".etag")

    # easylist.to 拒绝 urllib 默认 UA，带浏览器 UA 避免 403
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0 (tishen-engine)"}
    if etag_cache and etag_file.exists() and target.exists():
        headers["If-None-Match"] = etag_file.read_text(encoding="utf-8").strip()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            etag = resp.headers.get("ETag")
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and etag_cache and target.exists():
            return target  # 未变更：直接用既有文件
        raise RuntimeError(f"EasyPrivacy 下载失败（HTTP {exc.code}）：{url}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"EasyPrivacy 下载失败：{url}（{exc}）") from exc

    target.write_bytes(body)
    if etag_cache and etag:
        etag_file.write_text(etag, encoding="utf-8")
    return target


def import_easyprivacy(conn: sqlite3.Connection, text_path: str | Path) -> ParseStats:
    """解析 easyprivacy.txt 并入库（SPEC-E §3）。

    流程：parse_abp_lines → import_rules(source="easyprivacy") → 写 meta
    台账（source:easyprivacy）→ domains 粗标注聚合（命中规则的锚定 host，
    category="unknown"、is_tracking=1、source="easyprivacy"，并留痕
    domain_sources）。返回解析计数 ParseStats。
    """
    path = Path(text_path)
    text = path.read_text(encoding="utf-8", errors="replace")
    rules, stats = parse_abp_lines(text.splitlines(), source="easyprivacy")
    import_rules(conn, rules, source="easyprivacy")

    hosts = sorted({r.host for r in rules if r.host})
    with conn:
        conn.executemany(
            "INSERT INTO domains (domain, entity, category,"
            " fingerprinting_score, prevalence, is_tracking, source)"
            " VALUES (?, NULL, 'unknown', NULL, NULL, 1, 'easyprivacy')"
            " ON CONFLICT(domain) DO UPDATE SET"
            "   is_tracking = 1,"
            "   category = COALESCE(domains.category, 'unknown')",
            [(h,) for h in hosts])
        conn.executemany(
            "INSERT OR IGNORE INTO domain_sources (domain, source)"
            " VALUES (?, 'easyprivacy')",
            [(h,) for h in hosts])

    set_source_meta(conn, "easyprivacy",
                    license=LICENSE["name"], nc=LICENSE["nc"],
                    attribution=LICENSE["attribution"],
                    rows=len(rules), enabled=True)
    return stats
