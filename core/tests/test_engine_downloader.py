"""真实全量下载器测试（SPEC-E2 §D1–D4，Wave3 Coder D 拥有）。

fixture 为真实结构小样本：tracker_radar 3 域名 + 2 实体 JSON、伪造
tar.gz（含 `..` 路径穿越成员必须拒绝）、whotracksme 月度 trackerdb
5 条目。**不真连网**：file:// 注入 + monkeypatch urlopen 伪造
etag/304/重试场景。
"""

from __future__ import annotations

import io
import json
import tarfile
import urllib.error
import urllib.request

import pytest

from tishen.engine import trackerdb
from tishen.engine.datasets import downloader, tracker_radar, whotracksme


@pytest.fixture()
def conn(tmp_path):
    c = trackerdb.connect(tmp_path / "trackerdb.db")
    yield c
    c.close()


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """隔离的 $TISHEN_HOME（settings.json 闸门）。"""
    monkeypatch.setenv("TISHEN_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def _write_settings(home, **packages):
    home.mkdir(parents=True, exist_ok=True)
    (home / "settings.json").write_text(json.dumps({
        "mode": "default",
        "packages": {"easyPrivacy": True,
                     "trackerRadar": packages.get("trackerRadar", False),
                     "trackerDb": packages.get("trackerDb", False)},
        "retainDays": 14,
    }), encoding="utf-8")


class _FakeResponse:
    """伪造 urlopen 响应（上下文管理器 + headers + read）。"""

    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self._buf = io.BytesIO(body)
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---- fixture：真实结构小样本 -------------------------------------------------


def _tr_full_fixture(root):
    """tracker_radar 全量布局：3 域名 + 2 实体（T6 §2.1 真实 schema）。"""
    domains = root / "tracker_radar" / "domains" / "US"
    domains.mkdir(parents=True)
    (domains / "doubleclick.example.json").write_text(json.dumps({
        "domain": "doubleclick.example",
        "owner": {"name": "Google LLC", "displayName": "Google"},
        "categories": ["Advertising"],
        "prevalence": 0.446,
        "fingerprinting": 2,
        "cookies": 0.9,
        "subdomains": ["ad", "stats"],
    }), encoding="utf-8")
    (domains / "cdn.example.json").write_text(json.dumps({
        "domain": "cdn.example",
        "owner": {"name": "CDN Co"},
        "categories": ["CDN"],
        "prevalence": 0.01,
        "fingerprinting": 0,
    }), encoding="utf-8")
    (domains / "social.example.json").write_text(json.dumps({
        "domain": "social.example",
        "categories": ["Unknown High Risk Behavior", "Social Networking"],
        "fingerprinting": 0,
    }), encoding="utf-8")
    entities = root / "tracker_radar" / "entities"
    entities.mkdir(parents=True)
    (entities / "Google LLC.json").write_text(json.dumps({
        "name": "Google LLC",
        "properties": ["doubleclick.example", "google-syndication.example"],
        "prevalence": 0.5,
    }), encoding="utf-8")
    (entities / "Empty Co.json").write_text(json.dumps({
        "name": "Empty Co", "properties": [], "prevalence": 0.001,
    }), encoding="utf-8")
    return root


def _tr_archive_fixture(tmp_path, *, evil: bool = False):
    """伪造 codeload tar.gz（顶层 <repo>-<ref>/ 目录 + 区域子目录）。"""
    src = tmp_path / "src"
    _tr_full_fixture(src / "inner")
    archive = tmp_path / ("evil.tar.gz" if evil else "tracker-radar.tar.gz")

    def _add_json(tar, arcname, payload):
        data = json.dumps(payload).encode("utf-8")
        info = tarfile.TarInfo(arcname)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    prefix = "tracker-radar-main"
    with tarfile.open(archive, "w:gz") as tar:
        _add_json(tar, f"{prefix}/domains/US/a.example.json", {
            "domain": "a.example", "owner": {"name": "ACo"},
            "categories": ["Analytics"], "prevalence": 0.02,
            "fingerprinting": 1})
        _add_json(tar, f"{prefix}/entities/ACo.json", {
            "name": "ACo", "properties": ["a.example"], "prevalence": 0.02})
        _add_json(tar, f"{prefix}/docs/intro.json", {"ignored": True})
        if evil:
            _add_json(tar, f"{prefix}/domains/../../escape.json",
                      {"domain": "escape.example"})
    return archive


def _wtm_monthly_fixture(root, entries=None):
    """whotracksme 月度 trackerdb.json：5 tracker 条目（SPEC-E2 §D3）。"""
    if entries is None:
        entries = {
            "trackco": {"name": "TrackCo", "category": "advertising",
                        "website_url": "https://trackco.example",
                        "domains": ["tracker.example", "pixel.example"],
                        "prevalence": 0.012},
            "analyticsco": {"name": "Analytics Co", "category": "analytics",
                            "website_url": "https://analytics.example",
                            "domains": ["analytics.example"],
                            "prevalence": 0.03},
            "minimal": {"domains": ["minimal.example"]},  # 缺失键宽容
            "noprevalence": {"name": "NoPrev", "category": "advertising",
                             "domains": ["noprev.example"]},
            "nodomains": {"name": "NoDomains", "category": "misc",
                          "prevalence": 0.5},  # domains 缺失 → 无贡献
        }
    dest = root / "whotracksme"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "trackerdb.json").write_text(
        json.dumps({"trackers": entries}), encoding="utf-8")
    return root


# ---- D1 通用下载器 -----------------------------------------------------------


def test_fetch_file_url_downloads(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"tracker-data" * 100)
    result = downloader.fetch(src.as_uri(), tmp_path / "out")
    assert result.from_cache is False
    assert result.path.read_bytes() == src.read_bytes()
    assert result.bytes_written == len(src.read_bytes())


def test_fetch_writes_etag_sidecar(tmp_path, monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.header_items())
        return _FakeResponse(b"body", {"ETag": '"v1"'})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = downloader.fetch("https://example.com/data.bin", tmp_path)
    assert result.bytes_written == 4 and result.from_cache is False
    assert (tmp_path / "data.bin.etag").read_text() == '"v1"'


def test_fetch_304_returns_from_cache(tmp_path, monkeypatch):
    target = tmp_path / "data.bin"
    target.write_bytes(b"cached-body")
    (tmp_path / "data.bin.etag").write_text('"v1"', encoding="utf-8")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.header_items())
        raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = downloader.fetch("https://example.com/data.bin", tmp_path)
    assert result.from_cache is True
    assert result.bytes_written == len(b"cached-body")
    assert result.path.read_bytes() == b"cached-body"
    assert captured["headers"].get("If-none-match") == '"v1"'  # 带条件请求


def test_fetch_retries_then_succeeds(tmp_path, monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.URLError("boom")
        return _FakeResponse(b"ok")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = downloader.fetch("https://example.com/x.bin", tmp_path,
                              max_retries=2)
    assert result.path.read_bytes() == b"ok"
    assert len(calls) == 3


def test_fetch_retry_exhausted_raises(tmp_path, monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(1)
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError, match="下载失败"):
        downloader.fetch("https://example.com/x.bin", tmp_path, max_retries=1)
    assert len(calls) == 2  # 初次 + max_retries 次


def test_fetch_http_error_raises(tmp_path, monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        downloader.fetch("https://example.com/x.bin", tmp_path, max_retries=0)


def test_fetch_streams_large_body(tmp_path, monkeypatch):
    src = tmp_path / "big.bin"
    payload = b"x" * 8192
    src.write_bytes(payload)
    monkeypatch.setattr(downloader, "_STREAM_THRESHOLD", 1024)  # 强制流式路径
    result = downloader.fetch(src.as_uri(), tmp_path / "out")
    assert result.bytes_written == len(payload)
    assert result.path.read_bytes() == payload


# ---- D2 Tracker Radar 全量下载 / 导入 -----------------------------------------


def test_tracker_radar_download_disabled_skips(tmp_path, home):
    _write_settings(home)  # packages.trackerRadar False
    archive = _tr_archive_fixture(tmp_path)
    root = tracker_radar.download_tracker_radar(tmp_path / "data",
                                                url=archive.as_uri())
    assert root.name == "tracker_radar"
    assert not root.exists()  # NC 闸：跳过下载


def test_tracker_radar_download_extracts_archive(tmp_path, home):
    _write_settings(home, trackerRadar=True)
    archive = _tr_archive_fixture(tmp_path)
    root = tracker_radar.download_tracker_radar(tmp_path / "data",
                                                url=archive.as_uri())
    assert (root / "domains" / "US" / "a.example.json").is_file()
    assert (root / "entities" / "ACo.json").is_file()
    assert not (root / "docs").exists()  # 仅提取 domains/ 与 entities/


def test_tracker_radar_download_rejects_path_traversal(tmp_path, home):
    _write_settings(home, trackerRadar=True)
    archive = _tr_archive_fixture(tmp_path, evil=True)
    with pytest.raises(ValueError, match="路径穿越"):
        tracker_radar.download_tracker_radar(tmp_path / "data",
                                             url=archive.as_uri())
    assert not (tmp_path / "escape.json").exists()
    assert not (tmp_path.parent / "escape.json").exists()


def test_tracker_radar_full_import_schema_mapping(conn, tmp_path, home):
    _write_settings(home, trackerRadar=True)
    _tr_full_fixture(tmp_path)
    rows = tracker_radar.import_tracker_radar(conn, tmp_path)
    assert rows == 4  # 3 域名 + entities 并入 1 个新域名

    rec = conn.execute(
        "SELECT entity, category, fingerprinting_score, prevalence,"
        " is_tracking, source FROM domains WHERE domain='doubleclick.example'"
    ).fetchone()
    assert rec == ("Google LLC", "advertising", 2, 0.446, 1, "tracker_radar")

    # 多分类首选非 unknown：Social Networking 未映射 → category=unknown，
    # 但 is_tracking 命中 social 词表 = 1
    rec = conn.execute(
        "SELECT category, is_tracking FROM domains WHERE domain='social.example'"
    ).fetchone()
    assert rec == ("unknown", 1)

    # 无追踪类别且 fingerprinting=0 → is_tracking=0
    rec = conn.execute(
        "SELECT category, is_tracking FROM domains WHERE domain='cdn.example'"
    ).fetchone()
    assert rec == ("unknown", 0)

    # entities properties[] 并入：新域名挂到同实体，继承实体 prevalence
    rec = conn.execute(
        "SELECT entity, category, prevalence, is_tracking FROM domains"
        " WHERE domain='google-syndication.example'").fetchone()
    assert rec == ("Google LLC", "unknown", 0.5, 0)
    # 已存在域名不被 entities 覆盖
    assert conn.execute(
        "SELECT prevalence FROM domains WHERE domain='doubleclick.example'"
    ).fetchone()[0] == 0.446

    meta = trackerdb.get_source_status(conn, "tracker_radar")
    assert meta["enabled"] is True and meta["rows"] == 4 and meta["nc"] is True


def test_tracker_radar_nc_gate_skips_download_and_import(conn, tmp_path, home):
    _write_settings(home)  # trackerRadar False
    _tr_full_fixture(tmp_path)
    root = tracker_radar.download_tracker_radar(tmp_path / "nodl")
    assert not root.exists()
    rows = tracker_radar.import_tracker_radar(conn, tmp_path)
    assert rows == 0
    assert conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0
    meta = trackerdb.get_source_status(conn, "tracker_radar")
    assert meta["enabled"] is False and meta["rows"] == 0


# ---- D3 whoTracks.me 月度统计 -------------------------------------------------


def test_whotracksme_download_file_url(tmp_path):
    src = tmp_path / "trackerdb.json"
    src.write_text(json.dumps({"trackers": {}}), encoding="utf-8")
    path = whotracksme.download_whotracksme(tmp_path / "data",
                                            url=src.as_uri())
    assert path == tmp_path / "data" / "whotracksme" / "trackerdb.json"
    assert json.loads(path.read_text()) == {"trackers": {}}


def test_whotracksme_monthly_import_five_entries(conn, tmp_path):
    _wtm_monthly_fixture(tmp_path)
    rows = whotracksme.import_whotracksme(conn, tmp_path)
    assert rows == 5  # 2+1+1+1 域名（nodomains 条目无贡献）
    rec = conn.execute(
        "SELECT entity, category, prevalence, is_tracking, source FROM domains"
        " WHERE domain='tracker.example'").fetchone()
    assert rec == ("TrackCo", "advertising", 0.012, 1, "whotracksme")
    # 缺失键宽容：minimal.example 只有域名
    rec = conn.execute(
        "SELECT entity, category, prevalence FROM domains"
        " WHERE domain='minimal.example'").fetchone()
    assert rec == (None, None, None)
    meta = trackerdb.get_source_status(conn, "whotracksme")
    assert meta["enabled"] is True and meta["rows"] == 5


def test_whotracksme_strict_type_errors(conn, tmp_path):
    _wtm_monthly_fixture(tmp_path, entries={
        "bad": {"name": "Bad", "domains": "not-a-list"}})
    with pytest.raises(ValueError, match="domains 非列表"):
        whotracksme.import_whotracksme(conn, tmp_path)
    _wtm_monthly_fixture(tmp_path / "d2", entries={
        "bad": {"domains": ["x.example"], "prevalence": "high"}})
    with pytest.raises(ValueError, match="prevalence 非数值"):
        whotracksme.import_whotracksme(conn, tmp_path / "d2")


def test_whotracksme_priority_does_not_override_higher_sources(conn, tmp_path):
    """优先级 tracker_radar > trackerdb > whotracksme > easyprivacy：
    高优先级已写 entity/category 不被覆盖，prevalence 恒更新。"""
    conn.execute(
        "INSERT INTO domains (domain, entity, category, fingerprinting_score,"
        " prevalence, is_tracking, source)"
        " VALUES ('tracker.example', 'NCCo', 'fingerprinting', 3, NULL, 1,"
        "        'tracker_radar')")
    conn.execute(
        "INSERT INTO domains (domain, entity, category, fingerprinting_score,"
        " prevalence, is_tracking, source)"
        " VALUES ('analytics.example', 'TdbCo', 'analytics', NULL, NULL, 1,"
        "        'trackerdb')")
    conn.commit()
    _wtm_monthly_fixture(tmp_path)
    whotracksme.import_whotracksme(conn, tmp_path)

    rec = conn.execute(
        "SELECT entity, category, source, prevalence FROM domains"
        " WHERE domain='tracker.example'").fetchone()
    assert rec == ("NCCo", "fingerprinting", "tracker_radar", 0.012)
    rec = conn.execute(
        "SELECT entity, category, source, prevalence FROM domains"
        " WHERE domain='analytics.example'").fetchone()
    assert rec == ("TdbCo", "analytics", "trackerdb", 0.03)
    # 未占用的域名正常补 entity/category
    rec = conn.execute(
        "SELECT entity, category, source FROM domains"
        " WHERE domain='pixel.example'").fetchone()
    assert rec == ("TrackCo", "advertising", "whotracksme")
