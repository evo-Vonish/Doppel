"""数据适配器 + license 矩阵测试（SPEC-E §6，本地 fixture 注入不连网）。"""

from __future__ import annotations

import json

import pytest

from tishen.engine import rules, trackerdb
from tishen.engine.datasets import licenses, tracker_radar, trackerdb_src, whotracksme


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


def _wtm_fixture(tmp_path):
    d = tmp_path / "wtm"
    d.mkdir()
    (d / "whotracksme.json").write_text(json.dumps({"domains": {
        "tracker.example": {"prevalence": 0.012, "entity": "TrackCo",
                            "category": "advertising"},
        "pixel.example": {"prevalence": 0.003},
    }}), encoding="utf-8")
    return d


def _tr_fixture(tmp_path):
    d = tmp_path / "tr"
    d.mkdir()
    (d / "tracker_radar.json").write_text(json.dumps({"trackers": {
        "tracker.example": {"owner": {"name": "TrackCo"},
                            "categories": ["Advertising"],
                            "prevalence": 0.02, "fingerprinting": 2},
        "fp.example": {"owner": {"name": "FpCo"},
                       "categories": ["Fingerprinting"],
                       "fingerprinting": 3},
        "odd.example": {"fingerprinting": 9},   # 越界评分 → clamp
    }}), encoding="utf-8")
    return d


_ENO = """name: TrackCo Service
category: advertising
domains:
- tracker.example
filters:
- `||tracker.example^$third-party`
- `##.ad-banner`

name: Analytics Co
category: site_analytics
domains:
- analytics.example
"""


def _eno_fixture(tmp_path):
    d = tmp_path / "eno"
    d.mkdir()
    (d / "patterns.eno").write_text(_ENO, encoding="utf-8")
    return d


# ---- LICENSE_MATRIX / NOTICE ----------------------------------------------


def test_license_matrix_completeness():
    assert set(licenses.LICENSE_MATRIX) == {
        "easyprivacy", "whotracksme", "tracker_radar", "trackerdb"}
    for name, info in licenses.LICENSE_MATRIX.items():
        assert {"license", "nc", "attribution", "url"} <= set(info), name
    assert licenses.LICENSE_MATRIX["whotracksme"]["nc"] is False
    assert licenses.LICENSE_MATRIX["tracker_radar"]["nc"] is True
    assert licenses.LICENSE_MATRIX["trackerdb"]["nc"] is True


def test_generate_notice_lists_imported_sources(conn):
    trackerdb.set_source_meta(conn, "whotracksme", license="CC BY 4.0",
                              nc=False, attribution="Ghostery", rows=10,
                              enabled=True)
    notice = licenses.generate_notice(conn)
    assert "whotracksme" in notice and "CC BY 4.0" in notice
    assert "tracker_radar" not in notice  # 未导入源不出现


# ---- whoTracks.me（非 NC）---------------------------------------------------


def test_whotracksme_import_rows_and_meta(conn, tmp_path):
    rows = whotracksme.import_whotracksme(conn, _wtm_fixture(tmp_path))
    assert rows == 2
    rec = conn.execute(
        "SELECT entity, prevalence, is_tracking, source FROM domains"
        " WHERE domain = 'tracker.example'").fetchone()
    assert rec == ("TrackCo", 0.012, 1, "whotracksme")
    meta = trackerdb.get_source_status(conn, "whotracksme")
    assert meta["enabled"] is True and meta["rows"] == 2
    assert meta["license"] == "CC BY 4.0" and meta["nc"] is False


def test_whotracksme_does_not_override_nc_entity(conn, tmp_path):
    conn.execute(
        "INSERT INTO domains (domain, entity, category, fingerprinting_score,"
        " prevalence, is_tracking, source)"
        " VALUES ('tracker.example', 'NCCo', 'fingerprinting', 3, NULL, 1,"
        "        'tracker_radar')")
    conn.execute("INSERT INTO domain_sources VALUES ('tracker.example',"
                 " 'tracker_radar')")
    conn.commit()
    whotracksme.import_whotracksme(conn, _wtm_fixture(tmp_path))
    rec = conn.execute(
        "SELECT entity, category, source, prevalence FROM domains"
        " WHERE domain = 'tracker.example'").fetchone()
    assert rec[0] == "NCCo" and rec[1] == "fingerprinting"
    assert rec[2] == "tracker_radar" and rec[3] == 0.012  # prevalence 更新
    sources = {r[0] for r in conn.execute(
        "SELECT source FROM domain_sources WHERE domain = 'tracker.example'")}
    assert {"tracker_radar", "whotracksme"} <= sources


# ---- Tracker Radar（NC）------------------------------------------------------


def test_tracker_radar_disabled_skips_import(conn, tmp_path, home):
    _write_settings(home)  # packages 全 False
    rows = tracker_radar.import_tracker_radar(conn, _tr_fixture(tmp_path))
    assert rows == 0
    assert conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0
    meta = trackerdb.get_source_status(conn, "tracker_radar")
    assert meta["enabled"] is False and meta["rows"] == 0


def test_tracker_radar_enabled_imports_fp_scores(conn, tmp_path, home):
    _write_settings(home, trackerRadar=True)
    rows = tracker_radar.import_tracker_radar(conn, _tr_fixture(tmp_path))
    assert rows == 3
    rec = conn.execute(
        "SELECT entity, category, fingerprinting_score FROM domains"
        " WHERE domain = 'fp.example'").fetchone()
    assert rec == ("FpCo", "fingerprinting", 3)
    clamped = conn.execute(
        "SELECT fingerprinting_score FROM domains WHERE domain = 'odd.example'"
    ).fetchone()[0]
    assert clamped == 3  # 0–3 clamp，绝不脑补
    meta = trackerdb.get_source_status(conn, "tracker_radar")
    assert meta["enabled"] is True and meta["nc"] is True


def test_tracker_radar_missing_settings_file_disabled(conn, tmp_path, home):
    """缺 settings.json（默认 packages 全 False）→ 未启用。"""
    rows = tracker_radar.import_tracker_radar(conn, _tr_fixture(tmp_path))
    assert rows == 0
    assert trackerdb.get_source_status(conn, "tracker_radar")["enabled"] is False


# ---- ghostery/trackerdb .eno（NC）---------------------------------------------


def test_trackerdb_src_eno_parse_and_import(conn, tmp_path, home):
    _write_settings(home, trackerDb=True)
    rows = trackerdb_src.import_trackerdb_src(conn, _eno_fixture(tmp_path))
    assert rows == 2
    cat = conn.execute(
        "SELECT category FROM domains WHERE domain = 'analytics.example'"
    ).fetchone()[0]
    assert cat == "analytics"  # site_analytics → analytics 映射
    # filter 转 ABP 子集入库；## 元素隐藏被跳过计数
    hits = conn.execute(
        "SELECT raw, source, host, third_party FROM rules"
        " WHERE source = 'trackerdb'").fetchall()
    assert hits == [("||tracker.example^$third-party", "trackerdb",
                     "tracker.example", 1)]
    m = rules.match_url(conn, "https://tracker.example/x.js",
                        page_host="site-a.com")
    assert m.hit is True and m.exception is False


def test_trackerdb_src_disabled_skips_everything(conn, tmp_path, home):
    _write_settings(home)  # trackerDb=False
    rows = trackerdb_src.import_trackerdb_src(conn, _eno_fixture(tmp_path))
    assert rows == 0
    assert conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM rules WHERE source = 'trackerdb'").fetchone()[0] == 0
    assert trackerdb.get_source_status(conn, "trackerdb")["enabled"] is False
