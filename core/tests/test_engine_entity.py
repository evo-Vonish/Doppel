"""E1 实体归因测试（SPEC-E §5 + §10-3 license 闸）。"""

from __future__ import annotations

import pytest

from tishen.engine import entity, trackerdb


@pytest.fixture()
def conn(tmp_path):
    c = trackerdb.connect(tmp_path / "trackerdb.db")
    yield c
    c.close()


def _add_domain(conn, domain, *, entity_name=None, category="advertising",
                fp=None, is_tracking=1, source="tracker_radar"):
    conn.execute(
        "INSERT INTO domains (domain, entity, category, fingerprinting_score,"
        " prevalence, is_tracking, source) VALUES (?, ?, ?, ?, NULL, ?, ?)",
        (domain, entity_name, category, fp, is_tracking, source))
    conn.execute(
        "INSERT OR IGNORE INTO domain_sources (domain, source) VALUES (?, ?)",
        (domain, source))
    conn.commit()


def _enable_nc(conn, enabled=True):
    trackerdb.set_source_meta(
        conn, "tracker_radar", license="CC BY-NC-SA 4.0", nc=True,
        attribution="DDG", rows=1, enabled=enabled)


def test_exact_match_hit(conn):
    _add_domain(conn, "tracker.example", entity_name="TrackCo")
    hit = entity.attribute(conn, "tracker.example")
    assert hit.entity == "TrackCo" and hit.is_tracking is True
    assert hit.category == "advertising"


def test_parent_domain_fallback(conn):
    """a.b.c.com → b.c.com → c.com 逐级回退（SPEC-E §5）。"""
    _add_domain(conn, "c.com", entity_name="CCo")
    hit = entity.attribute(conn, "a.b.c.com")
    assert hit.entity == "CCo"
    assert hit.host == "a.b.c.com"  # host 保留查询原值


def test_all_miss_returns_empty_hit(conn):
    hit = entity.attribute(conn, "no.such-domain.example")
    assert hit.entity is None and hit.is_tracking is False
    assert hit.is_fp_invasive is False and hit.sources == []
    assert hit.fingerprinting_score is None


def test_nc_disabled_fp_score_none_and_not_invasive(conn):
    """§10-3 license 闸：NC 未启用 → fp 恒 None、is_fp_invasive 恒 False
    （即便 domains 扩展列残留历史值也不参与判定）。"""
    _add_domain(conn, "fp.example", entity_name="FpCo", fp=3)
    hit = entity.attribute(conn, "fp.example")
    assert hit.fingerprinting_score is None
    assert hit.is_fp_invasive is False


def test_nc_enabled_fp_invasive_when_score_ge_2(conn):
    _add_domain(conn, "fp.example", entity_name="FpCo", fp=2)
    _enable_nc(conn, enabled=True)
    hit = entity.attribute(conn, "fp.example")
    assert hit.fingerprinting_score == 2
    assert hit.is_fp_invasive is True


def test_nc_enabled_but_score_below_2_not_invasive(conn):
    _add_domain(conn, "fp.example", entity_name="FpCo", fp=1)
    _enable_nc(conn, enabled=True)
    hit = entity.attribute(conn, "fp.example")
    assert hit.fingerprinting_score == 1
    assert hit.is_fp_invasive is False


def test_nc_meta_disabled_flag_overrides_column(conn):
    """meta 台账 enabled=false（重导被关）同样降级为 None。"""
    _add_domain(conn, "fp.example", entity_name="FpCo", fp=3)
    _enable_nc(conn, enabled=False)
    hit = entity.attribute(conn, "fp.example")
    assert hit.fingerprinting_score is None and hit.is_fp_invasive is False


def test_first_party_related_same_entity(conn):
    _add_domain(conn, "cdn.exco.com", entity_name="ExCo")
    _add_domain(conn, "www.exco.com", entity_name="ExCo")
    hit = entity.attribute(conn, "cdn.exco.com", page_host="www.exco.com")
    assert hit.first_party_related is True


def test_first_party_related_false_when_entity_differs_or_none(conn):
    _add_domain(conn, "tracker.example", entity_name="TrackCo")
    _add_domain(conn, "www.exco.com", entity_name="ExCo")
    assert entity.attribute(conn, "tracker.example",
                            page_host="www.exco.com").first_party_related is False
    # 无实体信息不得豁免
    _add_domain(conn, "anon.example", entity_name=None, source="easyprivacy")
    assert entity.attribute(conn, "anon.example",
                            page_host="anon.example").first_party_related is False
    assert entity.attribute(conn, "tracker.example",
                            page_host=None).first_party_related is False


def test_sources_multi_source_trace(conn):
    _add_domain(conn, "multi.example", entity_name="MCo", source="tracker_radar")
    conn.execute("INSERT INTO domain_sources VALUES ('multi.example', 'whotracksme')")
    conn.commit()
    hit = entity.attribute(conn, "multi.example")
    assert hit.sources == ["tracker_radar", "whotracksme"]


def test_not_tracking_row(conn):
    _add_domain(conn, "cdn.example", entity_name="CdnCo", is_tracking=0, fp=3)
    _enable_nc(conn, enabled=True)
    hit = entity.attribute(conn, "cdn.example")
    assert hit.is_tracking is False
    assert hit.is_fp_invasive is False  # is_fp_invasive = is_tracking ∧ score>=2
