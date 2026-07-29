"""trackerdb.db 建库与 meta 台账测试（SPEC-E §1.1）。"""

from __future__ import annotations

import json

import pytest

from tishen.engine import trackerdb


@pytest.fixture()
def conn(tmp_path):
    c = trackerdb.connect(tmp_path / "engine" / "trackerdb.db")
    yield c
    c.close()


def test_connect_creates_all_tables(conn):
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"meta", "rules", "domains", "domain_sources"} <= names


def test_connect_enables_wal(conn):
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_schema_version_written(conn):
    assert conn.execute(
        "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "1"


def test_rules_host_index_exists(conn):
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert "idx_rules_host" in names


def test_connect_idempotent(tmp_path):
    """重复 connect 不丢数据（IF NOT EXISTS 幂等）。"""
    p = tmp_path / "trackerdb.db"
    c1 = trackerdb.connect(p)
    trackerdb.set_source_meta(c1, "easyprivacy", license="GPLv3+", nc=False,
                              attribution="x", rows=7, enabled=True)
    c1.close()
    c2 = trackerdb.connect(p)
    assert trackerdb.get_source_status(c2, "easyprivacy")["rows"] == 7
    c2.close()


def test_default_db_path_under_tishen_home(tmp_path, monkeypatch):
    monkeypatch.setenv("TISHEN_HOME", str(tmp_path / "home"))
    assert trackerdb.default_db_path() == tmp_path / "home" / "engine" / "trackerdb.db"


def test_set_and_get_source_meta_roundtrip(conn):
    entry = trackerdb.set_source_meta(
        conn, "easyprivacy", license="GPLv3+/CC BY-SA 3.0+", nc=False,
        attribution="EasyPrivacy by EasyList authors", rows=123,
        enabled=True, imported_at=1_700_000_000_000)
    got = trackerdb.get_source_status(conn, "easyprivacy")
    assert got == entry
    assert got["rows"] == 123
    assert got["nc"] is False
    assert got["enabled"] is True
    assert got["imported_at"] == 1_700_000_000_000


def test_get_source_status_unknown_returns_none(conn):
    assert trackerdb.get_source_status(conn, "nope") is None


def test_set_source_meta_overwrites(conn):
    trackerdb.set_source_meta(conn, "trackerdb", license="CC BY-NC", nc=True,
                              attribution="t", rows=1, enabled=False)
    trackerdb.set_source_meta(conn, "trackerdb", license="CC BY-NC", nc=True,
                              attribution="t", rows=99, enabled=True)
    got = trackerdb.get_source_status(conn, "trackerdb")
    assert got["rows"] == 99 and got["enabled"] is True


def test_source_meta_stored_as_json_with_all_contract_keys(conn):
    trackerdb.set_source_meta(conn, "easyprivacy", license="L", nc=False,
                              attribution="a", rows=0, enabled=True)
    raw = conn.execute(
        "SELECT value FROM meta WHERE key = 'source:easyprivacy'").fetchone()[0]
    parsed = json.loads(raw)
    assert set(parsed) == {"license", "nc", "attribution", "rows",
                           "imported_at", "enabled"}
    assert isinstance(parsed["imported_at"], int)
