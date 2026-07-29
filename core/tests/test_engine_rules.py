"""E2 请求匹配层测试（SPEC-E §2 + §10-4 覆盖率口径）。

含：内置 100 行混合 ABP fixture 的 ParseStats 支持/跳过计数断言，
match_url 正误例各 ≥5，例外优先级、third-party 与 domain 修饰、
import_rules 幂等重导，以及 EasyPrivacy 适配器（§3，file:// 注入不连网）。
"""

from __future__ import annotations

import pytest

from conftest import FIXTURES_DIR

from tishen.engine import trackerdb
from tishen.engine.datasets import easyprivacy
from tishen.engine.rules import (MatchResult, import_rules, match_url,
                                 parse_abp_lines, registered_domain)

FIXTURE = FIXTURES_DIR / "abp_mixed_100.txt"


@pytest.fixture()
def conn(tmp_path):
    c = trackerdb.connect(tmp_path / "trackerdb.db")
    yield c
    c.close()


def _import(conn, lines):
    rules, stats = parse_abp_lines(lines, source="easyprivacy")
    import_rules(conn, rules, source="easyprivacy")
    return rules, stats


# ---------- §10-4：100 行混合 fixture 覆盖率断言 ----------

def test_fixture_total_and_invariant():
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 100
    _, stats = parse_abp_lines(lines, source="easyprivacy")
    assert stats.total == 100
    assert stats.total == stats.supported + stats.skipped


def test_fixture_supported_skipped_counts():
    _, stats = parse_abp_lines(
        FIXTURE.read_text(encoding="utf-8").splitlines(), source="easyprivacy")
    assert stats.supported == 65
    assert stats.skipped == 35
    assert stats.by_skip_reason == {
        "comment": 5, "blank": 3, "element_hiding": 10,
        "regex": 5, "unsupported_modifier": 12,
    }


def test_parse_domain_anchor_fields():
    rules, _ = parse_abp_lines(
        ["||ads.example.com/banner*$third-party"], source="easyprivacy")
    r = rules[0]
    assert r.kind == "block"
    assert r.pattern_type == "domain_anchor"
    assert r.host == "ads.example.com"
    assert r.path_pattern == "/banner*"
    assert r.third_party == 1
    assert r.rule_id.startswith("easyprivacy:")


def test_parse_exception_and_domain_modifier():
    rules, _ = parse_abp_lines(
        ["@@||good.example.com/ok.js^$~third-party,domain=a.com|~b.com"],
        source="easyprivacy")
    r = rules[0]
    assert r.kind == "exception"
    assert r.third_party == 0
    assert r.domain_modifier == "a.com|~b.com"


def test_parse_unsupported_never_raises():
    """不支持语法一律跳过计数，不报错（SPEC-E §2.1）。"""
    lines = ["x.com##.ad", "y.com#@#.ad", "/re\\d+/", "||a.com^$script",
             "||a.com^$redirect=noop", "||^", "||nodot^", "||a.com^$"]
    rules, stats = parse_abp_lines(lines, source="easyprivacy")
    assert rules == []
    assert stats.supported == 0
    assert stats.skipped == len(lines)


def test_registered_domain_last_two_labels():
    """注册域名近似判断=末两段，不做 eTLD 精度（SPEC-E §2.2 ③口径）。"""
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("a.example.co.uk") == "co.uk"
    assert registered_domain("localhost") == "localhost"


# ---------- match_url 正例 ≥5 ----------

@pytest.fixture()
def match_conn(conn):
    _import(conn, [
        "||ads.example.com^",
        "||tracker.example.com/pixel*",
        "/banner*",
        "||tp.example.net^$third-party",
        "||fp.example.org^$~third-party",
        "@@||ads.example.com/whitelist^",
        "||dm.example.com^$domain=good.com|~bad.good.com",
    ])
    return conn


def test_match_domain_anchor_hit(match_conn):
    res = match_url(match_conn, "http://ads.example.com/", "news.com")
    assert res.hit and not res.exception
    assert res.rule_id and res.raw == "||ads.example.com^"


def test_match_host_suffix_boundary(match_conn):
    res = match_url(match_conn, "http://sub.ads.example.com/x", "news.com")
    assert res.hit and res.raw == "||ads.example.com^"


def test_match_path_pattern_hit(match_conn):
    res = match_url(match_conn, "http://tracker.example.com/pixel.gif", "a.com")
    assert res.hit and res.raw == "||tracker.example.com/pixel*"


def test_match_substring_hit(match_conn):
    res = match_url(match_conn, "http://foo.com/ads/banner123.jpg", "foo.com")
    assert res.hit and res.raw == "/banner*"


def test_match_third_party_only_hit(match_conn):
    res = match_url(match_conn, "http://tp.example.net/", "unrelated.com")
    assert res.hit and res.raw == "||tp.example.net^$third-party"


def test_match_domain_modifier_positive_hit(match_conn):
    res = match_url(match_conn, "http://dm.example.com/", "www.good.com")
    assert res.hit and res.raw == "||dm.example.com^$domain=good.com|~bad.good.com"


def test_exception_beats_block(match_conn):
    """例外规则优先于 block（SPEC-E §2.2 ②）。"""
    res = match_url(match_conn, "http://ads.example.com/whitelist", "news.com")
    assert res.hit and res.exception
    assert res.raw == "@@||ads.example.com/whitelist^"


def test_no_page_host_treated_as_third_party(match_conn):
    res = match_url(match_conn, "http://tp.example.net/", None)
    assert res.hit  # page 未知从严按第三方


# ---------- match_url 误例 ≥5 ----------

def test_no_match_suffix_not_on_boundary(match_conn):
    res = match_url(match_conn, "http://ads.example.com.evil.com/", "news.com")
    assert not res.hit


def test_no_match_path_pattern_mismatch(match_conn):
    res = match_url(match_conn, "http://tracker.example.com/other.js", "a.com")
    assert not res.hit


def test_no_match_third_party_rule_on_first_party(match_conn):
    res = match_url(match_conn, "http://tp.example.net/", "sub.tp.example.net")
    assert not res.hit


def test_no_match_first_party_rule_on_third_party(match_conn):
    res = match_url(match_conn, "http://fp.example.org/", "other.com")
    assert not res.hit


def test_no_match_domain_modifier_negated(match_conn):
    res = match_url(match_conn, "http://dm.example.com/", "bad.good.com")
    assert not res.hit


def test_no_match_domain_modifier_unlisted_page(match_conn):
    res = match_url(match_conn, "http://dm.example.com/", "none.com")
    assert not res.hit


def test_no_match_unknown_host(match_conn):
    assert match_url(match_conn, "http://unknown.example/", "x.com").hit is False


def test_match_result_stable_shape(match_conn):
    res = match_url(match_conn, "http://unknown.example/", "x.com")
    assert res == MatchResult(hit=False, exception=False, rule_id=None, raw=None)


# ---------- import_rules 幂等 ----------

def test_import_rules_idempotent_reimport(conn):
    _import(conn, ["||a.example.com^", "/x*"])
    rules2, _ = parse_abp_lines(["||b.example.com^"], source="easyprivacy")
    import_rules(conn, rules2, source="easyprivacy")
    raws = {r[0] for r in conn.execute("SELECT raw FROM rules")}
    assert raws == {"||b.example.com^"}  # 先删该 source 旧规则再导入


def test_import_rules_preserves_other_sources(conn):
    _import(conn, ["||a.example.com^"])
    rules2, _ = parse_abp_lines(["||b.example.com^"], source="trackerdb")
    import_rules(conn, rules2, source="trackerdb")
    raws = {r[0] for r in conn.execute("SELECT raw FROM rules")}
    assert raws == {"||a.example.com^", "||b.example.com^"}


# ---------- EasyPrivacy 适配器（§3） ----------

def test_import_easyprivacy_end_to_end(conn, tmp_path):
    src = tmp_path / "easyprivacy.txt"
    src.write_text("! note\n||ads.example.com^\n||trk.example.net/px*$third-party"
                   "\n/banner*\nx.com##.ad\n", encoding="utf-8")
    stats = easyprivacy.import_easyprivacy(conn, src)
    assert stats.total == 5 and stats.supported == 3 and stats.skipped == 2

    assert match_url(conn, "http://ads.example.com/", "x.com").hit
    status = trackerdb.get_source_status(conn, "easyprivacy")
    assert status["nc"] is False and status["enabled"] is True
    assert status["rows"] == 3
    assert status["license"] == easyprivacy.LICENSE["name"]

    # domains 粗标注聚合（§3）：锚定 host 进 domains + domain_sources
    rows = dict(conn.execute("SELECT domain, is_tracking FROM domains"))
    assert rows == {"ads.example.com": 1, "trk.example.net": 1}
    cats = {r[0] for r in conn.execute("SELECT category FROM domains")}
    assert cats == {"unknown"}
    srcs = {r[0] for r in conn.execute("SELECT domain FROM domain_sources")}
    assert srcs == {"ads.example.com", "trk.example.net"}


def test_download_from_file_url(tmp_path):
    """测试不真连网：file:// 注入本地 fixture（§10-6）。"""
    fixture = FIXTURE
    out = easyprivacy.download(tmp_path / "dl", url=fixture.as_uri())
    assert out.name == "easyprivacy.txt"
    assert out.read_text(encoding="utf-8") == fixture.read_text(encoding="utf-8")


def test_download_failure_raises_runtime_error(tmp_path):
    with pytest.raises(RuntimeError):
        easyprivacy.download(tmp_path / "dl",
                             url=(tmp_path / "missing.txt").as_uri())


# ---------- 回归：path_pattern 参与匹配 + third-party 过滤（验收修复） ----------

@pytest.fixture()
def path_conn(conn):
    _import(conn, [
        "||tracker.net^/pixel.gif$third-party",
        "||ads.example.com^",
        "@@||ads.example.com^/whitelisted.js",
        "||fp-only.example.com/a*^$~third-party",
    ])
    return conn


def test_regression_anchored_path_hit(path_conn):
    res = match_url(path_conn, "https://tracker.net/pixel.gif", "foo.com")
    assert res.hit and not res.exception
    assert res.raw == "||tracker.net^/pixel.gif$third-party"


def test_regression_anchored_path_miss_other_path(path_conn):
    assert match_url(path_conn, "https://tracker.net/other.gif",
                     "foo.com").hit is False


def test_regression_exception_with_path_releases_only_that_path(path_conn):
    """例外带 path：只放行指定 path，同 host 其他 path 仍 block（§2.2 ②）。"""
    res = match_url(path_conn, "https://ads.example.com/whitelisted.js", "x.com")
    assert res.hit and res.exception
    res2 = match_url(path_conn, "https://ads.example.com/other.js", "x.com")
    assert res2.hit and not res2.exception
    assert res2.raw == "||ads.example.com^"


def test_regression_third_party_hit_only_on_third_party(path_conn):
    """tp=1 仅第三方命中（§2.2 ③，末两段注册域名近似判定）。"""
    assert match_url(path_conn, "https://tracker.net/pixel.gif", "foo.com").hit
    assert match_url(path_conn, "https://tracker.net/pixel.gif",
                     "sub.tracker.net").hit is False


def test_regression_first_party_modifier_hit_only_on_first_party(path_conn):
    """tp=0（$~third-party）仅第一方命中。"""
    assert match_url(path_conn, "https://fp-only.example.com/abc", "fp-only.example.com").hit
    assert match_url(path_conn, "https://fp-only.example.com/abc", "else.com").hit is False


def test_regression_third_party_none_page_treated_as_third(path_conn):
    assert match_url(path_conn, "https://tracker.net/pixel.gif", None).hit


def test_regression_match_url_does_not_touch_conn_row_factory(path_conn):
    """match_url 不得污染调用方共享连接的 row_factory（Wave2 复用 conn）。"""
    match_url(path_conn, "https://tracker.net/pixel.gif", "foo.com")
    assert path_conn.row_factory is None


def test_regression_parse_strips_leading_separator_in_path_pattern():
    rules, _ = parse_abp_lines(["||tracker.net^/pixel.gif$third-party"],
                               source="easyprivacy")
    assert rules[0].path_pattern == "/pixel.gif"
