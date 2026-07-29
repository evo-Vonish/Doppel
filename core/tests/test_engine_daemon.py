"""在线消费 daemon 测试（SPEC-E §7 + §10 强制验收用例 1–5）。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tishen.engine import daemon, entity, rules, trackerdb
from tishen.engine.daemon import EngineConfig, EngineDaemon
from tishen.engine.datasets import tracker_radar, whotracksme
from tishen.observ import store
from tishen.observ.events import EVENT_COLUMNS, Event

T0 = 1_700_000_000_000
PERSONA = "p_test"
MINER = "https://cdn.evil.example/miner.js"
FP_ACTOR = "https://tracker.example/fp.js"
FP_APIS = ["canvas.getImageData", "canvas.toDataURL", "webgl.getParameter",
           "audio.createOscillator", "fonts.check", "navigator.userAgent"]

# 只读纪律对照列：events 全字段减去允许回写的两列
READONLY_COLUMNS = tuple(c for c in EVENT_COLUMNS
                         if c not in ("alert_level", "engine_tags"))


# ---- fixture 构造 -------------------------------------------------------------


def _insert_events(db_path: Path, events: list[Event]) -> None:
    conn = store.connect(db_path)
    store.insert_events(conn, events)
    conn.close()


def _ev(ts, etype, summary, *, page="site-a.com", actor=MINER,
        target_host=None, target_url=None):
    return Event(persona_id=PERSONA, ts=ts, session_id="sess-1",
                 event_type=etype, summary=summary, evidence_ref="pcap:x#1",
                 page_url=f"https://{page}/" if page else None,
                 actor_script=actor, target_host=target_host,
                 target_url=target_url)


def _mining_events() -> list[Event]:
    """§10-2 合成挖矿序列：长寿命 worker + wasm + 高密度 api_call +
    visibility_probe(hidden) 后活跃（窗口跨度 180s ≥120s）。"""
    evs = [_ev(T0, "worker_spawn", "worker spawn",
               target_host="cdn.evil.example",
               target_url="https://cdn.evil.example/miner.js"),
           _ev(T0 + 1_000, "wasm_load", "wasm load")]
    for i in range(30):  # 隐藏前：30 条/分钟级密度
        evs.append(_ev(T0 + 2_000 + i * 1_000, "api_call", "crypto.hash iter"))
    evs.append(_ev(T0 + 60_000, "visibility_probe", "visibilitychange hidden"))
    for i in range(40):  # 隐藏后活跃不降（密度 ≥ 隐藏前 80%）+ pool 域接触
        evs.append(_ev(T0 + 61_000 + i * 2_000, "api_call", "crypto.hash iter",
                       target_host="coinhive.com",
                       target_url="wss://coinhive.com/proxy"))
    return evs


def _fp_events(pages: list[str], t0: int, calls_per_page: int = 18) -> list[Event]:
    """指纹行为序列：≥5 种 FP API + 高频调用 + 向第三方发 request。"""
    evs: list[Event] = []
    for pi, page in enumerate(pages):
        base = t0 + pi * 60_000
        for i in range(calls_per_page):
            evs.append(_ev(base + i * 1_000, "api_call",
                           f"{FP_APIS[i % len(FP_APIS)]} probe",
                           page=page, actor=FP_ACTOR))
        evs.append(_ev(base + 59_000, "request", "GET beacon", page=page,
                       actor=FP_ACTOR, target_host="cdn.third.example",
                       target_url="https://cdn.third.example/p.gif"))
    return evs


def _make_daemon(tmp_path, *, now=T0 + 600_000) -> EngineDaemon:
    cfg = EngineConfig(tishen_home=tmp_path / "home", persona_id=PERSONA,
                       events_db=tmp_path / "events.db",
                       trackerdb_db=tmp_path / "trackerdb.db",
                       engine_db=tmp_path / "engine.db")
    return EngineDaemon(cfg, now_fn=lambda: now)


def _add_tracker_domain(db_path: Path) -> None:
    """domains 底表：tracker.example → TrackCo（非 NC 源，fp 分 NULL）。"""
    conn = trackerdb.connect(db_path)
    conn.execute(
        "INSERT INTO domains (domain, entity, category, fingerprinting_score,"
        " prevalence, is_tracking, source)"
        " VALUES ('tracker.example', 'TrackCo', 'advertising', NULL, 0.01, 1,"
        "        'whotracksme')")
    conn.execute("INSERT INTO domain_sources VALUES ('tracker.example', 'whotracksme')")
    conn.commit()
    conn.close()


def _subject(conn, subject: str):
    return conn.execute(
        "SELECT level, score, signals, inactive_windows FROM subject_state"
        " WHERE subject = ?", (subject,)).fetchone()


@pytest.fixture()
def daemon_pair(tmp_path):
    d = _make_daemon(tmp_path)
    yield d, tmp_path
    d.close()


# ---- §10-2 用例 1：合成挖矿序列 → 级别 3 + 回写断言 -----------------------------


def test_forced_mining_sequence_reaches_level3(daemon_pair):
    d, tmp = daemon_pair
    _insert_events(tmp / "events.db", _mining_events())
    stats = d.run_once()
    assert stats["gap"] is False and stats["annotated"] == len(_mining_events())

    row = _subject(d._engine, f"mining:{MINER}")
    assert row is not None and row[0] == 3  # 级别 3
    signals = json.loads(row[2])
    assert {"mining.long_lived_worker", "mining.wasm_compute",
            "mining.hidden_active", "mining.stack_repeat",
            "mining.pool_domain"} <= set(signals)

    conn = store.connect(tmp / "events.db")
    lvl, cnt = conn.execute(
        "SELECT MIN(alert_level), COUNT(*) FROM events"
        " WHERE event_type = 'api_call'").fetchone()
    assert lvl == 3 and cnt == 70  # 关键事件 alert_level 回写
    tags = {r[0] for r in conn.execute(
        "SELECT engine_tags FROM events WHERE event_type = 'api_call' LIMIT 5")}
    assert all("alert:L3:mining" in json.loads(t) for t in tags)
    conn.close()


# ---- §10-1 用例 2：跨站闸门（同实体 2 站封顶 2，第 3 站放行 3）------------------


def test_forced_cross_site_gate_caps_then_allows(daemon_pair):
    d, tmp = daemon_pair
    _add_tracker_domain(tmp / "trackerdb.db")
    _insert_events(tmp / "events.db", _fp_events(["site-a.com", "site-b.com"], T0))
    d.run_once()
    row = _subject(d._engine, "fingerprinting:TrackCo")
    assert row is not None and row[0] == 2  # 2 站点 → 封顶 2
    assert set(json.loads(row[2])) >= {"fp.api_combo", "fp.api_volume",
                                       "fp.exfil_to_third"}
    # sightings 已记 2 个站点注册域名
    assert d._engine.execute(
        "SELECT COUNT(*) FROM sightings WHERE entity = 'TrackCo'").fetchone()[0] == 2

    # 第 3 站点行为出现（本窗口再次三信号）→ sightings 写入 → 允许 3
    _insert_events(tmp / "events.db",
                   _fp_events(["site-c.com"], T0 + 300_000, calls_per_page=36))
    d.run_once()
    row = _subject(d._engine, "fingerprinting:TrackCo")
    assert row[0] == 3
    conn = store.connect(tmp / "events.db")
    tags = conn.execute(
        "SELECT engine_tags FROM events WHERE page_url LIKE '%site-c%'"
        " AND event_type = 'api_call' LIMIT 1").fetchone()[0]
    assert "alert:L3:fingerprinting" in json.loads(tags)
    conn.close()


# ---- §10-3 用例 3：license 闸（packages 全 False）-------------------------------


def test_forced_license_gate_pure_behavior_path(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("TISHEN_HOME", str(home))
    home.mkdir()
    (home / "settings.json").write_text(json.dumps({
        "mode": "default",
        "packages": {"easyPrivacy": True, "trackerRadar": False,
                     "trackerDb": False},
        "retainDays": 14}), encoding="utf-8")
    # NC 包导入尝试被闸门拦下
    tr_dir = tmp_path / "tr"
    tr_dir.mkdir()
    (tr_dir / "tracker_radar.json").write_text(json.dumps({"trackers": {
        "tracker.example": {"owner": {"name": "TrackCo"},
                            "categories": ["Fingerprinting"],
                            "fingerprinting": 3}}}), encoding="utf-8")
    tconn = trackerdb.connect(tmp_path / "trackerdb.db")
    assert tracker_radar.import_tracker_radar(tconn, tr_dir) == 0
    tconn.close()
    _add_tracker_domain(tmp_path / "trackerdb.db")  # 非 NC 源行（fp 列 NULL）

    # fingerprinting_score 恒 NULL、is_fp_invasive 恒 False
    tconn = trackerdb.connect(tmp_path / "trackerdb.db")
    assert tconn.execute(
        "SELECT COUNT(*) FROM domains WHERE fingerprinting_score IS NOT NULL"
    ).fetchone()[0] == 0
    hit = entity.attribute(tconn, "tracker.example", "site-a.com")
    assert hit.fingerprinting_score is None and hit.is_fp_invasive is False
    tconn.close()

    # E3 走纯行为路径：不出现 fp.cross_entity_fp_invasive 信号
    d = _make_daemon(tmp_path)
    try:
        _insert_events(tmp_path / "events.db",
                       _fp_events(["site-a.com", "site-b.com"], T0))
        d.run_once()
        row = _subject(d._engine, "fingerprinting:TrackCo")
        assert row is not None
        assert "fp.cross_entity_fp_invasive" not in json.loads(row[2])
        assert row[0] <= 2  # 双交集缺席，纯行为封顶 2
    finally:
        d.close()


# ---- §10 用例 4：背压（>5000 条只走快路径）--------------------------------------


def test_forced_backpressure_gap_fast_path_only(daemon_pair):
    d, tmp = daemon_pair
    evs = [_ev(T0 + i, "api_call", "misc.call x") for i in range(5010)]
    _insert_events(tmp / "events.db", evs)
    stats = d.run_once()
    assert stats["gap"] is True and stats["annotated"] == 5000
    # 只走快路径：不跑 E3（无 subject_state 行）
    assert d._engine.execute(
        "SELECT COUNT(*) FROM subject_state").fetchone()[0] == 0
    # cursor 推进到已消费的第 5000 条
    assert d._read_cursor() == T0 + 4999
    rest = d.run_once()
    assert rest["gap"] is False and rest["annotated"] == 10


# ---- §10 用例 5：观测层只读（仅 alert_level/engine_tags 可变）--------------------


def test_forced_observ_readonly_except_two_columns(daemon_pair):
    d, tmp = daemon_pair
    _insert_events(tmp / "events.db", _mining_events())
    conn = store.connect(tmp / "events.db")
    before = conn.execute(
        f"SELECT {', '.join(READONLY_COLUMNS)} FROM events"
        " ORDER BY event_id").fetchall()
    d.run_once()
    after = conn.execute(
        f"SELECT {', '.join(READONLY_COLUMNS)} FROM events"
        " ORDER BY event_id").fetchall()
    assert before == after  # 非回写列一字节不变
    # alert_level 只升不降（初值 0 → 回写后 ≥0 且单调）
    levels = [r[0] for r in conn.execute("SELECT alert_level FROM events")]
    assert all(0 <= lvl <= 3 for lvl in levels) and max(levels) == 3
    conn.close()


# ---- 其余行为 -----------------------------------------------------------------


def test_cursor_incremental_second_tick_empty(daemon_pair):
    d, tmp = daemon_pair
    _insert_events(tmp / "events.db", _mining_events())
    d.run_once()
    stats = d.run_once()
    assert stats == {"annotated": 0, "alerts": 0, "gap": False}


def test_engine_tags_merge_preserves_existing(daemon_pair):
    d, tmp = daemon_pair
    _add_tracker_domain(tmp / "trackerdb.db")
    ev = _fp_events(["site-a.com"], T0)[0]
    conn = store.connect(tmp / "events.db")
    store.insert_events(conn, [ev])
    conn.execute("UPDATE events SET engine_tags = ? WHERE event_id = ?",
                 ('["manual:tag"]', ev.event_id))
    conn.commit()
    conn.close()
    d.run_once()
    conn = store.connect(tmp / "events.db")
    tags = json.loads(conn.execute(
        "SELECT engine_tags FROM events WHERE event_id = ?",
        (ev.event_id,)).fetchone()[0])
    assert "manual:tag" in tags and "e1:entity:TrackCo" in tags
    conn.close()


def test_alert_level_monotonic_never_lowers(daemon_pair):
    d, tmp = daemon_pair
    _add_tracker_domain(tmp / "trackerdb.db")
    evs = _fp_events(["site-a.com", "site-b.com"], T0)  # 目标级别 2
    conn = store.connect(tmp / "events.db")
    store.insert_events(conn, evs)
    conn.execute("UPDATE events SET alert_level = 3")  # 预置更高级别
    conn.commit()
    conn.close()
    d.run_once()
    conn = store.connect(tmp / "events.db")
    assert conn.execute("SELECT MIN(alert_level) FROM events").fetchone()[0] == 3
    conn.close()


def test_sightings_registered_domain_and_same_site_skipped(daemon_pair):
    d, tmp = daemon_pair
    _add_tracker_domain(tmp / "trackerdb.db")
    evs = _fp_events(["www.site-a.com"], T0)  # 注册域名 site-a.com
    evs.append(_ev(T0 + 90_000, "request", "GET self",
                   page="tracker.example", actor=FP_ACTOR,
                   target_host="tracker.example",
                   target_url="https://tracker.example/x"))  # 同站不计
    _insert_events(tmp / "events.db", evs)
    d.run_once()
    rows = d._engine.execute(
        "SELECT entity, first_party_host FROM sightings").fetchall()
    assert rows == [("TrackCo", "site-a.com")]


def test_subject_state_decay_across_windows(daemon_pair):
    d, tmp = daemon_pair
    _insert_events(tmp / "events.db", _mining_events())
    d.run_once()
    assert _subject(d._engine, f"mining:{MINER}")[0] == 3
    for tick in range(3):  # 连续无信号窗口：inactive 1→2→3，第 3 窗衰减
        _insert_events(tmp / "events.db",
                       [_ev(T0 + 400_000 + tick * 300_000, "request",
                           "GET benign", target_host="cdn.evil.example",
                           target_url="https://cdn.evil.example/favicon.ico")])
        d.run_once()
    row = _subject(d._engine, f"mining:{MINER}")
    assert row[0] == 2 and row[3] >= 3  # DECAY_WINDOWS=3 → 级别 -1


def test_e2_rule_hit_tagged(daemon_pair):
    d, tmp = daemon_pair
    tconn = trackerdb.connect(tmp / "trackerdb.db")
    parsed, _ = rules.parse_abp_lines(["||ads.evil.example^"], "easyprivacy")
    rules.import_rules(tconn, parsed, "easyprivacy")
    tconn.close()
    _insert_events(tmp / "events.db",
                   [_ev(T0, "request", "GET ad", actor=None,
                       target_host="ads.evil.example",
                       target_url="https://ads.evil.example/b.js")])
    d.run_once()
    conn = store.connect(tmp / "events.db")
    tags = json.loads(conn.execute("SELECT engine_tags FROM events").fetchone()[0])
    assert any(t.startswith("e2:easyprivacy:") for t in tags)
    conn.close()


# ---- §8 bake 加挂（降级跳过不阻塞）----------------------------------------------


def _load_bake_module():
    path = Path(__file__).resolve().parents[2] / "image" / "entrypoint" / "persona_bake.py"
    spec = importlib.util.spec_from_file_location("persona_bake", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_bake_engine_hook_degrades_on_selfcheck_failure(capsys):
    pb = _load_bake_module()
    pb._CHILDREN.clear()
    orig = pb._engine_available
    pb._engine_available = lambda: False
    try:
        persona = SimpleNamespace(meta=SimpleNamespace(id="p_test"))
        pb.step7_6_engine(persona)  # 不抛异常、不登记子进程
    finally:
        pb._engine_available = orig
    assert "engine" not in pb._CHILDREN
    assert "降级跳过" in capsys.readouterr().out


def test_bake_engine_hook_dry_run_plan(capsys):
    pb = _load_bake_module()
    pb._CHILDREN.clear()
    orig_dry = pb._DRY_RUN
    pb._DRY_RUN = True
    try:
        persona = SimpleNamespace(meta=SimpleNamespace(id="p_test"))
        pb.step7_6_engine(persona)
    finally:
        pb._DRY_RUN = orig_dry
    out = capsys.readouterr().out
    assert "tishen.engine.daemon" in out and "engine" not in pb._CHILDREN
