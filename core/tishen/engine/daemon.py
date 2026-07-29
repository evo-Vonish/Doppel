"""在线消费循环（SPEC-E §7，Wave2 Coder B 拥有）+ engine.db 建库（§1.2）。

run_once 严格按 §7 五步：
1. 读 engine.db cursor，增量查 events.db（`ts > last_ts`，同 persona_id，
   每次 ≤5000 条，超出记 gap=True 并只走快路径）；
2. 快路径标注：每条事件 E1 attribute + E2 match_url → 命中者 UPDATE
   `engine_tags`（JSON 数组合并原值去重，标签如 "e2:easyprivacy:<rule_id>"、
   "e1:entity:<name>"）；is_tracking 事件写 sightings（entity × page 注册域名）；
3. 窗口聚合：按 (actor_script 或 entity) 分桶 → behavior.score_mining /
   score_fingerprinting → scorer.decide_level（cross_site_count 查 sightings）；
4. 回写告警：级别 ≥1 的桶，UPDATE 桶内事件 `alert_level`
   （只升不降 `SET alert_level = MAX(alert_level, ?)`）并追加标签
   "alert:L<n>:<kind>"；写 subject_state；
5. 推进 cursor。

回写铁律（SPEC-E §0/§7）：对 events.db 的 UPDATE 只动
`alert_level` 与 `engine_tags` 两列，其余字段只读——本模块全部
events UPDATE 语句集中在 _merge_tags / _apply_alert 两处，供评审检查。

口径对齐（Wave1 已验）：
- api_call 的 API 名取 summary 首 token（behavior.py docstring 约定）；
- worker 无终止事件（EVENT_TYPES 无 worker_terminate），"长寿命"以
  窗口末端仍活跃近似（behavior._mining_signals 实现）；
- 分桶只产出 list[Event] 与布尔参数喂 behavior/scorer，不另造口径。
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from tishen.observ import store as observ_store
from tishen.observ.events import EVENT_COLUMNS, Event, event_from_row
from tishen.state import tishen_home

from . import rules, trackerdb
from .behavior import score_fingerprinting, score_mining
from .entity import EntityHit, attribute
from .scorer import decide_level

log = logging.getLogger("tishen.engine.daemon")

# 单 tick 增量上限（SPEC-E §7-1）：超出记 gap=True 且只走快路径
MAX_BATCH = 5000

# engine.db schema（SPEC-E §1.2 原样）
_ENGINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY CHECK(id=1), last_ts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sightings (  -- Privacy Badger 跨站闸门计数
    entity TEXT NOT NULL, first_party_host TEXT NOT NULL, first_seen_ts INTEGER NOT NULL,
    PRIMARY KEY (entity, first_party_host)
);
CREATE TABLE IF NOT EXISTS subject_state (  -- 评级状态（级别只升不降 + 跨窗衰减）
    subject TEXT PRIMARY KEY,      -- entity 名或 actor_script
    kind TEXT NOT NULL,            -- mining / fingerprinting
    level INTEGER NOT NULL,        -- 当前级别 0–3
    score INTEGER NOT NULL,
    signals TEXT NOT NULL,         -- JSON 数组
    inactive_windows INTEGER NOT NULL DEFAULT 0,
    updated_ts INTEGER NOT NULL
);
"""


@dataclass
class EngineConfig:
    """SPEC-E §7：引擎守护配置。"""

    tishen_home: Path
    persona_id: str
    window_ms: int = 300_000
    poll_interval_s: float = 30.0
    # 路径覆盖（测试注入）；默认按 §1.2/§1.1 与宿主 events 库约定推导
    engine_db: Path | None = None
    trackerdb_db: Path | None = None
    events_db: Path | None = None


def connect_engine_db(db_path: str | Path) -> sqlite3.Connection:
    """打开（必要时创建）engine.db 并按 §1.2 建三表，WAL。"""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_ENGINE_SCHEMA)
    return conn


def _host_of_actor(actor_script: str | None) -> str | None:
    """从 actor_script 提取 host（URL 取 hostname；裸域名原样）。"""
    if not actor_script:
        return None
    if "://" in actor_script:
        return urlparse(actor_script).hostname
    if "/" not in actor_script and "." in actor_script:
        return actor_script.lower()
    return None


def _page_host_of(ev: Event) -> str | None:
    if not ev.page_url:
        return None
    return urlparse(ev.page_url).hostname


def _merge_tags(old_json: str, new_tags: list[str]) -> str | None:
    """JSON 数组合并原值去重（排序保证确定性）；无新增返回 None。

    本函数是 events.db `engine_tags` 列的唯一回写处（回写铁律检查点）。
    """
    try:
        old = json.loads(old_json) if old_json else []
        if not isinstance(old, list):
            old = []
    except json.JSONDecodeError:
        old = []
    merged = sorted({*(str(t) for t in old), *new_tags})
    if merged == sorted(str(t) for t in old):
        return None
    return json.dumps(merged, ensure_ascii=False)


class EngineDaemon:
    """SPEC-E §7：events.db 增量消费 → E1/E2 标注 → E3 评级 → 告警回写。"""

    def __init__(self, config: EngineConfig, *, now_fn=None) -> None:
        self.config = config
        self.now_fn = now_fn or (lambda: time.time_ns() // 1_000_000)
        home = Path(config.tishen_home)
        engine_db = config.engine_db or home / "engine" / "engine.db"
        trackerdb_db = config.trackerdb_db or home / "engine" / "trackerdb.db"
        events_db = config.events_db or home / "events" / f"{config.persona_id}.db"
        self._engine = connect_engine_db(engine_db)
        self._tracker = trackerdb.connect(trackerdb_db)
        # 观测库只打开不建表之外的结构（store.connect 幂等建 schema，只读纪律
        # 指"事件字段只读"，schema IF NOT EXISTS 不动数据）
        self._events = observ_store.connect(events_db)
        self._closed = False

    # ---- 第 1 步：cursor + 增量拉取 ---------------------------------------

    def _read_cursor(self) -> int:
        row = self._engine.execute(
            "SELECT last_ts FROM cursor WHERE id = 1").fetchone()
        return int(row[0]) if row else 0

    def _fetch_new_events(self, last_ts: int) -> tuple[list[Event], bool]:
        """增量查 events.db（ts > last_ts、同 persona_id、≤5000 条）。

        多拉一条探测背压：超出 MAX_BATCH 记 gap=True 并只走快路径。
        """
        cur = self._events.execute(
            f"SELECT {', '.join(EVENT_COLUMNS)} FROM events"
            " WHERE ts > ? AND persona_id = ?"
            " ORDER BY ts, event_id LIMIT ?",
            (last_ts, self.config.persona_id, MAX_BATCH + 1))
        rows = cur.fetchall()
        gap = len(rows) > MAX_BATCH
        return [event_from_row(r) for r in rows[:MAX_BATCH]], gap

    # ---- 第 2 步：快路径标注 ----------------------------------------------

    def _annotate(self, ev: Event) -> dict:
        """单事件 E1 + E2 快路径标注；返回供分桶复用的标注记录。

        命中者 UPDATE engine_tags（仅此一列）；is_tracking 事件写
        sightings（entity × page 注册域名，同实体/同站豁免不计）。
        """
        page_host = _page_host_of(ev)
        host = ev.target_host or _host_of_actor(ev.actor_script)
        hit: EntityHit | None = attribute(self._tracker, host, page_host) if host else None
        match = None
        if ev.target_url:
            match = rules.match_url(self._tracker, ev.target_url, page_host)

        tags: list[str] = []
        if match is not None and match.hit and not match.exception:
            # rule_id 形如 "<source>:<sha1[:12]>" → "e2:easyprivacy:<id>"
            tags.append(f"e2:{match.rule_id}")
        if hit is not None and hit.entity:
            tags.append(f"e1:entity:{hit.entity}")
        if tags:
            merged = _merge_tags(ev.engine_tags, tags)
            if merged is not None:
                with self._events:
                    self._events.execute(
                        "UPDATE events SET engine_tags = ? WHERE event_id = ?",
                        (merged, ev.event_id))
                ev.engine_tags = merged

        if (hit is not None and hit.is_tracking and hit.entity and page_host
                and not hit.first_party_related):
            reg_page = rules.registered_domain(page_host)
            reg_host = rules.registered_domain(host) if host else None
            if reg_page and reg_host != reg_page:  # 同站不计入跨站闸门
                with self._engine:
                    self._engine.execute(
                        "INSERT OR IGNORE INTO sightings"
                        " (entity, first_party_host, first_seen_ts)"
                        " VALUES (?, ?, ?)",
                        (hit.entity, reg_page, ev.ts))

        # 分桶实体优先取脚本属主（actor host）：同一 actor 的外发 request
        # 指向第三方域，若按 target_host 归桶会把 fp.exfil_to_third 所需
        # 证据拆出桶外（与 §7-3 "actor_script 或 entity" 口径一致）。
        actor_host = _host_of_actor(ev.actor_script)
        actor_hit: EntityHit | None = None
        if actor_host and actor_host != host:
            actor_hit = attribute(self._tracker, actor_host, page_host)
        elif actor_host:
            actor_hit = hit
        bucket_entity = (actor_hit.entity if actor_hit and actor_hit.entity
                         else (hit.entity if hit else None))

        return {"event": ev, "page_host": page_host, "host": host,
                "hit": hit, "actor_hit": actor_hit, "entity": bucket_entity}

    # ---- 第 3 步：窗口聚合 -------------------------------------------------

    def _subject_state(self, subject: str) -> tuple[int, int]:
        """读 subject_state，返回 (prev_level, prev_inactive)；无存档为 (0, 0)。"""
        row = self._engine.execute(
            "SELECT level, inactive_windows FROM subject_state WHERE subject = ?",
            (subject,)).fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

    def _cross_site_count(self, entity: str) -> int:
        row = self._engine.execute(
            "SELECT COUNT(*) FROM sightings WHERE entity = ?", (entity,)).fetchone()
        return int(row[0])

    def _aggregate(self, records: list[dict]) -> list[dict]:
        """分桶 → 计分 → decide_level。返回评级桶列表（含无信号衰减桶）。

        分桶口径：mining 按 actor_script；fingerprinting 优先按 entity
        （actor_script host 归因），无实体可归属时按 actor_script——
        与 SPEC-E §7-3 "(actor_script 或 entity)" 一致，不另造口径。
        """
        mining_buckets: dict[str, list[Event]] = {}
        fp_buckets: dict[str, dict] = {}  # key → {"entity": str|None, "events": [...]}
        for rec in records:
            ev: Event = rec["event"]
            if ev.actor_script:
                mining_buckets.setdefault(ev.actor_script, []).append(ev)
                entity = rec["entity"]
                key = f"entity:{entity}" if entity else f"actor:{ev.actor_script}"
                bucket = fp_buckets.setdefault(
                    key, {"entity": entity, "subject": entity or ev.actor_script,
                          "events": []})
                bucket["events"].append(ev)

        results: list[dict] = []
        for actor, evts in mining_buckets.items():
            # subject_state.subject 以 "kind:name" 落库：§1.2 主键仅 subject
            # 一列，同一 actor 的 mining/fingerprinting 两类状态须隔离；
            # name 部分即 entity 名或 actor_script（§1.2 口径）。
            subject = f"mining:{actor}"
            scored = score_mining(evts, window_ms=self.config.window_ms)
            prev_level, prev_inactive = self._subject_state(subject)
            if scored is None and prev_level == 0 and prev_inactive == 0:
                continue  # 无历史且无信号：不落状态行
            signals = scored.signals if scored else []
            score = scored.score if scored else 0
            level, inactive = decide_level(
                signals=signals, score=score, kind="mining",
                cross_site_count=0, prev_level=prev_level,
                prev_inactive=prev_inactive)
            results.append({"subject": subject, "kind": "mining",
                            "level": level, "inactive": inactive,
                            "score": score, "signals": signals,
                            "events": evts, "had_signals": scored is not None})

        for bucket in fp_buckets.values():
            entity = bucket["entity"]
            evts: list[Event] = bucket["events"]
            entity_fp_invasive = False
            if entity:
                # 桶内任一命中记录 is_fp_invasive 即可（同实体判定一致）；
                # 优先脚本属主命中（actor_hit），退回 target_host 命中
                entity_fp_invasive = any(
                    (rec["actor_hit"] is not None
                     and rec["actor_hit"].is_fp_invasive
                     and rec["actor_hit"].entity == entity)
                    or (rec["hit"] is not None and rec["hit"].is_fp_invasive
                        and rec["hit"].entity == entity)
                    for rec in records)
            scored = score_fingerprinting(
                evts, entity_fp_invasive=entity_fp_invasive,
                window_ms=self.config.window_ms)
            subject = f"fingerprinting:{bucket['subject']}"
            prev_level, prev_inactive = self._subject_state(subject)
            if scored is None and prev_level == 0 and prev_inactive == 0:
                continue
            signals = scored.signals if scored else []
            score = scored.score if scored else 0
            cross_site = self._cross_site_count(entity) if entity else 0
            level, inactive = decide_level(
                signals=signals, score=score, kind="fingerprinting",
                cross_site_count=cross_site, prev_level=prev_level,
                prev_inactive=prev_inactive)
            results.append({"subject": subject, "kind": "fingerprinting",
                            "level": level, "inactive": inactive,
                            "score": score, "signals": signals,
                            "events": evts, "had_signals": scored is not None})
        return results

    # ---- 第 4 步：回写告警 -------------------------------------------------

    def _apply_alert(self, bucket: dict) -> None:
        """级别 ≥1 的桶：alert_level 只升不降 + 追加 alert 标签 + subject_state。

        本函数是 events.db `alert_level` 列的唯一回写处（回写铁律检查点，
        SQL 仅 `SET alert_level = MAX(alert_level, ?)`）。
        """
        level = bucket["level"]
        evts: list[Event] = bucket["events"]
        tag = f"alert:L{level}:{bucket['kind']}"
        with self._events:
            for ev in evts:
                self._events.execute(
                    "UPDATE events SET alert_level = MAX(alert_level, ?)"
                    " WHERE event_id = ?",
                    (level, ev.event_id))
                merged = _merge_tags(ev.engine_tags, [tag])
                if merged is not None:
                    self._events.execute(
                        "UPDATE events SET engine_tags = ? WHERE event_id = ?",
                        (merged, ev.event_id))
                    ev.engine_tags = merged
        with self._engine:
            self._engine.execute(
                "INSERT OR REPLACE INTO subject_state"
                " (subject, kind, level, score, signals, inactive_windows,"
                "  updated_ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (bucket["subject"], bucket["kind"], level, bucket["score"],
                 json.dumps(bucket["signals"], ensure_ascii=False),
                 bucket["inactive"], self.now_fn()))

    def _persist_state(self, bucket: dict) -> None:
        """无告警桶（含衰减路径）仍须落 subject_state（§4.3 跨窗衰减）。"""
        with self._engine:
            self._engine.execute(
                "INSERT OR REPLACE INTO subject_state"
                " (subject, kind, level, score, signals, inactive_windows,"
                "  updated_ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (bucket["subject"], bucket["kind"], bucket["level"],
                 bucket["score"],
                 json.dumps(bucket["signals"], ensure_ascii=False),
                 bucket["inactive"], self.now_fn()))

    # ---- 对外接口 -----------------------------------------------------------

    def run_once(self) -> dict:
        """一个 tick（SPEC-E §7 五步严格顺序）。

        返回 {"annotated": n, "alerts": n, "gap": bool}：
        annotated = 本 tick 拉取并走快路径的事件数；alerts = 本 tick
        级别 ≥1 的评级桶数；gap = 背压标记（>5000 条时只走快路径）。
        """
        if self._closed:
            raise RuntimeError("EngineDaemon 已 close")
        # 1. cursor + 增量
        last_ts = self._read_cursor()
        events, gap = self._fetch_new_events(last_ts)
        if not events:
            return {"annotated": 0, "alerts": 0, "gap": False}

        # 2. 快路径标注（含 sightings）
        records = [self._annotate(ev) for ev in events]

        # 3/4. 窗口聚合 + 回写（背压时跳过，只走快路径）
        alerts = 0
        if not gap:
            buckets = self._aggregate(records)
            for bucket in buckets:
                if bucket["level"] >= 1 and bucket["had_signals"]:
                    self._apply_alert(bucket)
                    alerts += 1
                else:
                    self._persist_state(bucket)
        else:
            log.warning("背压：单 tick 新事件超过 %d 条，本 tick 只走快路径"
                        "（跳过 E3 窗口聚合）", MAX_BATCH)

        # 5. 推进 cursor
        max_ts = max(ev.ts for ev in events)
        with self._engine:
            self._engine.execute(
                "INSERT OR REPLACE INTO cursor (id, last_ts) VALUES (1, ?)",
                (max_ts,))
        return {"annotated": len(events), "alerts": alerts, "gap": gap}

    def run_forever(self) -> None:
        """按 poll_interval_s 轮询 run_once，直至 KeyboardInterrupt。"""
        log.info("engine daemon 启动：persona=%s window=%dms poll=%.1fs",
                 self.config.persona_id, self.config.window_ms,
                 self.config.poll_interval_s)
        try:
            while True:
                stats = self.run_once()
                log.debug("tick: %s", stats)
                time.sleep(self.config.poll_interval_s)
        except KeyboardInterrupt:  # pragma: no cover - 交互路径
            log.info("收到中断，engine daemon 退出")
        finally:
            self.close()

    def close(self) -> None:
        """关闭三个连接（幂等）。"""
        if self._closed:
            return
        self._closed = True
        for conn in (self._events, self._tracker, self._engine):
            try:
                conn.close()
            except sqlite3.Error:  # pragma: no cover - 防御
                pass


def main(argv=None) -> None:  # pragma: no cover - 容器入口
    """`python -m tishen.engine.daemon` 容器入口（persona_bake 加挂，§8）。"""
    parser = argparse.ArgumentParser(description="替身判别引擎在线消费守护")
    parser.add_argument("--persona-id", required=True)
    parser.add_argument("--tishen-home", default=str(tishen_home()))
    parser.add_argument("--events-db", default=None)
    parser.add_argument("--poll-interval", type=float, default=30.0)
    parser.add_argument("--once", action="store_true", help="跑一个 tick 后退出")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="[engine_daemon] %(message)s")
    config = EngineConfig(
        tishen_home=Path(args.tishen_home), persona_id=args.persona_id,
        poll_interval_s=args.poll_interval,
        events_db=Path(args.events_db) if args.events_db else None)
    daemon = EngineDaemon(config)
    if args.once:
        print(json.dumps(daemon.run_once(), ensure_ascii=False))
        daemon.close()
        return
    daemon.run_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
