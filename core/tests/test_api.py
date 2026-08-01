"""本地 API 桥测试（SPEC-API §11，fastapi.testclient.TestClient）。

环境：monkeypatch TISHEN_HOME 到 tmp_path；沙盒无 docker
（FileNotFoundError 路径即真实覆盖——create 仍 201 creating，
生命周期动作 502 DOCKER_UNAVAILABLE，即 SPEC 规定的降级语义）。

覆盖 §11 全部 8 组：
1. settings GET 默认 / PUT 合法 / PUT 非法 400
2. personas：POST create → GET list → GET 单个 → GET 不存在 404
3. actions：无 docker 六动作 502；destroyed 后 start 409；非法 action 400（实现自择）
4. events：observ.store 建库插 3 条异类型事件 → 9 字段映射、type/limit/q 过滤、limit=0 → 400
5. lint：fixtures 合法 persona ok=true 且 checks 恰 10 条；V1 违例 ok=false 含 LINT_V1
6. doctor：items 非空且每项含 name/ok/hint
7. alerts：空数组；ack 未知 id → 404
8. embed：未 start（无 host_port）→ embedUrl == ""
"""

from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from conftest import FIXTURES_DIR

from tishen.api.app import app
from tishen.observ.events import Event
from tishen.observ.store import connect, insert_events
from tishen.persona import dump as dump_persona, load as load_persona
from tishen.state import StateDB, tishen_home

_TZ_CN = timezone(timedelta(hours=8))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TISHEN_HOME", str(tmp_path))
    # 显式构造"无 docker"环境（契约语义不依赖宿主是否装有 docker CLI——
    # CI runner 预装 docker 时 _run 返回非零/目录权限差异会污染断言）。
    def _no_docker(args):
        raise FileNotFoundError("docker CLI 不可用（测试显式构造）")
    monkeypatch.setattr("tishen.docker_ctl._run", _no_docker)
    return TestClient(app)


def _create(client: TestClient, name: str = "测试替身", region: str = "CN") -> dict:
    r = client.post("/api/personas", json={"name": name, "region": region})
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# 1. settings：GET 默认 / PUT 合法 / PUT 非法 400
# ---------------------------------------------------------------------------

def test_settings_default_get(client):
    r = client.get("/api/settings")
    assert r.status_code == 200
    assert r.json() == {
        "mode": "default",
        "packages": {"easyPrivacy": True, "trackerRadar": False,
                     "trackerDb": False},
        "retainDays": 14,
    }


def test_settings_put_valid_roundtrip(client):
    payload = {"mode": "expert",
               "packages": {"easyPrivacy": False, "trackerRadar": True,
                            "trackerDb": True},
               "retainDays": 30}
    r = client.put("/api/settings", json=payload)
    assert r.status_code == 200
    assert r.json() == payload
    # 写盘后 GET 回读一致
    assert client.get("/api/settings").json() == payload


@pytest.mark.parametrize("bad", [
    {"mode": "pro", "packages": {"easyPrivacy": True, "trackerRadar": False,
                                 "trackerDb": False}, "retainDays": 14},
    {"mode": "default", "packages": {"easyPrivacy": True, "trackerRadar": False,
                                     "trackerDb": False}, "retainDays": 15},
    {"mode": "default", "packages": {"easyPrivacy": True, "trackerRadar": False},
     "retainDays": 14},  # packages 缺键
    {"mode": "default", "packages": {"easyPrivacy": "yes", "trackerRadar": False,
                                     "trackerDb": False}, "retainDays": 14},
])
def test_settings_put_invalid_400(client, bad):
    r = client.put("/api/settings", json=bad)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_PARAM"


# ---------------------------------------------------------------------------
# 2. personas：create → list → 单个 → 404
# ---------------------------------------------------------------------------

def test_persona_create_list_get_404(client):
    # 沙盒无 docker：create 仍 201 creating（卷创建警告不阻断登记）
    created = _create(client)
    assert created["state"] == "creating"
    assert created["id"].startswith("p_")
    assert created["name"] == "测试替身"
    assert created["region"] == "CN"
    assert created["chromeVersion"]
    assert created["createdAt"]
    assert created["todayMinutes"] == 0
    # 未 start：无连接信息，Optional 键省略（不编造）
    assert "embedUrl" not in created
    assert "hostPort" not in created
    assert created["tz"] and created["locale"]
    assert "×" in created["resolution"] and "x" in created["resolution"]

    lst = client.get("/api/personas")
    assert lst.status_code == 200
    ids = [p["id"] for p in lst.json()]
    assert created["id"] in ids

    one = client.get(f"/api/personas/{created['id']}")
    assert one.status_code == 200
    assert one.json()["id"] == created["id"]

    missing = client.get("/api/personas/p_nonexistent_xx")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "PERSONA_NOT_FOUND"


def test_persona_create_invalid_region_400(client):
    r = client.post("/api/personas", json={"name": "x", "region": "XX"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_PARAM"


# ---------------------------------------------------------------------------
# 3. actions：无 docker 全 502；destroyed 后 409；非法 action 400
# ---------------------------------------------------------------------------

def test_actions_no_docker_502(client):
    pid = _create(client)["id"]
    for action in ("start", "stop", "suspend", "resume", "reset", "destroy"):
        r = client.post(f"/api/personas/{pid}/{action}")
        assert r.status_code == 502, f"{action}: {r.text}"
        assert r.json()["error"]["code"] == "DOCKER_UNAVAILABLE"


def test_actions_destroyed_conflict_409(client):
    pid = _create(client)["id"]
    # 用 502 路径之外的方式造 destroyed：直接 StateDB.update_state
    with StateDB() as db:
        db.update_state(pid, "destroyed")
    for action in ("start", "stop", "suspend", "resume", "reset"):
        r = client.post(f"/api/personas/{pid}/{action}")
        assert r.status_code == 409, f"{action}: {r.text}"
        assert r.json()["error"]["code"] == "STATE_CONFLICT"
    # destroyed 替身不出现在列表
    assert pid not in [p["id"] for p in client.get("/api/personas").json()]


def test_action_unknown_400(client):
    pid = _create(client)["id"]
    # 实现自择（SPEC-API §11.3）：非法 action 固定为 400 INVALID_PARAM
    r = client.post(f"/api/personas/{pid}/explode")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_PARAM"


def test_action_persona_not_found_404(client):
    r = client.post("/api/personas/p_nonexistent_xx/start")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "PERSONA_NOT_FOUND"


# ---------------------------------------------------------------------------
# 4. events：9 字段映射 + type/limit/q 过滤 + limit=0 → 400
# ---------------------------------------------------------------------------

def _seed_events(persona_id: str) -> tuple[str, list[int]]:
    """用 observ.store 建临时库插 3 条异类型事件（宿主回退路径），返回库路径与 ts 列表。"""
    now_ms = time.time_ns() // 1_000_000
    ts_list = [now_ms, now_ms - 5 * 60_000, now_ms - 10 * 60_000]
    db_path = tishen_home() / "events" / f"{persona_id}.db"
    conn = connect(db_path)
    try:
        insert_events(conn, [
            Event(persona_id=persona_id, ts=ts_list[0], session_id="s1",
                  event_type="request", summary="请求 Facebook 像素",
                  evidence_ref="pcap:shard0#1",
                  page_url="https://example.com/page",
                  target_host="www.facebook.com",
                  target_url="https://www.facebook.com/tr",
                  method="GET", status=200),
            Event(persona_id=persona_id, ts=ts_list[1], session_id="s1",
                  event_type="cookie_set", summary="写入会话 Cookie",
                  evidence_ref="pcap:shard0#2",
                  page_url="https://example.com/page",
                  target_host="example.com"),
            Event(persona_id=persona_id, ts=ts_list[2], session_id="s1",
                  event_type="api_call", summary="调用 canvas readback",
                  evidence_ref="hook:canvas#3",
                  page_url=None, actor_script="https://cdn.x.com/a.js"),
        ])
    finally:
        conn.close()
    return str(db_path), ts_list


def test_events_mapping_and_filters(client):
    pid = _create(client)["id"]
    _, ts_list = _seed_events(pid)

    r = client.get(f"/api/personas/{pid}/events")
    assert r.status_code == 200
    events = r.json()
    assert len(events) == 3
    # 时间倒序
    assert [e["ts"] for e in events] == sorted(
        [e["ts"] for e in events], reverse=True)
    e0 = events[0]
    # 10 字段契约（v0.2 增 engineTags）
    assert set(e0) == {"id", "ts", "personaId", "type", "pageHost",
                       "targetHost", "summary", "alertLevel", "engineTags",
                       "detail"}
    # 观测层 engine_tags 恒 "[]" → 解析为空数组
    assert e0["engineTags"] == []
    assert e0["personaId"] == pid
    assert e0["type"] == "request"
    assert e0["pageHost"] == "example.com"
    assert e0["targetHost"] == "www.facebook.com"
    assert e0["alertLevel"] == 0
    # ts：Unix 毫秒 → ISO8601 秒（东八区）
    expect_ts = datetime.fromtimestamp(ts_list[0] / 1000, _TZ_CN).isoformat(
        timespec="seconds")
    assert e0["ts"] == expect_ts
    # detail 平铺（None→""，int→str）
    assert e0["detail"]["status"] == "200"
    assert e0["detail"]["method"] == "GET"
    assert e0["detail"]["decrypt_state"] == "full"
    assert e0["detail"]["engine_tags"] == "[]"
    assert e0["detail"]["evidence_ref"] == "pcap:shard0#1"
    # page_url 为 None 的事件 → pageHost ""，detail.page_url ""
    e2 = [e for e in events if e["type"] == "api_call"][0]
    assert e2["pageHost"] == ""
    assert e2["detail"]["page_url"] == ""
    assert e2["targetHost"] == ""

    # type 过滤
    r = client.get(f"/api/personas/{pid}/events", params={"type": "request"})
    assert [e["type"] for e in r.json()] == ["request"]
    # 非法 type → 400
    r = client.get(f"/api/personas/{pid}/events", params={"type": "nope"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_PARAM"

    # limit 过滤
    r = client.get(f"/api/personas/{pid}/events", params={"limit": 1})
    assert len(r.json()) == 1
    # limit=0 → 400
    r = client.get(f"/api/personas/{pid}/events", params={"limit": 0})
    assert r.status_code == 400
    # limit>1000 → 400
    r = client.get(f"/api/personas/{pid}/events", params={"limit": 1001})
    assert r.status_code == 400

    # q 过滤（大小写不敏感，匹配 pageHost/targetHost/summary）
    r = client.get(f"/api/personas/{pid}/events", params={"q": "facebook"})
    assert len(r.json()) == 1
    assert r.json()[0]["type"] == "request"
    r = client.get(f"/api/personas/{pid}/events", params={"q": "CANVAS"})
    assert [e["type"] for e in r.json()] == ["api_call"]
    r = client.get(f"/api/personas/{pid}/events", params={"q": "不存在"})
    assert r.json() == []

    # todayMinutes：当天东八区事件首末 ts 跨度分钟数
    today = datetime.now(_TZ_CN).date()
    todays = [t for t in ts_list
              if datetime.fromtimestamp(t / 1000, _TZ_CN).date() == today]
    expected = (max(todays) - min(todays)) // 60_000 if todays else 0
    persona = client.get(f"/api/personas/{pid}").json()
    assert persona["todayMinutes"] == expected


def test_events_persona_not_found_404(client):
    r = client.get("/api/personas/p_nonexistent_xx/events")
    assert r.status_code == 404


def _engine_writeback(persona_id: str, *, engine_tags: str,
                      alert_level: int = 0) -> None:
    """模拟判别引擎回写（回写权属引擎，观测层 Event 校验不放行非零/标签注入）。"""
    db_path = tishen_home() / "events" / f"{persona_id}.db"
    conn = connect(db_path)
    try:
        conn.execute("UPDATE events SET engine_tags = ?, alert_level = ?",
                     (engine_tags, alert_level))
        conn.commit()
    finally:
        conn.close()


def test_events_engine_tags_parsed_and_bad_json(client):
    """v0.2：ObservEvent.engineTags——合法 JSON 解析为数组，非法 JSON 降级空数组。"""
    pid = _create(client)["id"]
    _seed_events(pid)
    tags = ["e2:easyprivacy:1234", "e1:entity:Google",
            "alert:L3:mining", "mining.payload_confirmed"]
    _engine_writeback(pid, engine_tags=json.dumps(tags, ensure_ascii=False))
    events = client.get(f"/api/personas/{pid}/events").json()
    assert len(events) == 3
    for e in events:
        assert e["engineTags"] == tags
    # detail 中 engine_tags 仍是平铺原文字符串（两处并存，各司其职）
    assert json.loads(events[0]["detail"]["engine_tags"]) == tags

    # 非法 JSON → 空数组，不报错
    _engine_writeback(pid, engine_tags="{不是合法JSON")
    events = client.get(f"/api/personas/{pid}/events").json()
    assert all(e["engineTags"] == [] for e in events)
    # JSON 合法但非数组 → 同样降级空数组
    _engine_writeback(pid, engine_tags='"e2:easyprivacy:1234"')
    events = client.get(f"/api/personas/{pid}/events").json()
    assert all(e["engineTags"] == [] for e in events)


def test_alerts_engine_tags_and_bad_json(client):
    """v0.2：Alert.engineTags——与源事件同源解析；坏数据降级空数组。"""
    pid = _create(client)["id"]
    _seed_events(pid)
    tags = ["e1:entity:CoinHive", "alert:L3:mining"]
    _engine_writeback(pid, engine_tags=json.dumps(tags, ensure_ascii=False),
                      alert_level=3)
    r = client.get("/api/alerts")
    assert r.status_code == 200
    alerts = r.json()
    assert len(alerts) == 3
    for a in alerts:
        assert a["level"] == 3
        assert a["engineTags"] == tags
    # ack 响应同样携带解析后的 engineTags
    r = client.post(f"/api/alerts/{alerts[0]['id']}/ack")
    assert r.status_code == 200
    assert r.json()["engineTags"] == tags
    assert r.json()["acknowledged"] is True

    # 坏 JSON → 告警仍在，engineTags 空数组
    _engine_writeback(pid, engine_tags="[[破损", alert_level=2)
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 3
    assert all(a["engineTags"] == [] for a in alerts)


# ---------------------------------------------------------------------------
# 5. lint：合法 → ok=true 且 checks 恰 10 条；V1 违例 → ok=false 含 V1
# ---------------------------------------------------------------------------

def test_lint_valid_fixture_ok(client):
    # tests/fixtures 合法 persona：登记 + 落盘（valid_cn.yaml 全规则通过）
    persona = load_persona(FIXTURES_DIR / "valid_cn.yaml")
    dump_persona(persona, tishen_home() / "personas" / f"{persona.meta.id}.yaml")
    with StateDB() as db:
        db.add(persona_id=persona.meta.id, name=persona.meta.name,
               region=persona.region.detected_ip_region, state="active",
               chrome_baseline=persona.evolution.baseline_chrome)
    r = client.get(f"/api/personas/{persona.meta.id}/lint")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["errors"] == []
    assert len(data["checks"]) == 10
    assert [c["code"] for c in data["checks"]] == [f"V{i}" for i in range(1, 11)]
    assert all(c["pass"] for c in data["checks"])
    assert all(c["label"] for c in data["checks"])


def test_lint_v1_violation(client):
    # 构造 V1 违例：API 建 CN 替身后把时区改成 America/New_York（属地 CN+纽约时区）
    pid = _create(client)["id"]
    yaml_path = tishen_home() / "personas" / f"{pid}.yaml"
    persona = load_persona(yaml_path)
    persona.region.timezone = "America/New_York"
    dump_persona(persona, yaml_path)

    r = client.get(f"/api/personas/{pid}/lint")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    codes = {e["code"] for e in data["errors"]}
    assert "LINT_V1" in codes
    v1 = [e for e in data["errors"] if e["code"] == "LINT_V1"][0]
    assert v1["field"] and v1["message"]
    checks = {c["code"]: c for c in data["checks"]}
    assert len(checks) == 10
    assert checks["V1"]["pass"] is False
    # 其余规则按实际（未违例 → pass）
    assert checks["V2"]["pass"] is True


# ---------------------------------------------------------------------------
# 6. doctor：items 非空且每项含 name/ok/hint
# ---------------------------------------------------------------------------

def test_doctor_items_shape(client):
    r = client.get("/api/doctor")
    assert r.status_code == 200  # 有失败项仍 200（前端引导页要完整报告）
    items = r.json()["items"]
    assert items
    for it in items:
        assert set(it) == {"name", "ok", "hint"}
        assert isinstance(it["name"], str) and it["name"]
        assert isinstance(it["ok"], bool)
        assert isinstance(it["hint"], str)


# ---------------------------------------------------------------------------
# 7. alerts：空数组（观测层恒 0 属正确行为）；ack 未知 id → 404
# ---------------------------------------------------------------------------

def test_alerts_empty_and_ack_404(client):
    pid = _create(client)["id"]
    _seed_events(pid)  # alert_level 恒 0 → 不派生告警
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json() == []
    r = client.post("/api/alerts/01UNKNOWN_EVENT_ID_00000/ack")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "EVENT_NOT_FOUND"


# ---------------------------------------------------------------------------
# 8. embed：未 start（无 host_port）→ embedUrl == ""
# ---------------------------------------------------------------------------

def test_embed_empty_when_not_started(client):
    pid = _create(client)["id"]
    r = client.get(f"/api/personas/{pid}/embed")
    assert r.status_code == 200
    assert r.json() == {"embedUrl": ""}
    # 不存在的替身 → 404
    r = client.get("/api/personas/p_nonexistent_xx/embed")
    assert r.status_code == 404
