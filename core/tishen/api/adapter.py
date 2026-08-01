"""API 桥适配层（SPEC-API §3/§4/§7）：合成逻辑。

职责：
- Persona 合成（StateDB 行 + persona.yaml → 前端 Persona 形状）；
- events.db 路径解析（与 cli.cmd_events 保持一致，勿漂移）；
- ObservEvent 18 字段 dict → 前端 9 字段映射；
- todayMinutes 口径（当天东八区事件首末 ts 跨度分钟数）；
- alerts 派生（alert_level ≥ 1 事件 → Alert）。

数据真实性纪律：任何字段没有真实来源就置空/省略，不编造。
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import cli  # 复用 _embed_url 等私有成员（随 cli 演进需同步）
from ..observ.query import query_events
from ..persona import Persona, load as load_persona
from ..state import tishen_home

# 状态时间戳/事件 ts 统一东八区展示（与 state._now / sampler created_at 口径一致）
_TZ_CN = timezone(timedelta(hours=8))

# alerts/todayMinutes 需要全量事件；query_events 契约要求正整数 limit，
# 取足够大的上限即等价全量拉取（观测库为本地滚动库，量级受 retain_days 约束）。
_FULL_SCAN_LIMIT = 1_000_000


def personas_dir() -> Path:
    """$TISHEN_HOME/personas（与 cli._personas_dir 同路径约定）。"""
    d = tishen_home() / "personas"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_persona_or_none(persona_id: str) -> Persona | None:
    """加载 $TISHEN_HOME/personas/<id>.yaml；缺失或损坏返回 None（不编造字段）。"""
    path = personas_dir() / f"{persona_id}.yaml"
    if not path.exists():
        return None
    try:
        return load_persona(path)
    except ValueError:
        return None


def events_db_path(persona_id: str, persona: Persona | None = None) -> str:
    """解析替身事件库路径——与 cli.cmd_events 路径逻辑保持一致，勿漂移。

    权威路径：M3 daemon 在容器内写 /persona/logs/events/events.db（替身 log 卷），
    宿主侧经 docker 卷目录直读；卷路径不存在时回退 $TISHEN_HOME/events/<id>.db。
    """
    if persona is None:
        persona = load_persona_or_none(persona_id)
    if persona is not None:
        candidate = (Path("/var/lib/docker/volumes") / persona.storage.log_volume
                     / "_data" / "events" / "events.db")
        try:
            if candidate.exists():
                return str(candidate)
        except PermissionError:
            # /var/lib/docker 对非 root 不可读：exists() 抛错而非返回 False
            # （CI/ubuntu runner 与真机普通用户同路径）——按不可用回退。
            pass
    return str(tishen_home() / "events" / f"{persona_id}.db")


def _iso_seconds(ts_ms: int) -> str:
    """Unix 毫秒 → ISO8601 秒（东八区，与 state._now 口径一致）。"""
    return datetime.fromtimestamp(ts_ms / 1000, _TZ_CN).isoformat(timespec="seconds")


def today_minutes(persona_id: str, persona: Persona | None = None) -> int:
    """当天（东八区）事件库首末事件 ts 跨度分钟数（int）。

    SPEC-API §3：max(ts)-min(ts) 毫秒差 // 60000；查询失败/库不存在/无事件 → 0。
    """
    try:
        events = query_events(events_db_path(persona_id, persona),
                              limit=_FULL_SCAN_LIMIT)
    except Exception:
        return 0
    today = datetime.now(_TZ_CN).date()
    ts_list = [e["ts"] for e in events
               if datetime.fromtimestamp(e["ts"] / 1000, _TZ_CN).date() == today]
    if not ts_list:
        return 0
    return (max(ts_list) - min(ts_list)) // 60_000


def compose_persona(rec: dict, persona: Persona) -> dict:
    """StateDB 行 + persona.yaml → 前端 Persona 形状（SPEC-API §3 字段映射）。

    embedUrl/hostPort 无真实来源（None）时省略该键（Optional，不编造）。
    """
    d = persona.display
    out = {
        "id": rec["id"],
        "name": rec["name"],
        "region": rec["region"],
        "state": rec["state"],
        "chromeVersion": rec["chrome_baseline"],
        "createdAt": rec["created_at"],          # ISO8601 字符串原样输出
        "todayMinutes": today_minutes(rec["id"], persona),
        "tz": persona.region.timezone,
        "locale": persona.region.locale,
        "resolution": f"{d.width}×{d.height} @{d.dpr:g}x",   # × = U+00D7
        # v1 口径：只标注透传模式与字符串来源，不编造宿主渲染器字符串
        "gpu": f"宿主 GPU 透传（{persona.hardware.gpu.renderer_string_source}）",
    }
    embed_url = cli._embed_url(rec.get("host_port"), rec.get("neko_password"))
    if embed_url is not None:
        out["embedUrl"] = embed_url
    if rec.get("host_port") is not None:
        out["hostPort"] = rec["host_port"]
    return out


# ---------------------------------------------------------------------------
# §4 ObservEvent 映射（18 字段 dict → 前端 9 字段）
# ---------------------------------------------------------------------------

# detail 平铺字段（None→""，int→str）
_DETAIL_FIELDS = ("session_id", "page_url", "frame", "actor_script",
                  "target_url", "method", "status", "decrypt_state",
                  "engine_tags", "evidence_ref")


def _host_of(url: str | None) -> str:
    """取 URL 的 host；None/非法 → ""。"""
    if not url:
        return ""
    return urllib.parse.urlparse(url).hostname or ""


def parse_engine_tags(raw: str | None) -> list[str]:
    """events.db 的 engine_tags（JSON 数组字符串）→ 字符串列表（v0.2）。

    判别引擎注入的标签形如 "e2:easyprivacy:<rule_id>" / "e1:entity:<实体名>" /
    "alert:L<1|2|3>:<mining|fingerprinting>"。非法 JSON / 非数组 → 空数组，
    不报错（消费侧宽容降级）；元素统一转 str 保证响应形状稳定。
    """
    if not raw:
        return []
    try:
        tags = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(tags, list):
        return []
    return [str(t) for t in tags]


def map_event(e: dict) -> dict:
    """query_events 返回的 18 字段 dict → 前端 ObservEvent 9 字段。"""
    detail = {}
    for key in _DETAIL_FIELDS:
        v = e.get(key)
        detail[key] = "" if v is None else str(v)
    return {
        "id": e["event_id"],
        "ts": _iso_seconds(e["ts"]),
        "personaId": e["persona_id"],
        "type": e["event_type"],
        "pageHost": _host_of(e.get("page_url")),
        "targetHost": e.get("target_host") or "",
        "summary": e["summary"],
        "alertLevel": e["alert_level"],
        "engineTags": parse_engine_tags(e.get("engine_tags")),
        "detail": detail,
    }


def filter_by_q(events: list[dict], q: str) -> list[dict]:
    """大小写不敏感匹配 pageHost/targetHost/summary（API 层内存过滤）。

    query_events 不支持 q——调用方先取 limit×4 条再经本函数过滤再截 limit
    （近似口径：q 命中的条数可能少于库内真实命中数）。
    """
    needle = q.lower()
    return [e for e in events
            if needle in e["pageHost"].lower()
            or needle in e["targetHost"].lower()
            or needle in e["summary"].lower()]


# ---------------------------------------------------------------------------
# §7 Alerts 派生（alert_level ≥ 1 → Alert）
# ---------------------------------------------------------------------------

def derive_alerts(rows: list[dict], acked: set[str]) -> list[dict]:
    """各非 destroyed 替身事件库中 alert_level ≥ 1 的事件 → Alert（ts 倒序）。

    观测层 alert_level 恒 0，判别引擎（M4）上线前返回空数组属正确行为。
    """
    alerts: list[tuple[int, dict]] = []
    for rec in rows:
        try:
            events = query_events(events_db_path(rec["id"]),
                                  limit=_FULL_SCAN_LIMIT)
        except Exception:
            continue
        for e in events:
            if e["alert_level"] >= 1:
                alerts.append((e["ts"], {
                    "id": e["event_id"],
                    "level": e["alert_level"],
                    "title": e["summary"],
                    "personaId": e["persona_id"],
                    "host": e.get("target_host") or "",
                    "evidence": [e["evidence_ref"]],
                    "engineTags": parse_engine_tags(e.get("engine_tags")),
                    "ts": _iso_seconds(e["ts"]),
                    "acknowledged": e["event_id"] in acked,
                }))
    alerts.sort(key=lambda pair: pair[0], reverse=True)
    return [a for _, a in alerts]
