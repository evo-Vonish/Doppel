"""事件 Schema v0.1（M3 方案 §3.1/§3.2）：Event dataclass + 枚举 + ULID。

字段与枚举一字不动照抄 M3 方案第三节：
- decrypt_state ∈ {full, metadata_only, gap}（解密空洞标记，第四节口径）；
- engine_tags 为 JSON 数组字符串，初始为空（"[]"），由判别引擎注入；
- alert_level 恒 0——观测层永不置非零（回写权属判别引擎）；
- ts 采信 pcap 包时间戳（Unix 毫秒），不用本机时钟。

ULID 为本地实现（禁引新依赖）：48 位毫秒时间戳 + 80 位随机数，
Crockford Base32 编码 26 字符，字典序即时间序。
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 枚举（M3 方案 §3.2，一字不动）
# ---------------------------------------------------------------------------

EVENT_TYPES = frozenset({
    # 网络层直接产出
    "request", "response", "redirect", "download", "ws_open", "ws_message",
    # 解密内容解析产出
    "cookie_set", "form_submit",
    # 元数据兜底产出（decrypt_state=metadata_only）
    "dns_query", "tls_handshake",
    # JS hook 层注入
    "storage_write", "api_call", "worker_spawn", "wasm_load", "block_action",
    # 编排层注入
    "visibility_probe",
})

DECRYPT_STATES = frozenset({"full", "metadata_only", "gap"})

# ---------------------------------------------------------------------------
# ULID（本地实现，Crockford Base32）
# ---------------------------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(ts_ms: int | None = None) -> str:
    """生成 ULID 字符串（26 字符）。ts_ms 缺省取当前 Unix 毫秒。"""
    if ts_ms is None:
        ts_ms = time.time_ns() // 1_000_000
    if not (0 <= ts_ms < 1 << 48):
        raise ValueError(f"ULID 时间戳超出 48 位范围：{ts_ms!r}")
    # 高 48 位时间 + 低 80 位随机，拼成 128 位整数后编码
    value = (ts_ms << 80) | secrets.randbits(80)
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


# ---------------------------------------------------------------------------
# Event dataclass（字段与 M3 方案 §3.1 一一对应）
# ---------------------------------------------------------------------------

@dataclass
class Event:
    persona_id: str                       # 替身 id（与 persona.yaml meta.id 一致）
    ts: int                               # Unix 毫秒（采信 pcap 包时间戳）
    session_id: str                       # 浏览会话 id（容器启动一次 = 一个会话）
    event_type: str                       # 枚举见 EVENT_TYPES
    summary: str                          # 人类可读一句话
    evidence_ref: str                     # pcap:分片名#帧号 或 payload:加密文件名
    page_url: str | None = None           # 事件发生时所在页面 URL（顶层文档）
    page_id: str | None = None            # 页面实例 id
    frame: str | None = None              # top / iframe（含 iframe 源）
    actor_script: str | None = None       # 脚本归因（网络层不可归因时 None）
    target_host: str | None = None        # 目标域名
    target_url: str | None = None         # 完整 URL（响应体不入此字段）
    method: str | None = None             # request/response 类事件专用
    status: int | None = None             # request/response 类事件专用
    decrypt_state: str = "full"           # full / metadata_only / gap
    engine_tags: str = "[]"               # JSON 数组字符串，判别引擎注入，初始为空
    alert_level: int = 0                  # 0–3，观测层恒 0，回写权属判别引擎
    event_id: str = field(default_factory=ulid)  # ULID，时间有序

    def validate(self) -> list[str]:
        """结构校验（persona.py 风格）：返回中文错误列表，空列表为合法。"""
        errors: list[str] = []

        def err(field_path: str, msg: str) -> None:
            errors.append(f"{field_path}: {msg}")

        if not isinstance(self.event_id, str) or len(self.event_id) != 26:
            err("event_id", f"须为 26 字符 ULID，实际为 {self.event_id!r}")
        if not isinstance(self.persona_id, str) or not self.persona_id:
            err("persona_id", f"须为非空字符串，实际为 {self.persona_id!r}")
        if not isinstance(self.ts, int) or isinstance(self.ts, bool) or self.ts < 0:
            err("ts", f"须为非负整数（Unix 毫秒），实际为 {self.ts!r}")
        if not isinstance(self.session_id, str) or not self.session_id:
            err("session_id", f"须为非空字符串，实际为 {self.session_id!r}")
        if self.event_type not in EVENT_TYPES:
            err("event_type", f"须 ∈ {sorted(EVENT_TYPES)}，实际为 {self.event_type!r}")
        if not isinstance(self.summary, str):
            err("summary", f"须为字符串，实际为 {self.summary!r}")
        if not isinstance(self.evidence_ref, str):
            err("evidence_ref", f"须为字符串，实际为 {self.evidence_ref!r}")
        if self.decrypt_state not in DECRYPT_STATES:
            err("decrypt_state",
                f"须 ∈ {sorted(DECRYPT_STATES)}，实际为 {self.decrypt_state!r}")
        # engine_tags：必须是合法 JSON 数组
        if not isinstance(self.engine_tags, str):
            err("engine_tags", f"须为 JSON 数组字符串，实际为 {self.engine_tags!r}")
        else:
            try:
                tags = json.loads(self.engine_tags)
                if not isinstance(tags, list):
                    err("engine_tags", f"须为 JSON 数组，实际解析为 {type(tags).__name__}")
            except json.JSONDecodeError:
                err("engine_tags", f"不是合法 JSON：{self.engine_tags!r}")
        # alert_level：观测层纪律——永不置非零
        if not isinstance(self.alert_level, int) or isinstance(self.alert_level, bool) \
                or self.alert_level != 0:
            err("alert_level",
                f"观测层恒为 0（回写权属判别引擎），实际为 {self.alert_level!r}")
        return errors

    def to_row(self) -> tuple:
        """按 store.py 表结构顺序输出插入元组（列序与 §3.1 字段表一致）。"""
        return (
            self.event_id, self.persona_id, self.ts, self.session_id,
            self.event_type, self.page_url, self.page_id, self.frame,
            self.actor_script, self.target_host, self.target_url,
            self.method, self.status, self.summary, self.evidence_ref,
            self.decrypt_state, self.engine_tags, self.alert_level,
        )


# store.py 的列名与 to_row() 顺序的唯一事实源
EVENT_COLUMNS = (
    "event_id", "persona_id", "ts", "session_id", "event_type",
    "page_url", "page_id", "frame", "actor_script",
    "target_host", "target_url", "method", "status",
    "summary", "evidence_ref", "decrypt_state", "engine_tags", "alert_level",
)


def event_from_row(row) -> Event:
    """SQLite 行 → Event（供需要对象形态的消费方使用）。"""
    data = dict(zip(EVENT_COLUMNS, row))
    return Event(**data)


def make_gap_event(*, persona_id: str, session_id: str, ts: int,
                   summary: str, evidence_ref: str,
                   target_host: str | None = None) -> Event:
    """构造 gap 占位事件（M3 方案第四节：不隐藏不脑补）。

    event_type 用 tls_handshake——整段缺口的占位只能是元数据级事件，
    语义由 decrypt_state=gap 与 summary 共同标注，绝不冒充内容级事件。
    """
    return Event(
        persona_id=persona_id, ts=ts, session_id=session_id,
        event_type="tls_handshake", summary=summary, evidence_ref=evidence_ref,
        target_host=target_host, decrypt_state="gap",
    )
