"""tshark 批处理解密封装（M3 方案 §2.2：tshark -o tls.keylog_file → -T json）。

职责：
1. run_tshark()：子进程调 tshark，对单个 pcap 分片做 TLS 解密 + HTTP/1.1、
   HTTP/2、DNS、WebSocket 重组，输出 JSON 包列表；
2. packets_to_events()：tshark JSON → Event 流（事件类型见 events.EVENT_TYPES）；
3. extract_handshakes()：从包列表提取 ClientHello 元数据，供 aligner 对齐。

纪律：
- ts 一律采信 frame.time_epoch（pcap 包时间戳），不用本机时钟；
- 解析不出内容时不脑补：元数据层事件 decrypt_state=metadata_only；
- tshark 缺席/失败由调用方（daemon）捕获转 gap 事件，本模块如实抛错。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .aligner import HandshakeRecord
from .events import Event

# 视为下载的响应 Content-Type（另加 Content-Disposition: attachment 判定）
_DOWNLOAD_CONTENT_TYPES = {
    "application/octet-stream", "application/zip", "application/x-xz",
    "application/gzip", "application/pdf", "application/msword",
}


class TsharkError(RuntimeError):
    """tshark 调用或输出解析失败（daemon 捕获后转 gap 事件，不 crash）。"""


# ---------------------------------------------------------------------------
# tshark 子进程
# ---------------------------------------------------------------------------

def run_tshark(pcap_path, keylog_path=None, timeout: int = 300) -> list[dict]:
    """对单个 pcap 分片跑 tshark，返回 JSON 包列表。

    - keylog_path 存在时以 -o tls.keylog_file 注入，启用 TLS/QUIC 解密；
    - 批处理模式（一次一个分片），与"异步解密削峰"架构一致（§7.2）。
    """
    if shutil.which("tshark") is None:
        raise TsharkError("tshark 不在 PATH 中（镜像须预装，Dockerfile L4 层）")
    cmd = ["tshark", "-r", str(pcap_path), "-T", "json"]
    if keylog_path is not None:
        cmd += ["-o", f"tls.keylog_file:{keylog_path}"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise TsharkError(f"tshark 处理超时（>{timeout}s）：{pcap_path}") from e
    if proc.returncode != 0:
        raise TsharkError(
            f"tshark 退出码 {proc.returncode}：{proc.stderr.strip()[:500]}")
    try:
        packets = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        raise TsharkError(f"tshark 输出不是合法 JSON：{e}") from e
    if not isinstance(packets, list):
        raise TsharkError("tshark JSON 顶层不是数组")
    return packets


def load_tshark_json(path) -> list[dict]:
    """从文件载入 tshark JSON（测试与离线回放用）。"""
    with Path(path).open("r", encoding="utf-8") as f:
        packets = json.load(f)
    if not isinstance(packets, list):
        raise TsharkError(f"tshark JSON 顶层不是数组：{path}")
    return packets


# ---------------------------------------------------------------------------
# tshark JSON 取值辅助：兼容扁平键与嵌套结构、单值与数组
# ---------------------------------------------------------------------------

def _flatten(obj, prefix: str = "") -> dict[str, object]:
    """把 tshark 的 layer 对象拍平为 {点分键: 叶子值}（叶子可为 str 或 list）。"""
    flat: dict[str, object] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                flat.update(_flatten(v, key))
            else:
                flat[key] = v
    return flat


def _get(flat: dict, *suffixes: str):
    """按完整键或键尾后缀取首个命中值；值为单元素列表时自动解包。"""
    for suffix in suffixes:
        # 先精确命中
        if suffix in flat:
            value = flat[suffix]
        else:
            value = None
            for k, v in flat.items():
                if k.endswith(suffix):
                    value = v
                    break
        if value is None:
            continue
        if isinstance(value, list):
            if not value:
                continue
            return value[0]
        return value
    return None


def _get_all(flat: dict, *suffixes: str) -> list:
    """取全部命中值（多值头字段用，如多条 Set-Cookie）。"""
    out: list = []
    for suffix in suffixes:
        for k, v in flat.items():
            if k == suffix or k.endswith(suffix):
                if isinstance(v, list):
                    out.extend(v)
                else:
                    out.append(v)
    return out


def _layers(packet: dict) -> dict[str, dict]:
    """取包的分层字典 {层名: 拍平后的键值}。结构异常返回 {}。"""
    try:
        raw = packet["_source"]["layers"]
    except (TypeError, KeyError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {name: _flatten(obj) for name, obj in raw.items() if isinstance(obj, dict)}


def _ts_ms(frame: dict) -> int:
    """frame.time_epoch（秒，字符串浮点）→ Unix 毫秒。采信 pcap 时间戳。"""
    raw = _get(frame, "frame.time_epoch")
    if raw is None:
        return 0
    try:
        return int(float(raw) * 1000)
    except (TypeError, ValueError):
        return 0


def _frame_number(frame: dict) -> int:
    raw = _get(frame, "frame.number")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# 握手元数据提取（供 aligner）
# ---------------------------------------------------------------------------

def extract_handshakes(packets: list[dict]) -> list[HandshakeRecord]:
    """从包列表提取全部 ClientHello（tls.handshake.type == 1）。"""
    records: list[HandshakeRecord] = []
    for packet in packets:
        layers = _layers(packet)
        tls = layers.get("tls") or layers.get("quic")
        if not tls:
            continue
        if _get(tls, "tls.handshake.type") != "1":
            continue
        random_hex = _get(tls, "tls.handshake.random")
        if not random_hex:
            continue
        frame = layers.get("frame", {})
        tcp = layers.get("tcp", {})
        records.append(HandshakeRecord(
            client_random=str(random_hex).lower(),
            sni=_get(tls, "tls.handshake.extensions_server_name",
                     "tls.handshake.extensions.server_name"),
            ts_ms=_ts_ms(frame),
            frame_number=_frame_number(frame),
            stream=_get(tcp, "tcp.stream"),
        ))
    return records


# ---------------------------------------------------------------------------
# 包列表 → Event 流
# ---------------------------------------------------------------------------

def packets_to_events(packets: list[dict], *, persona_id: str, session_id: str,
                      shard: str) -> list[Event]:
    """tshark JSON 包列表 → Event 流。

    映射口径（decrypt_state）：
    - http/http2/websocket 内容可见 → full；
    - dns_query / tls_handshake → metadata_only（元数据兜底，§4.2）；
    - 缺口不在此判定（daemon 依据 aligner 报告与异常路径产出 gap 事件）。
    """
    events: list[Event] = []

    def make(frame: dict, **kw) -> Event:
        fn = _frame_number(frame)
        kw.setdefault("evidence_ref", f"pcap:{shard}#{fn}")
        return Event(persona_id=persona_id, ts=_ts_ms(frame),
                     session_id=session_id, **kw)

    for packet in packets:
        layers = _layers(packet)
        if not layers:
            continue
        frame = layers.get("frame", {})

        # --- DNS（元数据兜底） ---
        dns = layers.get("dns")
        if dns is not None:
            qname = _get(dns, "dns.qry.name")
            if qname:
                events.append(make(
                    frame, event_type="dns_query", target_host=str(qname),
                    summary=f"仅元数据：DNS 查询 {qname}",
                    decrypt_state="metadata_only"))

        # --- TLS ClientHello（SNI/JA4 记录属元数据兜底） ---
        tls = layers.get("tls")
        if tls is not None and _get(tls, "tls.handshake.type") == "1":
            sni = _get(tls, "tls.handshake.extensions_server_name",
                       "tls.handshake.extensions.server_name")
            ja4 = _get(tls, "tls.handshake.ja4")
            summary = f"仅元数据：TLS 握手 SNI={sni or '(无)'}"
            if ja4:
                summary += f" JA4={ja4}"
            events.append(make(
                frame, event_type="tls_handshake",
                target_host=str(sni) if sni else None,
                summary=summary, decrypt_state="metadata_only"))

        # --- HTTP/1.1 ---
        http = layers.get("http")
        if http is not None:
            events.extend(_http1_events(make, frame, http))

        # --- HTTP/2（HPACK 重组后 tshark 给出 headers 视图） ---
        http2 = layers.get("http2")
        if http2 is not None:
            events.extend(_http2_events(make, frame, http2))

        # --- WebSocket 帧 ---
        ws = layers.get("websocket")
        if ws is not None:
            opcode = _get(ws, "websocket.opcode")
            payload_len = _get(ws, "websocket.payload_length",
                               "websocket.payload.len")
            events.append(make(
                frame, event_type="ws_message",
                summary=f"WebSocket 帧 opcode={opcode or '?'} "
                        f"载荷 {payload_len or '?'} 字节"))

    return events


def _http1_events(make, frame: dict, http: dict) -> list[Event]:
    """HTTP/1.1 层 → request/response/redirect/download/cookie_set/form_submit。"""
    events: list[Event] = []
    method = _get(http, "http.request.method")
    status_raw = _get(http, "http.response.code")
    host = _get(http, "http.host")
    full_uri = _get(http, "http.request.full_uri")
    uri = _get(http, "http.request.uri")
    target_url = full_uri or (f"http://{host}{uri}" if host and uri else uri)
    content_type = (_get(http, "http.content_type",
                         "http.content_type_header") or "")
    content_disp = (_get(http, "http.content_disposition") or "")

    if method:
        method_s = str(method)
        events.append(make(
            frame, event_type="request", method=method_s,
            target_host=str(host) if host else None,
            target_url=str(target_url) if target_url else None,
            summary=f"{method_s} {target_url or '(URL 未知)'}"))
        # 表单提交：POST + 表单编码（摘要化记录，字段值不入库）
        if method_s == "POST" and "application/x-www-form-urlencoded" in str(content_type):
            fields = _get_all(http, "urlencoded-form.key", "http.form.key")
            events.append(make(
                frame, event_type="form_submit",
                target_host=str(host) if host else None,
                target_url=str(target_url) if target_url else None,
                summary=f"表单提交至 {target_url or '(URL 未知)'}"
                        f"（字段 {len(fields)} 个，值不落库）"))

    if status_raw is not None:
        try:
            status = int(str(status_raw))
        except ValueError:
            status = None
        location = _get(http, "http.location")
        if status is not None and 300 <= status < 400 and location:
            events.append(make(
                frame, event_type="redirect", status=status,
                target_host=str(host) if host else None,
                target_url=str(location),
                summary=f"重定向 {status} → {location}"))
        else:
            events.append(make(
                frame, event_type="response", status=status,
                target_host=str(host) if host else None,
                target_url=str(target_url) if target_url else None,
                summary=f"响应 {status_raw}"
                        f"{f'（{content_type}）' if content_type else ''}"))
        # 下载判定：attachment 或已知下载类型
        if "attachment" in str(content_disp).lower() \
                or str(content_type).split(";")[0].strip() in _DOWNLOAD_CONTENT_TYPES:
            events.append(make(
                frame, event_type="download", status=status,
                target_host=str(host) if host else None,
                target_url=str(target_url) if target_url else None,
                summary=f"下载 {content_type or '未知类型'}，来源 {target_url or '(URL 未知)'}"))
        # WebSocket 升级
        if status == 101 and "websocket" in str(
                _get(http, "http.upgrade_insecure_requests", "http.upgrade") or "").lower():
            events.append(make(
                frame, event_type="ws_open",
                target_host=str(host) if host else None,
                target_url=str(target_url) if target_url else None,
                summary=f"WebSocket 建连 {target_url or '(URL 未知)'}"))

    # Set-Cookie：出现即产出 cookie_set（值不落库，只记域名/名）
    for cookie in _get_all(http, "http.set_cookie", "http.response.set_cookie"):
        name = str(cookie).split("=", 1)[0].strip()
        events.append(make(
            frame, event_type="cookie_set",
            target_host=str(host) if host else None,
            target_url=str(target_url) if target_url else None,
            summary=f"Set-Cookie：{name}（值不落库），来源 {host or '(主机未知)'}"))
    return events


def _http2_events(make, frame: dict, http2: dict) -> list[Event]:
    """HTTP/2 层 → request/response/redirect/cookie_set（tshark HPACK 重组视图）。"""
    events: list[Event] = []
    method = _get(http2, "http2.headers.method")
    status_raw = _get(http2, "http2.headers.status")
    authority = _get(http2, "http2.headers.authority")
    path = _get(http2, "http2.headers.path")
    scheme = _get(http2, "http2.headers.scheme") or "https"
    target_url = f"{scheme}://{authority}{path}" if authority and path else None

    if method:
        events.append(make(
            frame, event_type="request", method=str(method),
            target_host=str(authority) if authority else None,
            target_url=target_url,
            summary=f"{method} {target_url or '(URL 未知)'}（HTTP/2）"))
    if status_raw is not None:
        try:
            status = int(str(status_raw))
        except ValueError:
            status = None
        location = _get(http2, "http2.headers.location")
        if status is not None and 300 <= status < 400 and location:
            events.append(make(
                frame, event_type="redirect", status=status,
                target_host=str(authority) if authority else None,
                target_url=str(location),
                summary=f"重定向 {status} → {location}（HTTP/2）"))
        else:
            events.append(make(
                frame, event_type="response", status=status,
                target_host=str(authority) if authority else None,
                target_url=target_url,
                summary=f"响应 {status_raw}（HTTP/2）"))
    for cookie in _get_all(http2, "http2.headers.set_cookie"):
        name = str(cookie).split("=", 1)[0].strip()
        events.append(make(
            frame, event_type="cookie_set",
            target_host=str(authority) if authority else None,
            target_url=target_url,
            summary=f"Set-Cookie：{name}（值不落库），来源 {authority or '(主机未知)'}"))
    return events
