#!/usr/bin/env python3
"""Chrome native messaging host（SPEC-E3 §2.2）：扩展 → hook.sock 的唯一桥。

帧协议（§2.2）：stdin 每帧 = 4 字节 little-endian 长度 + JSON UTF-8；
stdout 仅用于回执（{"ok": true} / {"ok": false, "error": "…"}），同帧格式。

消息分派（§1/§2.2）：
- type=event：翻译 hook 扩展字段（sampled=true → summary 前缀 "[sampled] "；
  injected_late=true → 前缀 "[late] "），补 persona_id/session_id（argv 注入），
  其余字段原样，写 hook.sock（每行一条 JSON）；
- type=payload_sample：仅校验 sha256/size/ts 必填，追加写 payload-log（JSONL）；
- 未知 type 或坏样本：回执 error，绝不向扩展抛异常。

零业务逻辑（可审计面最小）；纯标准库；Event schema 零改动——
总线侧校验落库全部由 tishen.observ.hook_bus 负责，本进程只做翻译与转发。
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys

# sampled/late 前缀（§1：Event schema 零改动，证据可溯——前缀进 summary）
SAMPLED_PREFIX = "[sampled] "
LATE_PREFIX = "[late] "


def read_frame(stream) -> dict | None:
    """读一帧：4 字节 LE 长度 + JSON。EOF 返回 None，坏帧抛 ValueError。"""
    head = stream.read(4)
    if not head:
        return None
    if len(head) < 4:
        raise ValueError("帧头不足 4 字节")
    (length,) = struct.unpack("<I", head)
    body = stream.read(length)
    if len(body) < length:
        raise ValueError(f"帧体不足 {length} 字节（EOF）")
    try:
        msg = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"帧体不是合法 JSON：{exc}") from exc
    if not isinstance(msg, dict):
        raise ValueError("帧体须为 JSON 对象")
    return msg


def write_frame(stream, obj: dict) -> None:
    """写一帧回执（stdout 纪律：仅此一种用途）。"""
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    stream.write(struct.pack("<I", len(body)) + body)
    stream.flush()


def translate_event(event: dict, persona_id: str, session_id: str) -> dict:
    """翻译 hook 扩展字段并补身份（§1：sampled/late → summary 前缀）。

    sampled/injected_late 不落 Event 列，翻译后剥除；persona_id/session_id
    由本进程 argv 注入（hook 侧不可信身份声明，一律覆盖）。
    """
    out = dict(event)
    sampled = bool(out.pop("sampled", False))
    late = bool(out.pop("injected_late", False))
    summary = out.get("summary")
    if isinstance(summary, str) and summary:
        if late:
            summary = LATE_PREFIX + summary
        if sampled:
            summary = SAMPLED_PREFIX + summary
        out["summary"] = summary
    out["persona_id"] = persona_id
    out["session_id"] = session_id
    return out


def validate_payload_sample(msg: dict) -> list[str]:
    """payload_sample 必填校验（§2.2）：sha256 非空串、size/ts 非负整数。"""
    errors: list[str] = []
    sha = msg.get("sha256")
    if not isinstance(sha, str) or not sha:
        errors.append(f"sha256 须为非空字符串，实际为 {sha!r}")
    for field in ("size", "ts"):
        v = msg.get(field)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            errors.append(f"{field} 须为非负整数，实际为 {v!r}")
    return errors


class _SocketWriter:
    """hook.sock 惰性连接 + 断线重连（总线重启不拖死 host）。"""

    def __init__(self, path: str) -> None:
        self.path = path
        self._sock: socket.socket | None = None

    def send_line(self, line: str) -> None:
        data = line.encode("utf-8") + b"\n"
        for attempt in range(2):  # 首次失败重连一次再试
            try:
                if self._sock is None:
                    self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self._sock.connect(self.path)
                self._sock.sendall(data)
                return
            except OSError:
                self.close()
                if attempt == 1:
                    raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def handle_message(msg: dict, *, persona_id: str, session_id: str,
                   writer: _SocketWriter, payload_log: str) -> dict:
    """分派一条消息，返回回执 dict（§2.2 三种分支 + 未知 error）。"""
    mtype = msg.get("type")
    if mtype == "event":
        event = msg.get("event")
        if not isinstance(event, dict):
            return {"ok": False, "error": "event 字段缺失或不是对象"}
        out = translate_event(event, persona_id, session_id)
        try:
            # 总线协议与 §1 页面协议同构（{v,type,event} 包装）——裸事件
            # 会被 hook_bus 按 dropped:type 丢弃（串通冒烟教训）。
            writer.send_line(json.dumps(
                {"v": 1, "type": "event", "event": out}, ensure_ascii=False))
        except OSError as exc:
            return {"ok": False, "error": f"hook.sock 写入失败：{exc}"}
        return {"ok": True}
    if mtype == "payload_sample":
        errors = validate_payload_sample(msg)
        if errors:
            return {"ok": False, "error": "；".join(errors)}
        try:
            with open(payload_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(msg, ensure_ascii=False) + "\n")
        except OSError as exc:
            return {"ok": False, "error": f"payload-log 写入失败：{exc}"}
        return {"ok": True}
    return {"ok": False, "error": f"未知消息类型：{mtype!r}"}


def main(argv: list[str] | None = None) -> None:
    """native messaging 主循环：读帧 → 分派 → 回执，直至 stdin EOF。"""
    parser = argparse.ArgumentParser(
        description="tishen hook native messaging host（SPEC-E3 §2.2）")
    parser.add_argument("--persona-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--socket", required=True, help="hook.sock 路径")
    parser.add_argument("--payload-log", required=True, help="samples.jsonl 路径")
    # Chrome 启动 native host 时会把调用方扩展 origin 作为尾随位置参数。
    # 来源授权已由 manifest.allowed_origins 执行；host 只需接收该参数，避免
    # argparse 在进入帧循环前退出。nargs="?" 仍会拒绝第二个未知位置参数。
    parser.add_argument("origin", nargs="?", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    writer = _SocketWriter(args.socket)
    try:
        while True:
            try:
                msg = read_frame(sys.stdin.buffer)
            except ValueError as exc:
                write_frame(sys.stdout.buffer, {"ok": False, "error": str(exc)})
                continue
            if msg is None:
                break
            receipt = handle_message(msg, persona_id=args.persona_id,
                                     session_id=args.session_id,
                                     writer=writer, payload_log=args.payload_log)
            write_frame(sys.stdout.buffer, receipt)
    finally:
        writer.close()


if __name__ == "__main__":
    main()
