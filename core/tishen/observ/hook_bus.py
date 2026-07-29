"""JS hook 事件总线（SPEC-E3 §2.1）：Unix socket 收流 → 校验 → insert_events 落库。

链路（SPEC-E3 §0）：
    tishen_native_host.py ──每行一条 JSON──▶ hook.sock ──▶ 本模块 ──▶ events.db

纪律：
- 仅接受 type=event 消息；JSON 坏/未知 type/校验失败分桶丢弃计数
  （dropped:json / dropped:type / dropped:validation），合法事件经
  store.insert_events 落库（批量纪律同 M3 §7.2，每事务 ≤100 条）；
- 背压铁律（SPEC-E3 §2.1）：内部队列满（>max_backlog）新事件直接 drop 并
  累计 dropped_backlog，每 1000 次写一条内部事件留痕
  （event_type=block_action，summary="hook_bus backlog drop N"）；
- socket 文件权限 600，父目录缺失自动建；观测降级永不影响链路；
- evidence_ref 口径：hook 层事件恒为 "hook:tishen_hook.js"（Event schema
  零改动前提下给 hook 事件一个可溯证据位，§1「其余字段按 dataclass 默认」
  中唯一无默认值的必填字段由总线补）。

独立运行：python -m tishen.observ.hook_bus --socket … --events-db …
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import socket
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass, fields
from pathlib import Path

from tishen.observ import store
from tishen.observ.events import Event

# hook 层事件的 evidence_ref 统一口径（见模块 docstring）
HOOK_EVIDENCE_REF = "hook:tishen_hook.js"
# 背压留痕事件的证据位（总线自身簿记，不冒充 hook 事件）
BUS_EVIDENCE_REF = "hook:hook_bus"
# Event dataclass 可接受的消息字段名集合（sampled/injected_late 等 hook 扩展
# 字段由 native host 翻译剥除，总线不认识的字段一律忽略——协议宽容收严落库）
_EVENT_FIELDS = frozenset(f.name for f in fields(Event))


@dataclass
class BusConfig:
    """SPEC-E3 §2.1：总线配置。"""

    socket_path: Path
    events_db: Path
    max_backlog: int = 10_000  # 接收缓冲超此值丢弃并计数（观测降级铁律）


class HookBus:
    """Unix socket STREAM 服务：每连接一线程，入队后由写库线程批量落库。"""

    def __init__(self, config: BusConfig) -> None:
        self.config = config
        # 丢弃分桶计数（§2.1：dropped:json / dropped:type / dropped:validation）
        self.dropped: dict[str, int] = {"json": 0, "type": 0, "validation": 0}
        self.dropped_backlog = 0
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=config.max_backlog)
        self._stop = threading.Event()
        # 写库线程与背压留痕共用；RLock 允许同线程重入（测试可持锁灌队列）
        self._db_lock = threading.RLock()
        # 建库/schema 纪律复用 store.connect；随后以 check_same_thread=False
        # 重开——连接由写库线程与背压留痕（任意连接线程）在 _db_lock 下共用
        store.connect(config.events_db).close()
        self._conn = sqlite3.connect(str(config.events_db),
                                     check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._server: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._writer = threading.Thread(target=self._write_loop, daemon=True,
                                        name="hook-bus-writer")
        self._writer.start()

    # ── 单条处理（测试主入口，§2.1 签名固定）────────────────────────────
    def handle_line(self, line: bytes) -> str:
        """处理一行 JSON 消息，返回 "ok" 或 "drop:<reason>"。

        解析 → 仅接受 type=event → Event 构造 + validate() → 合法入队；
        非法分桶计数；队列满按背压铁律 drop 并留痕。
        """
        try:
            msg = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.dropped["json"] += 1
            return "drop:json"
        if not isinstance(msg, dict) or msg.get("type") != "event":
            self.dropped["type"] += 1
            return "drop:type"
        payload = msg.get("event")
        if not isinstance(payload, dict):
            self.dropped["type"] += 1
            return "drop:type"
        data = {k: v for k, v in payload.items() if k in _EVENT_FIELDS}
        data.setdefault("evidence_ref", HOOK_EVIDENCE_REF)
        try:
            event = Event(**data)
        except TypeError:
            self.dropped["validation"] += 1
            return "drop:validation"
        if event.validate():
            self.dropped["validation"] += 1
            return "drop:validation"
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped_backlog += 1
            if self.dropped_backlog % 1000 == 0:
                self._record_backlog_drop(event)
            return "drop:backlog"
        return "ok"

    def _record_backlog_drop(self, dropped: Event) -> None:
        """每 1000 次背压 drop 写一条内部留痕事件（§2.1，直写绕过满队列）。"""
        trace = Event(
            persona_id=dropped.persona_id or "hook_bus",
            ts=time.time_ns() // 1_000_000,
            session_id=dropped.session_id or "hook_bus",
            event_type="block_action",
            summary=f"hook_bus backlog drop {self.dropped_backlog}",
            evidence_ref=BUS_EVIDENCE_REF,
        )
        with self._db_lock:
            store.insert_events(self._conn, [trace])

    # ── 服务循环 ─────────────────────────────────────────────────────────
    def serve_forever(self) -> None:
        """绑定 socket（权限 600，父目录自动建）并 accept 循环，每连接一线程。"""
        path = Path(self.config.socket_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()  # 清理崩溃残留的旧 socket 文件
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600：仅属主可读写
        server.listen(16)
        server.settimeout(0.2)  # 轮询 _stop，保证 close() 可退出
        self._server = server
        while not self._stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # close() 关掉了 server
            t = threading.Thread(target=self._serve_conn, args=(conn,),
                                 daemon=True, name="hook-bus-conn")
            t.start()
            self._threads.append(t)

    def _serve_conn(self, conn: socket.socket) -> None:
        """按行读取并处理；任何异常只断开该连接，绝不拖垮总线。"""
        try:
            buf = b""
            while not self._stop.is_set():
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line:
                        self.handle_line(line)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _write_loop(self) -> None:
        """写库线程：攒批 ≤100 条一事务（M3 §7.2 批量纪律同 store.BATCH_SIZE）。"""
        while not self._stop.is_set() or not self._queue.empty():
            batch = []
            try:
                batch.append(self._queue.get(timeout=0.1))
            except queue.Empty:
                continue
            while len(batch) < store.BATCH_SIZE:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            with self._db_lock:
                store.insert_events(self._conn, batch)

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """等待队列清空且写库线程处理完在途批次（测试/收尾用）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty():
                time.sleep(0.15)  # 让写库线程收尾在途批次
                return True
            time.sleep(0.02)
        return False

    def close(self) -> None:
        """停服务：关 socket、排空队列落库、关 db 连接。"""
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        self._writer.join(timeout=5)
        with self._db_lock:
            self._conn.close()
        path = Path(self.config.socket_path)
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass


def main(argv: list[str] | None = None) -> None:
    """独立运行入口：python -m tishen.observ.hook_bus --socket … --events-db …"""
    parser = argparse.ArgumentParser(description="JS hook 事件总线（SPEC-E3 §2.1）")
    parser.add_argument("--socket", required=True, help="Unix socket 路径")
    parser.add_argument("--events-db", required=True, help="events.db 路径")
    parser.add_argument("--max-backlog", type=int, default=10_000,
                        help="接收缓冲上限，超出丢弃并计数（默认 10000）")
    args = parser.parse_args(argv)
    bus = HookBus(BusConfig(socket_path=Path(args.socket),
                            events_db=Path(args.events_db),
                            max_backlog=args.max_backlog))
    try:
        bus.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        bus.close()


if __name__ == "__main__":
    main()
