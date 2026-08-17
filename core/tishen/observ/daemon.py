"""观测守护主循环（SPEC-M2M3 §2.3 五步，容器内旁路运行）。

单轮流程：
    ① 监视 pcap 环形分片，挑出**已写完的旧分片**（跳过当前活动分片与已处理分片）；
    ② keylog 重载 → ③ 对齐（aligner）→ ④ 解密（tshark 批处理）→
    ⑤ 事件批量落库 → age 加密分片 → 删除明文（明文窗口目标 ≤5 分钟）。

纪律：
- 背压：落后超过 backlog_limit（默认 2）个分片则跳最新分片，
  写 gap 事件标注区间（M3 方案第四节"不隐藏不脑补"）；
- 缺钥会话按 aligner 报告逐条产 gap 事件；丢包/解密失败同样转 gap，继续下一片；
- 任何异常只记录不退出——观测降级绝不可影响链路（原则 6）；
- §7.3 的 monitor_backlog 不属 §3.2 事件枚举，积压情况只写 daemon.log，不入事件库。
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import decrypt, keylog, store
from .aligner import align
from .events import make_gap_event

# 默认定线（M1 §9 目录结构）
DEFAULT_PCAP_DIR = Path("/persona/logs/pcap")
DEFAULT_KEYLOG = Path("/persona/logs/sslkeys/sslkeys.log")
DEFAULT_EVENTS_DIR = Path("/persona/logs/events")
# age 接收方（公钥）：环境变量优先，其次密钥环落盘文件（M1 §9 同一套密钥环）
DEFAULT_AGE_RECIPIENT_FILE = Path("/persona/logs/age/recipient.txt")

# tcpdump 环形分片命名：ring.pcap / ring.pcap0..7 / *.pcapng（-W 追加序号）
SHARD_NAME_RE = re.compile(r"\.pcap(ng)?\d*$")

log = logging.getLogger("tishen.observ.daemon")


def _shard_generation(path: Path) -> str:
    """返回环形槽位的一次写入代际；文件名复用时仍保持唯一。"""
    stat = path.stat()
    return f"{path.name}@{stat.st_mtime_ns}:{stat.st_size}"


def _archive_path(path: Path) -> Path:
    """为一次分片代际生成不可碰撞的 age 归档名。"""
    stat = path.stat()
    return path.with_name(
        f"{path.name}.{stat.st_mtime_ns}-{stat.st_size}.age")


@dataclass
class DaemonConfig:
    persona_id: str                       # 替身 id（事件 persona_id 字段）
    session_id: str                       # 浏览会话 id（容器启动一次 = 一个会话）
    pcap_dir: Path = DEFAULT_PCAP_DIR
    keylog_path: Path = DEFAULT_KEYLOG
    events_dir: Path = DEFAULT_EVENTS_DIR
    retain_days: int = 30                 # persona.storage.retain_days 默认
    backlog_limit: int = 2                # 落后超过 N 个分片则跳最新分片
    poll_interval: float = 30.0           # 轮询间隔（秒）
    encrypt: bool = True                  # 处理后 age 加密并删明文
    age_recipient: str | None = None      # age 公钥；None 时从环境/文件探测

    @property
    def db_path(self) -> Path:
        return self.events_dir / "events.db"


# ---------------------------------------------------------------------------
# 默认实现：tshark 解密 / age 加密（测试可注入替身）
# ---------------------------------------------------------------------------

def default_decrypt_fn(shard: Path, keylog_path: Path) -> list[dict]:
    """默认解密：tshark 批处理（keylog 存在才注入，缺席按仅元数据跑）。"""
    kl = keylog_path if keylog_path.exists() else None
    return decrypt.run_tshark(shard, kl)


def default_encrypt_fn(path: Path, recipient: str) -> Path:
    """默认加密：输出名携带分片代际，避免环形槽位复用时碰撞。"""
    if shutil.which("age") is None:
        raise RuntimeError("age 不在 PATH 中（镜像须预装，Dockerfile L4 层）")
    out = _archive_path(path)
    proc = subprocess.run(
        ["age", "-r", recipient, "-o", str(out), str(path)],
        capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"age 加密失败（rc={proc.returncode}）："
                           f"{proc.stderr.strip()[:300]}")
    return out


def _resolve_age_recipient(config: DaemonConfig) -> str | None:
    """age 接收方探测顺序：配置显式值 → 环境变量 → 密钥环落盘文件。"""
    if config.age_recipient:
        return config.age_recipient
    env = os.environ.get("TISHEN_AGE_RECIPIENT")
    if env:
        return env.strip() or None
    try:
        text = DEFAULT_AGE_RECIPIENT_FILE.read_text(encoding="utf-8").strip()
        return text or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# 守护进程本体
# ---------------------------------------------------------------------------

class ObservDaemon:
    """环形分片批处理守护。decrypt_fn/encrypt_fn 可注入（测试离线驱动）。"""

    def __init__(self, config: DaemonConfig, *, decrypt_fn=None, encrypt_fn=None):
        self.config = config
        self.decrypt_fn = decrypt_fn or default_decrypt_fn
        self.encrypt_fn = encrypt_fn or default_encrypt_fn
        config.events_dir.mkdir(parents=True, exist_ok=True)
        self.conn = store.connect(config.db_path)

    # --- 内部工具 ---

    def _now_ms(self) -> int:
        return time.time_ns() // 1_000_000

    def _gap(self, *, ts: int, summary: str, evidence_ref: str,
             target_host: str | None = None):
        """产 gap 事件并落库（不隐藏不脑补）。"""
        event = make_gap_event(
            persona_id=self.config.persona_id,
            session_id=self.config.session_id, ts=ts,
            summary=summary, evidence_ref=evidence_ref, target_host=target_host)
        store.insert_events(self.conn, [event])

    def _list_shards(self) -> list[Path]:
        """pcap 目录下全部分片，按 mtime 升序（最旧在前）。"""
        try:
            files = [p for p in self.config.pcap_dir.iterdir()
                     if p.is_file() and SHARD_NAME_RE.search(p.name)
                     and not p.name.endswith(".age")]
        except OSError as e:
            log.warning("无法列出 pcap 目录 %s：%s", self.config.pcap_dir, e)
            return []
        return sorted(files, key=lambda p: (p.stat().st_mtime, p.name))

    def _pending_shards(self) -> list[Path]:
        """已写完且未处理的旧分片：排除当前活动分片（mtime 最新者）。"""
        shards = self._list_shards()
        if not shards:
            return []
        active = shards[-1]  # mtime 最新 = tcpdump 正在写的活动分片
        pending = []
        for shard in shards[:-1]:
            if store.is_shard_processed(
                    self.conn, _shard_generation(shard)):
                continue
            pending.append(shard)
        if pending:
            log.info("活动分片 %s 跳过；待处理 %d 片", active.name, len(pending))
        return pending

    def _encrypt_and_shred(self, path: Path, recipient: str | None) -> None:
        """age 加密后删除明文。加密不可用/失败时保留明文并记日志
        （宁可明文窗口超限，不可销毁未加密的证据副本）。"""
        if not self.config.encrypt:
            return
        if not recipient:
            log.warning("age 接收方未配置，跳过加密（明文保留）：%s", path.name)
            return
        try:
            self.encrypt_fn(path, recipient)
        except Exception as e:  # 加密失败不 crash，明文保留
            log.warning("加密失败（明文保留）：%s：%s", path.name, e)
            return
        try:
            path.unlink()
            log.info("已加密并删除明文：%s", path.name)
        except OSError as e:
            log.warning("明文删除失败：%s：%s", path.name, e)

    def _archive_keylog_segment(self, recipient: str | None) -> None:
        """keylog 段加密归档。

        M1 脚手架下 keylog 是 Chrome 热写的单一文件，不能删（删除会让
        Chrome 继续写入已断链的 inode，密钥全丢）。此处只对**已轮转的段**
        （sslkeys.log.* 旁文件）做加密+删明文；活动 keylog 保留原样，
        明文窗口由轮转机制（M1 守护侧）保证 ≤5 分钟。
        """
        if not self.config.encrypt or not recipient:
            return
        keylog = self.config.keylog_path
        try:
            segments = [p for p in keylog.parent.iterdir()
                        if p.is_file() and p.name.startswith(keylog.name + ".")
                        and not p.name.endswith(".age")]
        except OSError:
            return
        for seg in segments:
            self._encrypt_and_shred(seg, recipient)

    # --- 单片处理（§2.3 步骤 ②–⑤） ---

    def process_shard(self, shard: Path) -> dict:
        """处理一个分片：keylog 重载 → 对齐 → 解密 → 落库 → 加密 → 删明文。

        返回 {"events": n, "coverage": float, "status": "ok"|"gap"}。
        任何步骤失败转 gap 事件并继续（不抛出）。
        """
        cfg = self.config
        shard_generation = _shard_generation(shard)
        recipient = _resolve_age_recipient(cfg)
        # ② keylog 重载（每片一载：浏览器持续追加，索引必须新鲜）
        keylog_map = keylog.parse_keylog(cfg.keylog_path)
        try:
            # ④ 解密（tshark 批处理）
            packets = self.decrypt_fn(shard, cfg.keylog_path)
            # ③ 对齐：握手 random ↔ keylog，显式统计缺钥会话
            report = align(decrypt.extract_handshakes(packets), keylog_map)
            events = decrypt.packets_to_events(
                packets, persona_id=cfg.persona_id,
                session_id=cfg.session_id, shard=shard.name)
            # 缺钥会话逐条 gap 标记（完整率口径分母，§4.1）
            for rec in report.no_key:
                events.append(make_gap_event(
                    persona_id=cfg.persona_id, session_id=cfg.session_id,
                    ts=rec.ts_ms or self._now_ms(),
                    summary=f"解密空洞：SNI={rec.sni or '(无)'} 的 TLS 会话缺密钥"
                            "（no_key），内容不可见",
                    evidence_ref=f"pcap:{shard.name}#{rec.frame_number}",
                    target_host=rec.sni))
            # ⑤ 批量落库
            written = store.insert_events(self.conn, events)
            note = (f"覆盖率 {report.matched}/{report.total}；"
                    f"事件 {written} 条")
            store.record_shard(self.conn, shard_generation, "ok", note)
            log.info("分片 %s 处理完成：%s", shard.name, note)
            status = "ok"
            stats = {"events": written, "coverage": report.coverage,
                     "status": status}
        except Exception as e:
            # 解密/解析失败：gap 事件标注后继续，不 crash（原则 6）
            self._gap(ts=self._now_ms(),
                      summary=f"解密失败：分片 {shard.name} 处理异常"
                              f"（{type(e).__name__}），区间内容不可见",
                      evidence_ref=f"pcap:{shard.name}")
            store.record_shard(self.conn, shard_generation, "gap",
                               f"{type(e).__name__}: {e}"[:300])
            log.exception("分片 %s 处理异常（已记 gap，继续）：%s", shard.name, e)
            stats = {"events": 1, "coverage": 0.0, "status": "gap"}
        # ⑤ 后半：加密分片与 keylog 段 → 删明文
        self._encrypt_and_shred(shard, recipient)
        self._archive_keylog_segment(recipient)
        return stats

    # --- 主循环 ---

    def run_once(self) -> dict:
        """单轮循环（§2.3 全五步 + 背压）。返回统计 dict，供测试与日志。"""
        cfg = self.config
        pending = self._pending_shards()
        stats = {"pending": len(pending), "processed": 0,
                 "skipped": 0, "events": 0}
        # 背压（§2.3 步骤 3）：落后超限 → 跳最新分片，gap 事件标注区间
        if len(pending) > cfg.backlog_limit:
            skip = pending[cfg.backlog_limit:]
            pending = pending[:cfg.backlog_limit]
            for shard in skip:
                shard_generation = _shard_generation(shard)
                ts = int(shard.stat().st_mtime * 1000)
                self._gap(
                    ts=ts,
                    summary=f"背压跳片：积压 {len(skip) + cfg.backlog_limit} 片"
                            f"超过上限 {cfg.backlog_limit}，分片 {shard.name}"
                            " 未解密，区间内容不可见",
                    evidence_ref=f"pcap:{shard.name}")
                store.record_shard(
                    self.conn, shard_generation, "gap", "背压跳片")
                self._encrypt_and_shred(shard, _resolve_age_recipient(cfg))
                stats["skipped"] += 1
                stats["events"] += 1
            # §7.3：积压超过 3 批降速落库——此处以日志留痕（monitor_backlog
            # 不属 §3.2 事件枚举，不入事件库）
            log.warning("背压：跳片 %d 片（积压超限）", stats["skipped"])
        for shard in pending:
            result = self.process_shard(shard)
            stats["processed"] += 1
            stats["events"] += result["events"]
        # retain_days 滚动清理（§7.3）
        try:
            store.cleanup(self.conn, cfg.retain_days)
        except Exception as e:
            log.warning("事件库清理失败（不影响主流程）：%s", e)
        return stats

    def run_forever(self) -> None:
        """常驻循环：异常只记录不退出（观测降级不可影响链路，原则 6）。"""
        cfg = self.config
        log.info("观测守护启动：pcap_dir=%s keylog=%s db=%s 轮询 %.1fs",
                 cfg.pcap_dir, cfg.keylog_path, cfg.db_path, cfg.poll_interval)
        while True:
            try:
                self.run_once()
            except Exception:
                log.exception("单轮循环异常（已记录，继续运行）")
            time.sleep(cfg.poll_interval)

    def close(self) -> None:
        self.conn.close()


# ---------------------------------------------------------------------------
# 入口（python3 -m tishen.observ.daemon）
# ---------------------------------------------------------------------------

def _setup_logging(events_dir: Path) -> None:
    """日志双写：daemon.log 文件（§2.3 步骤 4）+ stderr（容器日志采集）。"""
    events_dir.mkdir(parents=True, exist_ok=True)
    handlers = [
        logging.FileHandler(events_dir / "daemon.log", encoding="utf-8"),
        logging.StreamHandler(),
    ]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers, force=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="tishen.observ.daemon", description="替身观测守护：解密 → 结构化 → 落库")
    parser.add_argument("--pcap-dir", default=os.environ.get(
        "TISHEN_PCAP_DIR", str(DEFAULT_PCAP_DIR)))
    parser.add_argument("--keylog", default=os.environ.get(
        "TISHEN_KEYLOG", str(DEFAULT_KEYLOG)))
    parser.add_argument("--events-dir", default=os.environ.get(
        "TISHEN_EVENTS_DIR", str(DEFAULT_EVENTS_DIR)))
    parser.add_argument("--persona-id", default=os.environ.get(
        "TISHEN_PERSONA_ID", "unknown"))
    parser.add_argument("--session-id", default=os.environ.get(
        "TISHEN_SESSION_ID", "unknown"))
    parser.add_argument("--retain-days", type=int, default=int(
        os.environ.get("TISHEN_RETAIN_DAYS", "30")))
    parser.add_argument("--backlog-limit", type=int, default=2)
    parser.add_argument("--poll-interval", type=float, default=30.0)
    parser.add_argument("--no-encrypt", action="store_true",
                        help="调试用：处理后不加密不删明文")
    args = parser.parse_args(argv)

    config = DaemonConfig(
        persona_id=args.persona_id, session_id=args.session_id,
        pcap_dir=Path(args.pcap_dir), keylog_path=Path(args.keylog),
        events_dir=Path(args.events_dir), retain_days=args.retain_days,
        backlog_limit=args.backlog_limit, poll_interval=args.poll_interval,
        encrypt=not args.no_encrypt)
    _setup_logging(config.events_dir)
    daemon = ObservDaemon(config)
    try:
        daemon.run_forever()
    except KeyboardInterrupt:
        log.info("收到中断信号，观测守护退出")
    finally:
        daemon.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
