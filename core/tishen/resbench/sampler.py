"""R1 资源采样器（SPEC-M5 §3）：docker stats 单行 JSON 解析 + 周期采样落 resbench.db。

口径（M5 方案 §一）：单活跃替身容器总内存（docker stats MEM USAGE，含 X/桌面/neko
流层/Chrome/fcitx5/观测守护全部进程）与 CPU %（相对全部核的百分比），分场景测量。

纪律（SPEC-M5 §0/§3）：
- 解析层 parse_stats_json 为纯函数可单测；docker 调用全部走可注入 stats_provider
  （默认 docker CLI `docker stats --no-stream --format '{{json .}}'`），单测不依赖 docker；
- 错误纪律：解析失败抛 ValueError、docker 不可用/容器不存在抛 RuntimeError，中文消息；
- 落库 Schema 见 SPEC-M5 §2（一字不动），WAL 模式；
- sample_loop 单次失败记 runs.note 追加行，不中断循环。
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

# resbench.db Schema（SPEC-M5 §2，一字不动——跨 Coder 集成全靠它）
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario TEXT NOT NULL,          -- idle_5tab|video_play|stream_encode|boot|sleep
  loadset_version TEXT,            -- LOADSET-v1
  image_version TEXT,              -- 替身镜像 tag
  started_at TEXT NOT NULL,        -- ISO8601 秒
  note TEXT
);
CREATE TABLE IF NOT EXISTS samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  ts TEXT NOT NULL,                -- ISO8601 秒
  mem_bytes INTEGER NOT NULL,
  mem_limit_bytes INTEGER,         -- docker 限额（无则 null）
  cpu_pct REAL NOT NULL            -- 相对全部核的百分比
);
CREATE TABLE IF NOT EXISTS boots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER REFERENCES runs(id),
  boot_mode TEXT NOT NULL,         -- cold-create|cold-start|warm-resume
  total_ms INTEGER,                -- 全程（可空：部分段缺失时不编造总和）
  recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boot_segments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  boot_id INTEGER NOT NULL REFERENCES boots(id),
  segment TEXT NOT NULL,           -- §5 段名枚举
  elapsed_ms INTEGER NOT NULL      -- 从 entrypoint 启动起的累计毫秒
);
CREATE TABLE IF NOT EXISTS fidelity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER REFERENCES runs(id),
  sleep_mode TEXT NOT NULL,        -- pause|stop|checkpoint
  item TEXT NOT NULL,              -- §6 清单 item id
  pass INTEGER NOT NULL,           -- 1 通过 / 0 失败
  evidence TEXT,                   -- 实际值/说明（人工确认项注明 "manual:" 前缀）
  checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

# MemUsage 单位（IEC 1024 进制，SPEC-M5 §3 要求 KiB/MiB/GiB；B/TiB 顺带兼容）
_IEC_UNITS = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}

# "123.4MiB" 形（数值 + 单位，允许间空白）
_MEM_VALUE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)$")


def _now_iso() -> str:
    """当前时刻 ISO8601 秒（UTC，samples.ts / runs.started_at 口径）。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_mem_value(text: str) -> int:
    """"123.4MiB" → 字节 int；非法抛 ValueError（中文）。"""
    m = _MEM_VALUE_RE.match(text.strip())
    if m is None:
        raise ValueError(f"内存数值格式非法：{text!r}（期望形如 123.4MiB）")
    value, unit = m.group(1), m.group(2)
    if unit not in _IEC_UNITS:
        raise ValueError(f"未知内存单位 {unit!r}（支持 {sorted(_IEC_UNITS)}，IEC 1024 进制）")
    return int(float(value) * _IEC_UNITS[unit])


def parse_stats_json(line: str) -> dict:
    """docker stats --no-stream --format '{{json .}}' 单行 JSON →
    {"mem_bytes": int, "mem_limit_bytes": int|None, "cpu_pct": float}
    - MemUsage 形如 "123.4MiB / 2GiB"：解析 KiB/MiB/GiB（IEC 1024 进制），无 "/" 段则 limit=None
    - CPUPerc 形如 "12.34%" → float；解析失败抛 ValueError（中文消息）"""
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"docker stats 输出不是合法 JSON：{line.strip()!r}（{exc}）") from None
    if not isinstance(data, dict):
        raise ValueError(f"docker stats 输出须为 JSON 对象，实际为 {type(data).__name__}")

    mem_usage = data.get("MemUsage")
    if not isinstance(mem_usage, str):
        raise ValueError(f"docker stats JSON 缺少 MemUsage 字符串字段：{line.strip()!r}")
    parts = mem_usage.split("/")
    mem_bytes = _parse_mem_value(parts[0])
    mem_limit_bytes = _parse_mem_value(parts[1]) if len(parts) > 1 else None

    cpu_raw = data.get("CPUPerc")
    if not isinstance(cpu_raw, str):
        raise ValueError(f"docker stats JSON 缺少 CPUPerc 字符串字段：{line.strip()!r}")
    cpu_text = cpu_raw.strip()
    if not cpu_text.endswith("%"):
        raise ValueError(f"CPUPerc 格式非法：{cpu_raw!r}（期望形如 12.34%）")
    try:
        cpu_pct = float(cpu_text[:-1])
    except ValueError:
        raise ValueError(f"CPUPerc 数值解析失败：{cpu_raw!r}") from None

    return {"mem_bytes": mem_bytes, "mem_limit_bytes": mem_limit_bytes, "cpu_pct": cpu_pct}


def _docker_stats_cli(container: str) -> str:
    """默认 stats_provider：docker CLI 单行 JSON。不可用/容器不存在 → RuntimeError（中文）。"""
    argv = ["docker", "stats", "--no-stream", "--format", "{{json .}}", container]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError("docker CLI 不可用：未找到 docker 命令（采样要求宿主机已安装 Docker）") from None
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "无输出"
        raise RuntimeError(
            f"docker stats 失败（容器 {container!r} 不存在或未运行？rc={proc.returncode}）：{detail}")
    return proc.stdout


def _connect(db_path) -> sqlite3.Connection:
    """打开（必要时创建）resbench.db 并初始化 §2 Schema。WAL 模式。"""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _insert_sample(conn: sqlite3.Connection, run_id: int, parsed: dict) -> None:
    conn.execute(
        "INSERT INTO samples (run_id, ts, mem_bytes, mem_limit_bytes, cpu_pct)"
        " VALUES (?,?,?,?,?)",
        (run_id, _now_iso(), parsed["mem_bytes"], parsed["mem_limit_bytes"], parsed["cpu_pct"]),
    )


def _append_run_note(conn: sqlite3.Connection, run_id: int, text: str) -> None:
    """向 runs.note 追加一行（SPEC-M5 §3：结束/异常标记走 note 追加，不新增列）。"""
    row = conn.execute("SELECT note FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return
    note = row[0]
    note = text if not note else f"{note}\n{text}"
    conn.execute("UPDATE runs SET note = ? WHERE id = ?", (note, run_id))


def open_run(db_path: str, scenario: str, loadset_version=None,
             image_version=None, note=None) -> int:
    """开一次采样运行：写 runs 行（started_at 取当前 ISO8601 秒），返回 run id。"""
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO runs (scenario, loadset_version, image_version, started_at, note)"
            " VALUES (?,?,?,?,?)",
            (scenario, loadset_version, image_version, _now_iso(), note),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def close_run(db_path: str, run_id: int, note=None) -> None:
    """结束标记：向 runs.note 追加（SPEC-M5 §3，不新增列）。note 缺省记"运行结束@时刻"。"""
    text = note if note is not None else f"运行结束@{_now_iso()}"
    conn = _connect(db_path)
    try:
        _append_run_note(conn, run_id, text)
        conn.commit()
    finally:
        conn.close()


def sample_once(container: str, db_path: str, run_id: int,
                stats_provider=None) -> dict:
    """采一次写 samples；stats_provider(container)->str 可注入（默认走 docker CLI）；
    docker 不可用/容器不存在 → 抛 RuntimeError（中文消息），调用方决定"""
    provider = stats_provider or _docker_stats_cli
    parsed = parse_stats_json(provider(container))
    conn = _connect(db_path)
    try:
        _insert_sample(conn, run_id, parsed)
        conn.commit()
    finally:
        conn.close()
    return parsed


def sample_loop(container: str, db_path: str, run_id: int,
                interval_s: float = 1.0, duration_s: float = 600.0,
                stats_provider=None, sleep=time.sleep) -> int:
    """周期采样写库，返回样本数；sleep 可注入（单测快进）；单次失败记 note 行不中断循环"""
    provider = stats_provider or _docker_stats_cli
    conn = _connect(db_path)
    count = 0
    start = time.monotonic()
    try:
        while time.monotonic() - start < duration_s:
            try:
                parsed = parse_stats_json(provider(container))
            except (RuntimeError, ValueError) as exc:
                # 单次失败不中断：记 runs.note 追加行，继续下一轮
                _append_run_note(conn, run_id, f"采样失败@{_now_iso()}：{exc}")
                conn.commit()
            else:
                _insert_sample(conn, run_id, parsed)
                conn.commit()
                count += 1
            sleep(interval_s)
    finally:
        conn.close()
    return count
