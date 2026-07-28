"""替身 Tishen M4 · 探针收集器（SPEC-M4 §5 T3）。

FastAPI 独立 app，仅绑定回环 127.0.0.1:8790：

    uvicorn collector:app --host 127.0.0.1 --port 8790
    或： python collector.py [--db probe.db]

端点：
- POST /capture?group_tag=T-cold&persona_id=xxx
    校验 capture_version==1（SPEC-M4 §2），按 §4 建表写 captures；
    随后经占位钩子 run_rgate_if_available 尝试 R-Gate 评估。
- GET /health → {"ok": true}

数据库路径：参数 --db 或环境变量 TISHEN_PROBE_DB，默认脚本同目录 probe.db。
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# §4 group_tag 合法值（注释口径：T-cold|T-warm|A-native|B-extension）
GROUP_TAGS = {"T-cold", "T-warm", "A-native", "B-extension"}

# §4 建表 SQL（一字不改）
DDL = """
CREATE TABLE IF NOT EXISTS captures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_tag TEXT NOT NULL,
  persona_id TEXT,
  entry TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clr_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  capture_id INTEGER NOT NULL REFERENCES captures(id),
  report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fcr_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_tag TEXT NOT NULL, persona_id TEXT,
  site TEXT NOT NULL,
  outcome TEXT NOT NULL,
  score TEXT,
  recorded_at TEXT NOT NULL, note TEXT
);
CREATE TABLE IF NOT EXISTS edr_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_tag TEXT NOT NULL, persona_id TEXT,
  dimension TEXT NOT NULL,
  detected INTEGER NOT NULL,
  evidence TEXT, recorded_at TEXT NOT NULL
);
"""

DEFAULT_DB = str(Path(__file__).resolve().parent / "probe.db")


def _now_iso() -> str:
    """ISO8601 秒（UTC），与 §2 collected_at 口径一致。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def init_db(db_path: str) -> None:
    """建表（幂等）并开启 WAL（§4）。"""
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(DDL)


def insert_capture(db_path: str, group_tag: str, persona_id: str | None,
                   entry: str, captured_at: str, payload: str) -> int:
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO captures (group_tag, persona_id, entry, captured_at, payload)"
            " VALUES (?, ?, ?, ?, ?)",
            (group_tag, persona_id, entry, captured_at, payload),
        )
        return int(cur.lastrowid)


def run_rgate_if_available(db_path: str, capture_id: int, capture: dict) -> str:
    """占位钩子：尝试 import tishen.adversarial.rgate 并评估 capture。

    Coder A 分支（m4-rgate）合并后本钩子自动生效；未合并/导入失败时
    只存不评（capture 已落库，事后可离线补评），返回状态串供调用方回显。
    """
    try:
        from tishen.adversarial import rgate  # noqa: PLC0415  延迟导入
    except ImportError:
        return "unavailable"  # R-Gate 未并入：只存不评
    try:
        report = rgate.run_rgate(capture)
    except Exception:  # 评估异常不阻断入库（采集优先）
        return "error"
    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT INTO clr_reports (capture_id, report) VALUES (?, ?)",
                     (capture_id, json.dumps(report, ensure_ascii=False)))
    return "evaluated"


def _err(status: int, code: str, message: str) -> JSONResponse:
    """统一错误格式（对齐 core/tishen/api 风格：中文消息）。"""
    return JSONResponse(status_code=status,
                        content={"error": {"code": code, "message": message}})


def create_app(db_path: str | None = None) -> FastAPI:
    """app 工厂：测试用临时库路径注入（单测禁起真服，走 TestClient）。"""
    db = db_path or os.environ.get("TISHEN_PROBE_DB") or DEFAULT_DB
    init_db(db)

    app = FastAPI(title="tishen M4 探针收集器", version="0.1.0")
    # CORS 纪律：探针页同机回环来源（8789 静态服 + file:// 打开场景）
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:8789", "http://localhost:8789", "null",
        ],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/capture", status_code=201)
    async def capture(
        request: Request,
        group_tag: str = Query(default="T-cold"),
        persona_id: str | None = Query(default=None),
    ):
        if group_tag not in GROUP_TAGS:
            return _err(400, "INVALID_PARAM",
                        f"group_tag 须 ∈ {sorted(GROUP_TAGS)}，实际为 {group_tag!r}")
        try:
            body = await request.json()
        except Exception:
            return _err(400, "INVALID_JSON", "请求体不是合法 JSON。")
        if not isinstance(body, dict):
            return _err(400, "INVALID_CAPTURE",
                        "capture 须为 JSON 对象（SPEC-M4 §2 FingerprintCapture）。")
        # 版本闸门：只认 capture_version==1，其余一律拒收（不猜、不迁移）
        if body.get("capture_version") != 1:
            return _err(400, "INVALID_CAPTURE_VERSION",
                        "capture_version 须为 1，实际为 "
                        f"{body.get('capture_version')!r}。")

        captured_at = body.get("collected_at")
        if not isinstance(captured_at, str):
            captured_at = _now_iso()  # 页面侧缺失时以收集端时间兜底

        capture_id = insert_capture(db, group_tag, persona_id, "probe",
                                    captured_at,
                                    json.dumps(body, ensure_ascii=False))
        rgate_status = run_rgate_if_available(db, capture_id, body)
        return {"ok": True, "capture_id": capture_id, "rgate": rgate_status}

    return app


app = create_app()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tishen M4 探针收集器（127.0.0.1:8790）")
    parser.add_argument("--db", default=DEFAULT_DB, help="probe.db 路径")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    args = parser.parse_args(argv)

    import uvicorn  # 仅 CLI 入口需要；单测走 TestClient 不依赖

    init_db(args.db)
    os.environ["TISHEN_PROBE_DB"] = args.db
    uvicorn.run(create_app(args.db), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
