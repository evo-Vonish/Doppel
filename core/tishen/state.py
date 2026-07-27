"""本地状态库（SPEC §7.3 + M2 连接信息列，SPEC-M2M3 §1.3）：SQLite，$TISHEN_HOME/state.db。

表：personas(id, name, region, state, chrome_baseline, created_at, updated_at,
             host_port, neko_password)
M2 新增 host_port（neko 流服务在宿主 loopback 的映射端口）与 neko_password
（创建时随机生成的登录口令，供外壳拼接 embed_url；不落 persona.yaml）。
迁移安全：旧库缺列时 ALTER TABLE 补列（try/except 幂等），不清库不丢数据。
TISHEN_HOME 默认 ~/.tishen。生命周期状态机（M1 方案 §7）：
creating → active ⇄ suspended → (reset → creating) → destroyed
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

# 状态时间戳统一东八区展示（与 sampler 的 created_at 口径一致）
_TZ_CN = timezone(timedelta(hours=8))


def tishen_home() -> Path:
    """$TISHEN_HOME，默认 ~/.tishen。"""
    return Path(os.environ.get("TISHEN_HOME", "~/.tishen")).expanduser()


def _now() -> str:
    return datetime.now(_TZ_CN).isoformat(timespec="seconds")


class StateDB:
    """SQLite 状态库封装。用法：

        db = StateDB()                 # 默认 $TISHEN_HOME/state.db
        db = StateDB(path=tmp_path)    # 测试注入
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else tishen_home() / "state.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS personas (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                region          TEXT NOT NULL,
                state           TEXT NOT NULL,
                chrome_baseline TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                host_port       INTEGER,
                neko_password   TEXT
            )
            """
        )
        # M2 迁移：旧库（M1 建的）缺 host_port/neko_password 两列，逐列补齐；
        # 列已存在时 sqlite 抛 OperationalError，吞掉即幂等（不丢既有数据）。
        for ddl in ("ALTER TABLE personas ADD COLUMN host_port INTEGER",
                    "ALTER TABLE personas ADD COLUMN neko_password TEXT"):
            try:
                self._conn.execute(ddl)
            except sqlite3.OperationalError:
                pass
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def add(self, persona_id: str, name: str, region: str, state: str,
            chrome_baseline: str) -> None:
        """登记新替身（create 时调用，初始状态 creating）。"""
        now = _now()
        self._conn.execute(
            "INSERT INTO personas (id, name, region, state, chrome_baseline,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (persona_id, name, region, state, chrome_baseline, now, now),
        )
        self._conn.commit()

    def get(self, persona_id: str) -> dict | None:
        """按 id 查询；不存在返回 None。"""
        row = self._conn.execute(
            "SELECT * FROM personas WHERE id = ?", (persona_id,)).fetchone()
        return dict(row) if row else None

    def list_all(self, include_destroyed: bool = False) -> list[dict]:
        """列出全部替身；默认不含已销毁。"""
        if include_destroyed:
            rows = self._conn.execute(
                "SELECT * FROM personas ORDER BY created_at").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM personas WHERE state != 'destroyed'"
                " ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def update_state(self, persona_id: str, state: str) -> None:
        """更新生命周期状态并刷新 updated_at。"""
        self._conn.execute(
            "UPDATE personas SET state = ?, updated_at = ? WHERE id = ?",
            (state, _now(), persona_id),
        )
        self._conn.commit()

    def update_connection(self, persona_id: str, host_port: int | None = None,
                          neko_password: str | None = None) -> None:
        """记录/更新 M2 连接信息（neko 宿主端口与口令），刷新 updated_at。

        传 None 的字段保持原值（start 既有容器时只刷新端口，不覆盖口令）。
        """
        if host_port is None and neko_password is None:
            return
        sets, params = [], []
        if host_port is not None:
            sets.append("host_port = ?")
            params.append(host_port)
        if neko_password is not None:
            sets.append("neko_password = ?")
            params.append(neko_password)
        sets.append("updated_at = ?")
        params.append(_now())
        params.append(persona_id)
        self._conn.execute(
            f"UPDATE personas SET {', '.join(sets)} WHERE id = ?", params)
        self._conn.commit()
