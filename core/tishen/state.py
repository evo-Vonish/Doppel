"""本地状态库（SPEC §7.3）：SQLite，$TISHEN_HOME/state.db。

表：personas(id, name, region, state, chrome_baseline, created_at, updated_at)
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
                updated_at      TEXT NOT NULL
            )
            """
        )
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
