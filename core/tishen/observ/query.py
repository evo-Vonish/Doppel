"""事件查询接口（SPEC-M2M3 §1.3：`tishen events` 子命令消费）。

契约签名（cli.py 直接 import，不可变）：
    query_events(db_path: str, event_type: str | None = None,
                 limit: int = 50) -> list[dict]
"""

from __future__ import annotations

from .events import EVENT_COLUMNS
from .store import connect


def query_events(db_path: str, event_type: str | None = None,
                 limit: int = 50) -> list[dict]:
    """按时间倒序查事件，返回 dict 列表（键即 §3.1 字段名）。

    - event_type 为 None 时查全部类型；
    - limit ≤ 0 视为契约外用法，抛 ValueError；
    - 库不存在时返回空列表（替身临盆未产出事件属正常态，不报错）。
    """
    if not isinstance(limit, int) or limit <= 0:
        raise ValueError(f"limit 须为正整数，实际为 {limit!r}")
    from pathlib import Path
    if not Path(db_path).exists():
        return []
    conn = connect(db_path)
    try:
        cols = ", ".join(EVENT_COLUMNS)
        if event_type is None:
            cur = conn.execute(
                f"SELECT {cols} FROM events ORDER BY ts DESC, event_id DESC LIMIT ?",
                (limit,))
        else:
            cur = conn.execute(
                f"SELECT {cols} FROM events WHERE event_type = ?"
                " ORDER BY ts DESC, event_id DESC LIMIT ?",
                (event_type, limit))
        return [dict(zip(EVENT_COLUMNS, row)) for row in cur.fetchall()]
    finally:
        conn.close()
