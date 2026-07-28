"""替身 Tishen M4 · creepjs_export 导入 probe.db（SPEC-M4 §4/§5 T2）。

用法：
  python import_export.py --db probe.db --group T-cold --persona 替身ID \
      --file creepjs_export.json

校验 §4 creepjs_export 形状后写入 captures 表（entry="creepjs"）；
字段缺失/null 不补造，原样入库。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
from collector import DDL, GROUP_TAGS  # noqa: E402  同工具链模块复用 §4 SQL

REQUIRED_KEYS = {
    "source": str,
    "creepjs_commit": (str, type(None)),
    "trust_score": (int, float, type(None)),
    "lies": list,
    "resistance": dict,
    "fp_hash": (str, type(None)),
    "raw_summary": dict,
}


def _fail(msg: str) -> "None":
    print(f"错误：{msg}", file=sys.stderr)
    raise SystemExit(2)


def _now_iso() -> str:
    """ISO8601 秒（UTC），与 §4 captured_at 口径一致。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_export(data: object) -> str | None:
    """校验 §4 creepjs_export 必填键与类型；合法返回 None，否则返回中文错误。"""
    if not isinstance(data, dict):
        return "creepjs_export 须为 JSON 对象。"
    for key, types in REQUIRED_KEYS.items():
        if key not in data:
            return f"creepjs_export 缺少必填键 {key!r}（SPEC-M4 §4）。"
        if not isinstance(data[key], types):
            return f"creepjs_export[{key!r}] 类型须为 {types}，实际为 {type(data[key])}。"
    if data["source"] != "creepjs-selfhost":
        return f"source 须为 'creepjs-selfhost'，实际为 {data['source']!r}。"
    for i, lie in enumerate(data["lies"]):
        if not isinstance(lie, dict) or not isinstance(lie.get("name"), str) \
                or not isinstance(lie.get("detail"), str):
            return f"lies[{i}] 须为 {{'name': str, 'detail': str}}。"
    res = data["resistance"]
    if not isinstance(res.get("detected"), bool) or not isinstance(res.get("patterns"), list):
        return "resistance 须为 {'detected': bool, 'patterns': list}。"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tishen M4 creepjs_export 导入 probe.db")
    parser.add_argument("--db", required=True, help="probe.db 路径")
    parser.add_argument("--group", required=True,
                        help="group_tag：T-cold|T-warm|A-native|B-extension")
    parser.add_argument("--persona", default=None, help="受测组替身 ID（对照组留空）")
    parser.add_argument("--file", required=True, help="extract_inpage.js 产出的 JSON")
    args = parser.parse_args(argv)

    if args.group not in GROUP_TAGS:
        _fail(f"--group 须 ∈ {sorted(GROUP_TAGS)}，实际为 {args.group!r}")

    try:
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"文件不存在：{args.file}")
    except json.JSONDecodeError as e:
        _fail(f"文件不是合法 JSON：{e}")

    err = validate_export(data)
    if err:
        _fail(err)

    # captured_at 优先取导出内嵌时间（提取页记录的观测时刻），缺失则兜底当前
    captured_at = data.get("raw_summary", {}).get("collected_at")
    if not isinstance(captured_at, str):
        captured_at = _now_iso()

    with sqlite3.connect(args.db) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(DDL)  # 幂等建表
        cur = conn.execute(
            "INSERT INTO captures (group_tag, persona_id, entry, captured_at, payload)"
            " VALUES (?, ?, 'creepjs', ?, ?)",
            (args.group, args.persona, captured_at,
             json.dumps(data, ensure_ascii=False)),
        )
    print(f"creepjs_export 已入库 captures.id={cur.lastrowid}"
          f"（group={args.group} persona={args.persona} entry=creepjs）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
