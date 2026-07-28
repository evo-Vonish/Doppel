"""替身 Tishen M4 · FCR/EDR 结果录入 CLI（SPEC-M4 §4/§5）。

用法：
  # FCR（实战挑战率）：--site 与 --outcome 必填，v3 分数填 --score
  python record_result.py --db probe.db --group T-cold --persona 替身ID \
      --site recaptcha_v3 --outcome score_bucket --score 0.7 --note "第3次"

  # EDR（环境识别）：--dimension 与 --detected 必填
  python record_result.py --db probe.db --group A-native \
      --dimension headless --detected 0 --evidence "areyouheadless 未识别"

纪律：只记录观测结果，被挑战如实记 challenged/blocked，不做任何绕过动作（R10）。
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# 与 collector.py 共用 §4 建表 SQL（同目录模块，不 import core/ 任何内容）
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collector import DDL, GROUP_TAGS  # noqa: E402

FCR_SITES = {"recaptcha_v3", "recaptcha_v2", "turnstile", "managed_challenge"}
FCR_OUTCOMES = {"pass", "challenged", "blocked", "score_bucket"}
EDR_DIMENSIONS = {"headless", "bot", "vm"}


def _now_iso() -> str:
    """ISO8601 秒（UTC），与 §4 recorded_at 口径一致。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fail(msg: str) -> "None":
    print(f"错误：{msg}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tishen M4 FCR/EDR 结果录入")
    parser.add_argument("--db", required=True, help="probe.db 路径")
    parser.add_argument("--group", required=True,
                        help="group_tag：T-cold|T-warm|A-native|B-extension")
    parser.add_argument("--persona", default=None, help="受测组替身 ID（对照组留空）")
    # FCR 参数
    parser.add_argument("--site", help="recaptcha_v3|recaptcha_v2|turnstile|managed_challenge")
    parser.add_argument("--outcome", help="pass|challenged|blocked|score_bucket")
    parser.add_argument("--score", default=None, help="v3 分桶 0.1/0.3/...；其余 null")
    # EDR 参数
    parser.add_argument("--dimension", help="headless|bot|vm")
    parser.add_argument("--detected", type=int, choices=[0, 1],
                        help="1=被识别（坏） 0=通过（好）")
    # 公共
    parser.add_argument("--evidence", default=None, help="EDR 证据说明")
    parser.add_argument("--note", default=None, help="FCR 备注")
    args = parser.parse_args(argv)

    if args.group not in GROUP_TAGS:
        _fail(f"--group 须 ∈ {sorted(GROUP_TAGS)}，实际为 {args.group!r}")

    is_fcr = args.site is not None or args.outcome is not None or args.score is not None
    is_edr = args.dimension is not None or args.detected is not None
    if is_fcr and is_edr:
        _fail("FCR 与 EDR 参数不可混用，请分两次录入。")
    if not is_fcr and not is_edr:
        _fail("缺少结果参数：FCR 需 --site/--outcome，EDR 需 --dimension/--detected。")

    if is_fcr:
        if args.site not in FCR_SITES:
            _fail(f"--site 须 ∈ {sorted(FCR_SITES)}，实际为 {args.site!r}")
        if args.outcome not in FCR_OUTCOMES:
            _fail(f"--outcome 须 ∈ {sorted(FCR_OUTCOMES)}，实际为 {args.outcome!r}")
        # 口径：score 仅 v3 分桶有意义，其余入口须为 null（不编造）
        if args.score is not None and args.site != "recaptcha_v3":
            _fail("--score 仅 recaptcha_v3 可填（v3 分桶），其余入口应为空。")

    if is_edr:
        if args.dimension not in EDR_DIMENSIONS:
            _fail(f"--dimension 须 ∈ {sorted(EDR_DIMENSIONS)}，实际为 {args.dimension!r}")
        if args.detected is None:
            _fail("EDR 录入须给 --detected 0|1。")

    recorded_at = _now_iso()
    with sqlite3.connect(args.db) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(DDL)  # 幂等建表
        if is_fcr:
            cur = conn.execute(
                "INSERT INTO fcr_results"
                " (group_tag, persona_id, site, outcome, score, recorded_at, note)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (args.group, args.persona, args.site, args.outcome,
                 args.score, recorded_at, args.note),
            )
            print(f"FCR 已录入 id={cur.lastrowid}：{args.site} "
                  f"{args.group} outcome={args.outcome} score={args.score}")
        else:
            cur = conn.execute(
                "INSERT INTO edr_results"
                " (group_tag, persona_id, dimension, detected, evidence, recorded_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (args.group, args.persona, args.dimension, args.detected,
                 args.evidence, recorded_at),
            )
            print(f"EDR 已录入 id={cur.lastrowid}：{args.dimension} "
                  f"{args.group} detected={args.detected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
