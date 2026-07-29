"""评级闸（SPEC-E §4.3）：评级铁律的唯一实现处。

规则逐行对齐 SPEC-E §4.3：
- 无信号：inactive=prev+1；inactive≥DECAY_WINDOWS 则级别 max(prev-1, 0)；
- 有信号：inactive=0；target 初值 0；
  - len(signals)>=2 or score>=60            → target=2
  - len(signals)>=3 and score>=80           → target=3
  - kind=="fingerprinting" 时 target=3 还需 cross_site_count>=3，否则封顶 2
  - 其余有信号情形                         → target=1
- new_level = max(prev_level, target)（同窗口只升不降；衰减路径除外）。

铁律（§0）：单个可疑 API 调用永不触发级别 ≥2——
单信号且 score<60 时 target 恒为 1，由本函数保证。
"""

from __future__ import annotations

DECAY_WINDOWS = 3  # §4.3：连续无信号窗口数，达到则级别 -1（至 0）


def decide_level(*, signals: list[str], score: int, kind: str,
                 cross_site_count: int, prev_level: int,
                 prev_inactive: int) -> tuple[int, int]:
    """§4.3：给定本窗口信号与历史状态，返回 (new_level, new_inactive_windows)。"""
    if not signals:
        # 无信号：inactive=prev+1；inactive≥DECAY_WINDOWS 则 max(prev-1, 0)
        new_inactive = prev_inactive + 1
        if new_inactive >= DECAY_WINDOWS:
            return max(prev_level - 1, 0), new_inactive
        return prev_level, new_inactive

    # 有信号：inactive=0；target = 0
    new_inactive = 0
    target = 0
    # len(signals)>=2 or score>=60 → target=2
    if len(signals) >= 2 or score >= 60:
        target = 2
    # len(signals)>=3 and score>=80 → target=3
    if len(signals) >= 3 and score >= 80:
        target = 3
    # kind=="fingerprinting" 时 target=3 还需 cross_site_count>=3，否则封顶 2
    if kind == "fingerprinting" and target == 3 and cross_site_count < 3:
        target = 2
    # 其余有信号情形 target=1
    if target == 0:
        target = 1
    # new_level = max(prev_level, target)（同窗口只升不降；衰减路径除外）
    return max(prev_level, target), new_inactive
