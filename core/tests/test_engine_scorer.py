"""评级闸测试（SPEC-E §4.3 + §10-1 铁律用例）。

decide_level 是评级铁律的唯一实现处：规则逐行对齐 §4.3。
"""

from __future__ import annotations

from tishen.engine.scorer import DECAY_WINDOWS, decide_level

BASE = dict(kind="mining", cross_site_count=0, prev_level=0, prev_inactive=0)


def test_decay_windows_constant():
    """§4.3：DECAY_WINDOWS = 3。"""
    assert DECAY_WINDOWS == 3


def test_iron_rule_single_signal_low_score():
    """§10-1 铁律：单信号且 score<60 → 级别 ≤1。"""
    level, inactive = decide_level(signals=["fp.api_volume"], score=25, **BASE)
    assert level <= 1
    assert inactive == 0


def test_iron_rule_single_api_call_flow():
    """§10-1 铁律：单一 api_call 事件流对应的计分输入 → decide_level ≤1。"""
    # 单一 api_call 在 behavior 层无任何信号；即便保守给 1 信号低分，闸门也 ≤1
    no_signal = decide_level(signals=[], score=0, **BASE)
    assert no_signal[0] <= 1
    weak = decide_level(signals=["mining.pool_domain"], score=20, **BASE)
    assert weak[0] <= 1


def test_no_signal_increments_inactive():
    """§4.3：无信号 inactive=prev+1，未达窗口数级别不降。"""
    level, inactive = decide_level(signals=[], score=0, kind="mining",
                                   cross_site_count=0, prev_level=2,
                                   prev_inactive=1)
    assert (level, inactive) == (2, 2)


def test_decay_after_three_windows():
    """§4.3：连续无信号窗口达 DECAY_WINDOWS → 级别 -1。"""
    level, inactive = decide_level(signals=[], score=0, kind="mining",
                                   cross_site_count=0, prev_level=2,
                                   prev_inactive=2)
    assert (level, inactive) == (1, 3)


def test_decay_floor_zero():
    """§4.3：衰减至 0 为止（max(prev-1, 0)）。"""
    level, _ = decide_level(signals=[], score=0, kind="mining",
                            cross_site_count=0, prev_level=0, prev_inactive=5)
    assert level == 0


def test_two_signals_level_2():
    """§4.3：len(signals)>=2 → target=2。"""
    level, _ = decide_level(signals=["a", "b"], score=10, **BASE)
    assert level == 2


def test_score_60_level_2():
    """§4.3：score>=60（单信号）→ target=2。"""
    level, _ = decide_level(signals=["a"], score=60, **BASE)
    assert level == 2


def test_three_signals_score_80_level_3():
    """§4.3：len(signals)>=3 and score>=80 → target=3（挖矿类无跨站闸门）。"""
    level, _ = decide_level(signals=["a", "b", "c"], score=80, **BASE)
    assert level == 3


def test_fp_cross_site_gate_caps_at_2():
    """§10-1 跨站闸门：指纹类同实体 2 站点 → 封顶 2。"""
    level, _ = decide_level(signals=["a", "b", "c"], score=90,
                            kind="fingerprinting", cross_site_count=2,
                            prev_level=0, prev_inactive=0)
    assert level == 2


def test_fp_cross_site_gate_allows_3():
    """§10-1 跨站闸门：指纹类第 3 站点 → 允许 3。"""
    level, _ = decide_level(signals=["a", "b", "c"], score=90,
                            kind="fingerprinting", cross_site_count=3,
                            prev_level=0, prev_inactive=0)
    assert level == 3


def test_mining_no_cross_site_gate():
    """§4.3：跨站闸门只限 kind=="fingerprinting"，挖矿类不受限。"""
    level, _ = decide_level(signals=["a", "b", "c"], score=90,
                            kind="mining", cross_site_count=1,
                            prev_level=0, prev_inactive=0)
    assert level == 3


def test_same_window_never_downgrades():
    """§4.3：new_level = max(prev_level, target)，同窗口只升不降。"""
    level, inactive = decide_level(signals=["a"], score=10, kind="mining",
                                   cross_site_count=0, prev_level=3,
                                   prev_inactive=0)
    assert (level, inactive) == (3, 0)


def test_signal_resets_inactive():
    """§4.3：有信号窗口 inactive 归零。"""
    _, inactive = decide_level(signals=["a"], score=10, kind="mining",
                               cross_site_count=0, prev_level=1,
                               prev_inactive=2)
    assert inactive == 0
