"""sampler 测试（SPEC §1：固定 seed 可复现 + 离线兜底路径）。"""

import random
from dataclasses import asdict

import pytest

import tishen.sampler as sampler
from tishen.linter import (LintContext, lint_persona, COMMON_RESOLUTIONS,
                           HARDWARE_MEMORY_PAIRS, FONT_PACKS_BY_OS)
from tishen.sampler import create_persona, generate_candidates

STABLE = "138.0.7204.50"

# 易变字段：id/created_at 含时间戳与随机缀（卷名派生自 id），farbling.seed
# 恒为 secrets.token_hex(16)（SPEC §4：seed 参数只驱动采样 rng），复现比较时排除。
VOLATILE_PATHS = [("meta", "id"), ("meta", "created_at"),
                  ("storage", "profile_volume"), ("storage", "log_volume"),
                  ("farbling", "seed")]


def _stable_dict(p):
    d = asdict(p)
    for section, key in VOLATILE_PATHS:
        d[section].pop(key, None)
    return d


# ---------------------------------------------------------------------------
# 固定 seed 可复现
# ---------------------------------------------------------------------------

def test_create_persona_reproducible_with_fixed_seed():
    p1 = create_persona("测试替身", "CN", STABLE, seed=42)
    p2 = create_persona("测试替身", "CN", STABLE, seed=42)
    assert _stable_dict(p1) == _stable_dict(p2)


def test_generate_candidates_reproducible_with_fixed_seed():
    c1 = generate_candidates(20, "CN", random.Random(7))
    c2 = generate_candidates(20, "CN", random.Random(7))
    assert c1 == c2


# ---------------------------------------------------------------------------
# 离线兜底路径（无 browserforge）
# ---------------------------------------------------------------------------

def test_offline_fallback_candidates(monkeypatch):
    """强制走 BUNDLED_DISTRIBUTION 兜底：候选全部可过滤出合法组合。"""
    monkeypatch.setattr(sampler, "_HAS_BROWSERFORGE", False)
    candidates = generate_candidates(50, "CN", random.Random(1))
    assert len(candidates) == 50
    valid = [c for c in candidates if sampler._passes_constraints(c, "CN")]
    assert valid, "兜底分布表应能产出通过约束过滤的候选"
    for c in valid:
        assert (c["width"], c["height"]) in COMMON_RESOLUTIONS
        assert c["deviceMemory"] in HARDWARE_MEMORY_PAIRS[c["hardwareConcurrency"]]
        assert c["font_pack"] in FONT_PACKS_BY_OS["linux"]


def test_offline_fallback_create_persona(monkeypatch):
    monkeypatch.setattr(sampler, "_HAS_BROWSERFORGE", False)
    p = create_persona("兜底替身", "JP", STABLE, seed=9)
    assert p.region.detected_ip_region == "JP"
    # 出场门禁复验：零错误
    ctx = LintContext(current_stable_chrome=STABLE, detected_ip_region="JP")
    assert lint_persona(p, ctx) == []


# ---------------------------------------------------------------------------
# create_persona 全流程
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("region", ["CA", "CN", "HK", "TW", "JP", "US", "GB", "DE"])
def test_create_persona_passes_lint_for_all_regions(region):
    p = create_persona("全属地替身", region, STABLE, seed=3)
    ctx = LintContext(current_stable_chrome=STABLE, detected_ip_region=region)
    assert lint_persona(p, ctx) == []
    # schema 全字段填充：结构校验也必须零错误
    from tishen.persona import validate_structure
    assert validate_structure(p) == []


def test_create_persona_ca_defaults_to_vancouver_grid():
    p = create_persona("温哥华替身", "CA", STABLE, seed=3)
    assert p.region.detected_ip_region == "CA"
    assert p.region.timezone == "America/Vancouver"
    assert p.region.locale == "en-CA"
    assert p.region.languages[:2] == ["en-CA", "en"]


def test_create_persona_auto_uses_ip_region():
    p = create_persona("自动替身", "auto", STABLE, ip_region="DE", seed=5)
    assert p.region.detected_ip_region == "DE"
    assert p.meta.note is None


def test_create_persona_auto_defaults_cn_with_note():
    """region=auto 且无实测属地 → 默认 CN 并在 meta 注释（SPEC §4）。"""
    p = create_persona("自动替身", "auto", STABLE, seed=5)
    assert p.region.detected_ip_region == "CN"
    assert p.meta.note and "默认按 CN" in p.meta.note


def test_create_persona_farbling_seed_is_random_per_call():
    """farbling.seed 不受 seed 参数影响，每次调用独立随机。"""
    p1 = create_persona("甲", "CN", STABLE, seed=42)
    p2 = create_persona("甲", "CN", STABLE, seed=42)
    assert p1.farbling.seed != p2.farbling.seed
    assert len(p1.farbling.seed) == 32


def test_create_persona_unknown_region_raises():
    with pytest.raises(ValueError, match="未知属地"):
        create_persona("x", "XX", STABLE, seed=1)
