"""linter V1–V10 测试（SPEC §1：每条 ≥1 正例 + ≥1 负例）。

门禁上下文统一：current_stable_chrome=138.0.7204.50（major 138），属地锚 CN。
invalid_v*.yaml 各自只触发对应规则（SPEC §9.5）。
"""

import copy

import pytest

from conftest import FIXTURES_DIR

from tishen.linter import LintContext, lint_persona
from tishen.persona import load

CTX = LintContext(current_stable_chrome="138.0.7204.50", detected_ip_region="CN")


def _valid():
    return load(FIXTURES_DIR / "valid_cn.yaml")


def _codes(errors):
    return {e.code for e in errors}


# ---------------------------------------------------------------------------
# 总正例：合法 persona 零错误；invalid fixtures 各自仅触发对应规则
# ---------------------------------------------------------------------------

def test_valid_persona_passes_all_rules():
    assert lint_persona(_valid(), CTX) == []


@pytest.mark.parametrize("fixture,code", [
    ("invalid_v1.yaml", "LINT_V1"),
    ("invalid_v2.yaml", "LINT_V2"),
    ("invalid_v4.yaml", "LINT_V4"),
    ("invalid_v5.yaml", "LINT_V5"),
    ("invalid_v9.yaml", "LINT_V9"),
])
def test_invalid_fixtures_trigger_only_their_rule(fixture, code):
    errors = lint_persona(load(FIXTURES_DIR / fixture), CTX)
    assert errors, f"{fixture} 应触发 {code}"
    assert _codes(errors) == {code}


# ---------------------------------------------------------------------------
# V1 属地族一致
# ---------------------------------------------------------------------------

def test_v1_positive_cn_family():
    assert not any(e.code == "LINT_V1" for e in lint_persona(_valid(), CTX))


def test_v1_negative_timezone_mismatch():
    p = _valid()
    p.region.timezone = "America/New_York"
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V1"]
    assert errors and any("时区" in e.message or "timezone" in e.field for e in errors)


def test_v1_negative_language_prefix_mismatch():
    p = _valid()
    p.region.locale = "en-US"
    p.region.languages = ["en-US", "en"]
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V1"]
    # locale 与 languages 首项都背离 CN 族，至少报一条
    assert errors


def test_v1_skipped_when_anchor_is_none():
    """校验期属地锚为 None 时跳过 V1（SPEC §3.1）。"""
    p = _valid()
    p.region.timezone = "America/New_York"
    ctx = LintContext(current_stable_chrome="138.0.7204.50", detected_ip_region=None)
    assert not any(e.code == "LINT_V1" for e in lint_persona(p, ctx))


# ---------------------------------------------------------------------------
# V2 OS 锁定
# ---------------------------------------------------------------------------

def test_v2_positive_linux():
    assert not any(e.code == "LINT_V2" for e in lint_persona(_valid(), CTX))


def test_v2_negative_windows():
    p = _valid()
    p.os.family = "windows"
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V2"]
    assert errors and "linux" in errors[0].message


# ---------------------------------------------------------------------------
# V3 GPU 禁撒谎
# ---------------------------------------------------------------------------

def test_v3_positive_real_gpu():
    assert not any(e.code == "LINT_V3" for e in lint_persona(_valid(), CTX))


@pytest.mark.parametrize("field,value", [
    ("mode", "swiftshader"),
    ("renderer_string_source", "custom"),
])
def test_v3_negative_lying_gpu(field, value):
    p = _valid()
    setattr(p.hardware.gpu, field, value)
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V3"]
    assert errors


# ---------------------------------------------------------------------------
# V4 分辨率真实
# ---------------------------------------------------------------------------

def test_v4_positive_common_resolution():
    assert not any(e.code == "LINT_V4" for e in lint_persona(_valid(), CTX))


def test_v4_negative_weird_resolution():
    p = _valid()
    p.display.width, p.display.height = 1873, 941
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V4"]
    assert errors and "1873" in errors[0].message


def test_v4_negative_weird_dpr():
    p = _valid()
    p.display.dpr = 1.7
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V4"]
    assert errors and any("dpr" in e.field for e in errors)


# ---------------------------------------------------------------------------
# V5 硬件搭配合理
# ---------------------------------------------------------------------------

def test_v5_positive_reasonable_pair():
    assert not any(e.code == "LINT_V5" for e in lint_persona(_valid(), CTX))


def test_v5_negative_2core_16gb():
    p = _valid()
    p.hardware.hardwareConcurrency = 2
    p.hardware.deviceMemory = 16
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V5"]
    assert errors and "2 核" in errors[0].message


def test_v5_negative_unknown_concurrency():
    p = _valid()
    p.hardware.hardwareConcurrency = 3
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V5"]
    assert errors


# ---------------------------------------------------------------------------
# V6 版本新鲜
# ---------------------------------------------------------------------------

def test_v6_positive_fresh_baseline():
    """major 138 对当前 138：通过；落后 1 个版本（137）也允许。"""
    p = _valid()
    assert not any(e.code == "LINT_V6" for e in lint_persona(p, CTX))
    p.evolution.baseline_chrome = "137.0.7000.0"
    assert not any(e.code == "LINT_V6" for e in lint_persona(p, CTX))


def test_v6_negative_stale_baseline():
    p = _valid()
    p.evolution.baseline_chrome = "136.0.6800.0"  # 落后 2 个版本
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V6"]
    assert errors and "落后" in errors[0].message


# ---------------------------------------------------------------------------
# V7 字体包匹配
# ---------------------------------------------------------------------------

def test_v7_positive_matching_pack():
    assert not any(e.code == "LINT_V7" for e in lint_persona(_valid(), CTX))


def test_v7_negative_foreign_pack():
    p = _valid()
    p.fonts.pack = "windows-segoe-standard"
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V7"]
    assert errors and "字体包" in errors[0].message


def test_v7_negative_cjk_without_cjk_context():
    """非 CJK 属地（US）激活 cjk 附加包 → 矛盾。"""
    p = _valid()
    p.region.detected_ip_region = "US"
    p.region.locale = "en-US"
    p.region.timezone = "America/New_York"
    p.region.languages = ["en-US", "en"]
    ctx = LintContext(current_stable_chrome="138.0.7204.50", detected_ip_region="US")
    errors = [e for e in lint_persona(p, ctx) if e.code == "LINT_V7"]
    assert errors and any("fonts.extras" in e.field for e in errors)


# ---------------------------------------------------------------------------
# V8 种子合法
# ---------------------------------------------------------------------------

def test_v8_positive_valid_seed():
    assert not any(e.code == "LINT_V8" for e in lint_persona(_valid(), CTX))


@pytest.mark.parametrize("seed", ["", "xyz", "ABCDEF" * 6, "9f2c4e8a"])
def test_v8_negative_bad_seed(seed):
    p = _valid()
    p.farbling.seed = seed
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V8"]
    assert errors


# ---------------------------------------------------------------------------
# V9 WebRTC 禁泄露
# ---------------------------------------------------------------------------

def test_v9_positive_disable_policy():
    assert not any(e.code == "LINT_V9" for e in lint_persona(_valid(), CTX))


@pytest.mark.parametrize("policy", ["default", "default_public_and_private_interfaces"])
def test_v9_negative_leaky_policy(policy):
    p = _valid()
    p.webrtc.ip_handling_policy = policy
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V9"]
    assert errors and "WebRTC" in errors[0].message


# ---------------------------------------------------------------------------
# V10 代理边界
# ---------------------------------------------------------------------------

def test_v10_positive_null_proxy():
    assert not any(e.code == "LINT_V10" for e in lint_persona(_valid(), CTX))


@pytest.mark.parametrize("proxy", ["socks5://127.0.0.1:1080", "http://proxy.local:8080"])
def test_v10_positive_wellformed_proxy(proxy):
    p = _valid()
    p.proxy = proxy
    assert not any(e.code == "LINT_V10" for e in lint_persona(p, CTX))


@pytest.mark.parametrize("proxy", ["ftp://x:21", "socks5://host", "随便填的"])
def test_v10_negative_malformed_proxy(proxy):
    p = _valid()
    p.proxy = proxy
    errors = [e for e in lint_persona(p, CTX) if e.code == "LINT_V10"]
    assert errors
