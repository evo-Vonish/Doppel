"""schema 往返 + 结构校验测试（SPEC §1：test_persona.py）。"""

import copy

import pytest
import yaml

from conftest import FIXTURES_DIR

from tishen.persona import load, dump, validate_structure


def _load_valid():
    return load(FIXTURES_DIR / "valid_cn.yaml")


def _mutated_persona(tmp_path, mutate):
    """读 valid_cn.yaml → dict 变异 → 写临时文件 → load。"""
    with (FIXTURES_DIR / "valid_cn.yaml").open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    mutate(data)
    tmp = tmp_path / "mutated.yaml"
    with tmp.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)
    return load(tmp)


# ---------------------------------------------------------------------------
# 往返：load → dump → load 完全一致
# ---------------------------------------------------------------------------

def test_roundtrip(tmp_path):
    p1 = _load_valid()
    out = tmp_path / "roundtrip.yaml"
    dump(p1, out)
    p2 = load(out)
    assert p1 == p2


def test_roundtrip_preserves_all_fields(tmp_path):
    """往返后原始 YAML 的每个字段都在（含中文名与 null proxy）。"""
    p1 = _load_valid()
    out = tmp_path / "roundtrip.yaml"
    dump(p1, out)
    with out.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["meta"]["name"] == "默认替身"
    assert data["proxy"] is None
    assert data["region"]["languages"] == ["zh-CN", "zh", "en-US", "en"]
    assert data["farbling"]["scope"] == ["canvas_readback", "webgl_readback", "audio"]


# ---------------------------------------------------------------------------
# 结构校验：正例
# ---------------------------------------------------------------------------

def test_validate_structure_valid_fixture():
    assert validate_structure(_load_valid()) == []


# ---------------------------------------------------------------------------
# 结构校验：负例（类型 / 枚举 / 格式，不做跨字段一致性——那是 linter 的事）
# ---------------------------------------------------------------------------

def test_version_must_be_1(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d.update(version=2))
    errors = validate_structure(p)
    assert any("version" in e for e in errors)


def test_meta_id_format(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["meta"].update(id="BAD ID"))
    errors = validate_structure(p)
    assert any("meta.id" in e for e in errors)


def test_meta_name_length(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["meta"].update(name="x" * 33))
    errors = validate_structure(p)
    assert any("meta.name" in e for e in errors)


def test_created_at_iso8601(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["meta"].update(created_at="不是时间"))
    errors = validate_structure(p)
    assert any("meta.created_at" in e for e in errors)


def test_languages_first_must_match_locale(tmp_path):
    p = _mutated_persona(
        tmp_path, lambda d: d["region"].update(languages=["en-US", "zh-CN"]))
    errors = validate_structure(p)
    assert any("languages" in e for e in errors)


def test_hardware_concurrency_enum(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["hardware"].update(hardwareConcurrency=3))
    errors = validate_structure(p)
    assert any("hardwareConcurrency" in e for e in errors)


def test_farbling_seed_format(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["farbling"].update(seed="xyz"))
    errors = validate_structure(p)
    assert any("farbling.seed" in e for e in errors)


def test_lifecycle_state_enum(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["lifecycle"].update(state="running"))
    errors = validate_structure(p)
    assert any("lifecycle.state" in e for e in errors)


def test_retain_days_minimum(tmp_path):
    p = _mutated_persona(tmp_path, lambda d: d["storage"].update(retain_days=0))
    errors = validate_structure(p)
    assert any("retain_days" in e for e in errors)


def test_structure_does_not_do_cross_field_checks(tmp_path):
    """跨字段一致性（如 2 核配 16GB）归 linter，结构校验必须放行。"""
    p = _mutated_persona(
        tmp_path, lambda d: d["hardware"].update(hardwareConcurrency=2, deviceMemory=16))
    assert validate_structure(p) == []


def test_load_missing_field_raises(tmp_path):
    with pytest.raises(ValueError, match="缺少必填字段"):
        _mutated_persona(tmp_path, lambda d: d.pop("region"))
