# EVO-1/EVO-2 测试（演化方案 §二数据模型 / §三 drift pack / §四时机门禁）：
# 1) Evolution 扩展字段缺省值与既有 fixture 兼容回归（无新字段 yaml 全取缺省）；
# 2) 结构校验各违例（单调增/channel/delay_model/时机闸门日期/history 条目）；
# 3) check_evolve_gate 四条断言正反面（纯函数，today 显式注入）；
# 4) validate_drift_pack 七组缺失/冻结项缺失/from≥to 等违例；
# 5) CLI evolve 子命令输出（门禁预览文案 + 放行/拒绝分支）。

from __future__ import annotations

import json

import pytest

from tishen import cli
from tishen.evolution import (DRIFT_PACK_GROUPS, DRIFT_PACK_INVARIANTS,
                              build_drift_pack_skeleton, check_evolve_gate,
                              validate_drift_pack)
from tishen.persona import (Evolution, EvolutionSchedule, count_rollbacks,
                            dump as dump_persona, load as load_persona,
                            validate_structure)

from conftest import FIXTURES_DIR

VALID_FIXTURE = FIXTURES_DIR / "valid_cn.yaml"

BASELINE = "138.0.7204.0"
V139 = "139.0.7258.0"
V140 = "140.0.7312.0"
V_UNSIGNED = "141.0.7400.0"  # 版本目录表外（未签发）


def _load_valid():
    return load_persona(VALID_FIXTURE)


def _make_pack(from_ver=BASELINE, to_ver=V139, release_date="2026-08-05"):
    return build_drift_pack_skeleton(from_ver, to_ver, release_date)


def _evolution(current=BASELINE, channel="stable", delay_model="mainstream",
               not_before=None, history=None):
    return Evolution(
        strategy="anchor_chrome_version", baseline_chrome=BASELINE,
        drift_policy="follow_stable_diff", current_chrome=current,
        channel=channel,
        schedule=EvolutionSchedule(delay_model=delay_model,
                                   next_upgrade_not_before=not_before),
        history=history or [],
    )


def _history_entry(from_ver=BASELINE, to_ver=V139,
                   at="2026-08-20T09:30:00+08:00", **extra):
    entry = {"from": from_ver, "to": to_ver, "at": at,
             "stable_release_date": "2026-08-05", "drift_pack": "138→139.v1",
             "clr_after": 0, "diff_audit": "pass"}
    entry.update(extra)
    return entry


# ---------------------------------------------------------------------------
# EVO-1：缺省值与既有 fixture 兼容（§二）
# ---------------------------------------------------------------------------

def test_fixture_loads_with_all_defaults():
    """既有 persona fixture（无新字段）加载后演化扩展字段全取缺省，结构零错误。"""
    p = _load_valid()
    ev = p.evolution
    assert ev.current_chrome == ev.baseline_chrome == BASELINE
    assert ev.channel == "stable"
    assert ev.schedule.delay_model == "mainstream"
    assert ev.schedule.next_upgrade_not_before is None
    assert ev.history == []
    assert validate_structure(p) == []


def test_dump_load_roundtrip_preserves_new_fields(tmp_path):
    """新字段 dump→load 往返无损（含 schedule/history 整块）。"""
    p = _load_valid()
    p.evolution.current_chrome = V139
    p.evolution.channel = "extended_stable"
    p.evolution.schedule.delay_model = "laggard"
    p.evolution.schedule.next_upgrade_not_before = "2026-09-20"
    p.evolution.history.append(_history_entry())
    path = tmp_path / "roundtrip.yaml"
    dump_persona(p, path)
    q = load_persona(path)
    assert q.evolution.current_chrome == V139
    assert q.evolution.channel == "extended_stable"
    assert q.evolution.schedule.delay_model == "laggard"
    assert q.evolution.schedule.next_upgrade_not_before == "2026-09-20"
    assert q.evolution.history == p.evolution.history
    assert validate_structure(q) == []


def test_validate_current_below_baseline_rejected():
    """current_chrome < baseline_chrome 违反单调增语义，结构校验拒绝。"""
    p = _load_valid()
    p.evolution.current_chrome = "137.0.7151.0"
    errors = validate_structure(p)
    assert any("current_chrome" in e and "单调增" in e for e in errors)


def test_validate_version_compare_is_numeric():
    """版本比较走四段数值：138.0.7204.10 > 138.0.7204.2（字符串序会判反）。"""
    p = _load_valid()
    p.evolution.baseline_chrome = "138.0.7204.2"
    p.evolution.current_chrome = "138.0.7204.10"
    assert validate_structure(p) == []


def test_validate_bad_channel_rejected():
    p = _load_valid()
    p.evolution.channel = "beta"
    assert any("evolution.channel" in e for e in validate_structure(p))


def test_validate_bad_delay_model_rejected():
    p = _load_valid()
    p.evolution.schedule.delay_model = "eager"
    assert any("delay_model" in e for e in validate_structure(p))


def test_validate_bad_not_before_date_rejected():
    p = _load_valid()
    p.evolution.schedule.next_upgrade_not_before = "2026-13-40"
    assert any("next_upgrade_not_before" in e for e in validate_structure(p))


def test_validate_history_to_must_exceed_from():
    """history 条目 to<=from 违反单调增（审计链不许编造反向演化）。"""
    p = _load_valid()
    p.evolution.history.append(_history_entry(to_ver=BASELINE))
    errors = validate_structure(p)
    assert any("history[0].to" in e and "to>from" in e for e in errors)


def test_validate_history_at_must_be_iso_seconds():
    p = _load_valid()
    p.evolution.history.append(_history_entry(at="2026-08-20"))
    assert any("history[0].at" in e for e in validate_structure(p))


def test_history_rollback_entry_is_valid_but_counted():
    """rollback=true 条目合法（§七.3 诚实留痕），结构校验放行，计数警告=1。"""
    p = _load_valid()
    p.evolution.history.append(_history_entry(rollback=True))
    assert validate_structure(p) == []
    assert count_rollbacks(p.evolution) == 1


# ---------------------------------------------------------------------------
# EVO-2：时机门禁 check_evolve_gate（§四步骤 0/2，纯函数）
# ---------------------------------------------------------------------------

def test_gate_passes_when_all_assertions_hold():
    ev = _evolution(not_before="2026-08-20")
    ok, reasons = check_evolve_gate(ev, _make_pack(), today="2026-08-20")
    assert ok and reasons == []


def test_gate_rejects_before_not_before():
    ev = _evolution(not_before="2026-08-20")
    ok, reasons = check_evolve_gate(ev, _make_pack(), today="2026-08-19")
    assert not ok and any("时机闸门" in r for r in reasons)


def test_gate_rejects_target_not_above_current():
    ev = _evolution(current=V139)
    ok, reasons = check_evolve_gate(ev, _make_pack(), today="2026-08-20")
    assert not ok and any("单调增" in r for r in reasons)


def test_gate_rejects_before_stable_release_date():
    ev = _evolution(not_before="2026-08-01")
    ok, reasons = check_evolve_gate(ev, _make_pack(), today="2026-08-04")
    assert not ok and any("不超前" in r for r in reasons)


def test_gate_rejects_unsigned_version_pair():
    """版本目录表外=该版本对 drift pack 未签发，硬拒绝（§三）。"""
    ev = _evolution(not_before="2026-08-01")
    pack = _make_pack(to_ver=V_UNSIGNED, release_date="2026-08-20")
    ok, reasons = check_evolve_gate(ev, pack, today="2026-08-20")
    assert not ok and any("未签发" in r for r in reasons)


def test_gate_accepts_persona_object_for_os_check():
    """传 Persona 时 os 字段取自 persona.os.family（本期恒 linux，目录表支持）。"""
    p = _load_valid()
    ok, reasons = check_evolve_gate(p, _make_pack(), today="2026-08-20")
    assert ok and reasons == []


def test_gate_tolerates_explicit_none_schedule():
    """回归：schedule=None（整块缺省）按缺省画像处理——时机闸门不限制，gate 不炸。

    缺省口径（persona.Evolution docstring）：__post_init__ 统一回填 EvolutionSchedule
    缺省实例（delay_model=mainstream、next_upgrade_not_before=None）。
    """
    ev = Evolution(strategy="anchor_chrome_version", baseline_chrome=BASELINE,
                   drift_policy="follow_stable_diff", schedule=None, history=None)
    assert ev.schedule.delay_model == "mainstream"
    assert ev.schedule.next_upgrade_not_before is None
    assert ev.history == []
    ok, reasons = check_evolve_gate(ev, _make_pack(), today="2026-08-20")
    assert ok and reasons == []


def test_load_tolerates_yaml_schedule_null(tmp_path):
    """回归：yaml 显式写 `schedule: null` / `history: null` 也走缺省回填，gate 正常。"""
    import yaml
    data = yaml.safe_load(VALID_FIXTURE.read_text(encoding="utf-8"))
    data["evolution"]["schedule"] = None
    data["evolution"]["history"] = None
    path = tmp_path / "null_schedule.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    p = load_persona(path)
    assert p.evolution.schedule.delay_model == "mainstream"
    assert p.evolution.history == []
    assert validate_structure(p) == []
    ok, reasons = check_evolve_gate(p, _make_pack(), today="2026-08-20")
    assert ok and reasons == []


# ---------------------------------------------------------------------------
# EVO-2：drift pack 校验与生成器骨架（§三）
# ---------------------------------------------------------------------------

def test_validate_drift_pack_skeleton_passes():
    assert validate_drift_pack(_make_pack()) == []


def test_validate_drift_pack_missing_group_rejected():
    pack = _make_pack()
    del pack["groups"]["G-TLS"]
    errors = validate_drift_pack(pack)
    assert any("G-TLS" in e for e in errors)


def test_validate_drift_pack_missing_invariant_rejected():
    pack = _make_pack()
    pack["invariants"].remove("farbling_seed")
    errors = validate_drift_pack(pack)
    assert any("farbling_seed" in e for e in errors)


def test_validate_drift_pack_from_must_precede_to():
    pack = _make_pack()
    pack["from"], pack["to"] = pack["to"], pack["from"]
    assert any("from<to" in e for e in validate_drift_pack(pack))


def test_skeleton_prefills_groups_invariants_and_api_source():
    pack = _make_pack()
    assert sorted(pack["groups"]) == sorted(DRIFT_PACK_GROUPS)
    assert pack["invariants"] == DRIFT_PACK_INVARIANTS
    assert pack["groups"]["G-API"]["source"] == "chromestatus diff"
    # 骨架不编造真值：G-UA/G-TLS 字符串占位为 None
    assert pack["groups"]["G-UA"]["ua_string"] is None
    assert pack["groups"]["G-TLS"]["ja4_expected"] is None


def test_skeleton_rejects_invalid_args():
    with pytest.raises(ValueError):
        build_drift_pack_skeleton(V139, BASELINE, "2026-08-05")  # from>to
    with pytest.raises(ValueError):
        build_drift_pack_skeleton(BASELINE, V139, "2026-02-30")  # 非法日期


# ---------------------------------------------------------------------------
# EVO-2：CLI evolve 子命令（门禁预览，不执行演化）
# ---------------------------------------------------------------------------

@pytest.fixture()
def home(tmp_path, monkeypatch):
    """隔离的 $TISHEN_HOME，并放入一份 persona.yaml。"""
    monkeypatch.setenv("TISHEN_HOME", str(tmp_path))
    personas = tmp_path / "personas"
    personas.mkdir()
    p = _load_valid()
    # 时机闸门设在过去，保证放行分支与真实 today 无关（确定性）
    p.evolution.schedule.next_upgrade_not_before = "2020-01-01"
    dump_persona(p, personas / f"{p.meta.id}.yaml")
    return tmp_path, p.meta.id


def _write_pack(tmp_path, pack) -> str:
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack, ensure_ascii=False), encoding="utf-8")
    return str(path)


def test_cli_evolve_preview_pass(home, capsys):
    tmp_path, pid = home
    # stable_release_date 放过去（目录表行只管 OS×版本组合），保证确定性放行
    pack = _make_pack(release_date="2020-08-05")
    rc = cli.main(["evolve", pid, "--pack", _write_pack(tmp_path, pack)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "演化门禁检查（预览）" in out
    assert "[放行]" in out
    assert f"当前版本 current_chrome  : {BASELINE}" in out
    assert "演化履历 history         : 0 条" in out


def test_cli_evolve_preview_rejected(home, capsys):
    tmp_path, pid = home
    pack = _make_pack(to_ver=V_UNSIGNED, release_date="2020-08-05")
    rc = cli.main(["evolve", pid, "--pack", _write_pack(tmp_path, pack)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "[拒绝]" in out and "未签发" in out


def test_cli_evolve_invalid_pack_rejected(home, capsys):
    tmp_path, pid = home
    pack = _make_pack()
    del pack["groups"]["G-H2"]
    rc = cli.main(["evolve", pid, "--pack", _write_pack(tmp_path, pack)])
    out = capsys.readouterr().out
    assert rc == 1 and "G-H2" in out


def test_cli_evolve_missing_pack_file(home, capsys):
    _, pid = home
    rc = cli.main(["evolve", pid, "--pack", "/nonexistent/pack.json"])
    assert rc == 2
    assert "不存在" in capsys.readouterr().err
