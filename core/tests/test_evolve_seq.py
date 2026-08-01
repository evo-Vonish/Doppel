# EVO-3 测试（演化方案 §四门禁序列编排骨架 + §四-5 diff 审计器）：
# 1) GROUP_FIELDS 七组映射与 SPEC-M4 §2 的 18 顶层键对齐（含 G-ENV 兜底）；
# 2) diff_captures 递归对比：七组归位 / 缺失键算变化 / 采集元数据排除；
# 3) audit_diff 双断言正反（白名单外变化拒 / G-UA 未变拒 / 声明组放行 / 合规通过）；
# 4) run_evolve_sequence：步骤顺序断言（mock hooks 记录调用序）、gate 拒 held、
#    CLR 前置≠0 held、镜像未接入 held 且 history 空、diff 违例 rejected、
#    外部抽样未接入 held、完整 happy path（全 stub 注入）→ evolved + history 落账；
# 5) CLI evolve --execute 输出（stub 步骤「skipped（真机接入后激活）」+ held），
#    及预览默认路径不变回归。

from __future__ import annotations

import copy
import json

import pytest

from tishen import cli
from tishen.evolution import (CAPTURE_METADATA_KEYS, GROUP_FIELDS,
                              G_UA_MUST_CHANGE, audit_diff,
                              build_drift_pack_skeleton, diff_captures,
                              group_of_path)
from tishen.evolve_seq import EvolveHooks, run_evolve_sequence
from tishen.persona import dump as dump_persona, load as load_persona, \
    validate_structure

from conftest import FIXTURES_DIR

VALID_FIXTURE = FIXTURES_DIR / "valid_cn.yaml"

BASELINE = "138.0.7204.0"
V139 = "139.0.7258.0"
TODAY = "2026-08-20"

# SPEC-M4 §2 FingerprintCapture 的 18 个顶层键（diff 审计的数据源）
SPEC_M4_TOP_KEYS = {
    "capture_version", "collected_at", "navigator", "sec_ch_ua", "screen",
    "intl", "webgl", "canvas", "audio", "fonts", "media", "permissions",
    "storage", "webrtc", "cross_reads", "features", "cdp_traces", "tls_assert",
}

SEVEN_GROUPS = ["G-UA", "G-JSVER", "G-API", "G-TLS", "G-H2", "G-REND", "G-ENV"]


def _load_valid():
    p = load_persona(VALID_FIXTURE)
    # 时机闸门放过去，保证 gate 放行分支与真实 today 无关（确定性）
    p.evolution.schedule.next_upgrade_not_before = "2020-01-01"
    return p


def _make_pack(**group_overrides):
    """签发态 pack：G-UA 填真值（版本升级 UA 族必漂移），其余组保持骨架占位。"""
    pack = build_drift_pack_skeleton(BASELINE, V139, "2020-08-05")
    pack["groups"]["G-UA"] = {
        "ua_string": "Mozilla/5.0 … Chrome/139.0.7258.0 …",
        "sec_ch_ua": '"Chromium";v="139"',
        "ua_reduction_kv": "139.0.7258.0",
    }
    for g, decl in group_overrides.items():
        pack["groups"][g] = decl
    return pack


def _capture(ua_ver="138", canvas_hash="c1"):
    """最小合法形态 capture（SPEC-M4 §2 子集；diff 审计不关心字段全集）。"""
    return {
        "capture_version": 1,
        "collected_at": f"2026-08-20T09:00:0{ua_ver[-1]}Z",
        "navigator": {
            "userAgent": f"Mozilla/5.0 … Chrome/{ua_ver}.0.0.0 …",
            "platform": "Linux x86_64",
            "vendor": "Google Inc.",
            "hardwareConcurrency": 8,
        },
        "sec_ch_ua": {"brands": [{"brand": "Chromium", "version": ua_ver}],
                      "mobile": False, "uaFullVersion": f"{ua_ver}.0.0.0"},
        "screen": {"width": 1920, "height": 1080, "devicePixelRatio": 1.0},
        "intl": {"locale": "zh-CN", "timeZone": "Asia/Shanghai"},
        "webgl": {"vendor": "Google Inc.", "renderer": "ANGLE (Intel)"},
        "canvas": {"hash_1": canvas_hash, "hash_2": canvas_hash},
        "audio": {"hash": "a1"},
        "fonts": ["Arial", "Noto Sans CJK SC"],
        "media": {"videoCodecs": ["h264"]},
        "permissions": {"geolocation": "prompt"},
        "storage": {"localStorage": True},
        "webrtc": {"candidates": ["host x.x.x.1"]},
        # 任务契约把 cross_reads 归入 G-ENV（冻结组），故 fixture 中 worker UA
        # 保持恒定——真实演化中 worker UA 会随版本漂移，此张力见交付报告遗留问题
        "cross_reads": {"ua_worker": "… Chrome UA …"},
        "features": {"touchEvent": False, "batteryApi": True},
        "cdp_traces": {"runtimeEnableArtifacts": False},
        "tls_assert": {"ja3": "j3", "ja4": "j4", "source": "tls.peet.ws"},
    }


def _evolved_capture():
    """合规演化后的 capture：仅 G-UA 族（UA 字符串 + Sec-CH-UA）变到 139。"""
    new = _capture(ua_ver="139")
    new["collected_at"] = _capture()["collected_at"]  # 控制变量：仅 UA 族漂移
    return new


# ---------------------------------------------------------------------------
# GROUP_FIELDS 映射表（七组 × SPEC-M4 §2 的 18 键对齐）
# ---------------------------------------------------------------------------

def test_group_fields_seven_groups_complete():
    assert list(GROUP_FIELDS) == SEVEN_GROUPS
    for keys in GROUP_FIELDS.values():
        assert isinstance(keys, frozenset) and keys


def test_group_fields_align_spec_m4_top_keys():
    # 映射键的顶层段必须落在 SPEC-M4 §2 的 18 顶层键内；
    # 唯一例外是 features.js_ 前缀标记（V8 特征扩展预留族，docstring 已注明）
    for keys in GROUP_FIELDS.values():
        for k in keys:
            if k == "features.js_":
                continue
            assert k.split(".")[0] in SPEC_M4_TOP_KEYS, k
    # 全部 16 个非元数据顶层键都能被归组（不丢键；navigator/cdp_traces 走 G-ENV 兜底）
    for top in SPEC_M4_TOP_KEYS - CAPTURE_METADATA_KEYS:
        assert group_of_path(top) in SEVEN_GROUPS


def test_group_of_path_precedence_and_fallback():
    assert group_of_path("navigator.userAgent") == "G-UA"
    assert group_of_path("sec_ch_ua.brands") == "G-UA"
    assert group_of_path("features.js_mathTan") == "G-JSVER"   # 前缀标记族
    assert group_of_path("features.batteryApi") == "G-API"
    assert group_of_path("features") == "G-API"
    assert group_of_path("tls_assert.h2") == "G-H2"            # 最长匹配优先
    assert group_of_path("tls_assert.ja4") == "G-TLS"
    for k in ("canvas.hash_1", "audio.hash", "webgl.renderer", "fonts"):
        assert group_of_path(k) == "G-REND"
    for k in ("screen.width", "intl.timeZone", "webrtc.candidates",
              "cross_reads.ua_worker", "media.videoCodecs",
              "permissions.geolocation", "storage.localStorage"):
        assert group_of_path(k) == "G-ENV"
    # 未覆盖键兜底 G-ENV：navigator 其余子键 / cdp_traces / 未来新增键
    for k in ("navigator.vendor", "navigator.hardwareConcurrency",
              "cdp_traces.runtimeEnableArtifacts", "future_new_key.x"):
        assert group_of_path(k) == "G-ENV"


# ---------------------------------------------------------------------------
# diff_captures（递归对比，按七组返回）
# ---------------------------------------------------------------------------

def test_diff_identical_captures_all_groups_empty():
    diff = diff_captures(_capture(), _capture())
    assert list(diff) == SEVEN_GROUPS
    assert all(v == [] for v in diff.values())


def test_diff_metadata_keys_excluded():
    old, new = _capture(), _capture()
    new["collected_at"] = "2026-08-21T00:00:00Z"
    new["capture_version"] = 2
    assert all(v == [] for v in diff_captures(old, new).values())


def test_diff_routes_changes_to_groups():
    old, new = _capture(), _capture()
    new["navigator"]["userAgent"] = "… Chrome/139 …"
    new["canvas"]["hash_1"] = "c2"
    new["tls_assert"]["ja4"] = "j4new"
    new["screen"]["width"] = 2560
    new["features"]["batteryApi"] = False
    diff = diff_captures(old, new)
    assert diff["G-UA"] == ["navigator.userAgent"]
    assert diff["G-REND"] == ["canvas.hash_1"]
    assert diff["G-TLS"] == ["tls_assert.ja4"]
    assert diff["G-ENV"] == ["screen.width"]
    assert diff["G-API"] == ["features.batteryApi"]
    assert diff["G-JSVER"] == [] and diff["G-H2"] == []


def test_diff_missing_key_counts_as_change():
    old, new = _capture(), _capture()
    del new["audio"]                                    # 缺键算变化
    old["features"]["js_newV8"] = True                  # 结构新增也算变化
    diff = diff_captures(old, new)
    assert diff["G-REND"] == ["audio"]
    assert diff["G-JSVER"] == ["features.js_newV8"]


def test_diff_list_value_compared_whole():
    old, new = _capture(), _capture()
    new["sec_ch_ua"]["brands"] = [{"brand": "Chromium", "version": "139"}]
    new["fonts"] = ["Arial"]                            # list 不逐元素下钻
    diff = diff_captures(old, new)
    assert diff["G-UA"] == ["sec_ch_ua.brands"]
    assert diff["G-REND"] == ["fonts"]


# ---------------------------------------------------------------------------
# audit_diff 双断言（§四-5）
# ---------------------------------------------------------------------------

def test_audit_compliant_pass():
    ok, errors = audit_diff(_capture(), _evolved_capture(), _make_pack())
    assert ok is True and errors == []


def test_audit_rejects_whitelist_violation():
    new = _evolved_capture()
    new["canvas"]["hash_1"] = "c2"                      # G-REND 未声明漂移
    new["screen"]["width"] = 2560                       # G-ENV 恒冻结（pack 中 {}）
    ok, errors = audit_diff(_capture(), new, _make_pack())
    assert ok is False
    assert any("白名单外变化" in e and "canvas.hash_1" in e and "G-REND" in e
               for e in errors)
    assert any("白名单外变化" in e and "screen.width" in e and "G-ENV" in e
               for e in errors)


def test_audit_rejects_gua_must_change_missing():
    old = _capture()
    new = _capture()                                    # 毫无变化：该变的没变
    ok, errors = audit_diff(old, new, _make_pack())
    assert ok is False
    assert len(errors) == len(G_UA_MUST_CHANGE) == 2
    assert any("G-UA 必变集未变到位" in e and "navigator.userAgent" in e for e in errors)
    assert any("G-UA 必变集未变到位" in e and "sec_ch_ua" in e for e in errors)


def test_audit_partial_gua_change_rejected():
    new = _capture()
    new["navigator"]["userAgent"] = "… Chrome/139 …"    # 只变 UA，Sec-CH-UA 没跟上
    ok, errors = audit_diff(_capture(), new, _make_pack())
    assert ok is False
    assert errors == [e for e in errors if "sec_ch_ua" in e]


def test_audit_allows_declared_groups():
    # G-REND 声明 canvas_changed=true → canvas 变化合规
    pack = _make_pack(**{"G-REND": {"canvas_changed": True,
                                    "angle_backend_changed": False}})
    new = _evolved_capture()
    new["canvas"]["hash_1"] = new["canvas"]["hash_2"] = "c2"
    ok, errors = audit_diff(_capture(), new, pack)
    assert ok is True and errors == []
    # G-TLS 声明 ja4_expected 非 null → TLS 面变化合规
    pack2 = _make_pack(**{"G-TLS": {"ja4_expected": "t13d1516h2_139"}})
    new2 = _evolved_capture()
    new2["tls_assert"]["ja4"] = "t13d1516h2_139"
    ok2, errors2 = audit_diff(_capture(), new2, pack2)
    assert ok2 is True and errors2 == []


def test_audit_unsigned_pack_only_allows_gua():
    # 骨架占位 pack（G-UA 也全 null）：G-UA 恒允许（必变义务），其余组一律拒
    pack = build_drift_pack_skeleton(BASELINE, V139, "2020-08-05")
    new = _evolved_capture()
    new["features"]["bluetooth"] = True                 # G-API 未声明 → 拒
    ok, errors = audit_diff(_capture(), new, pack)
    assert ok is False
    assert any("features.bluetooth" in e and "G-API" in e for e in errors)
    # source 键是出处元数据，不构成 G-API 漂移声明（上面 features 变化被拒即证）；
    # 骨架 pack 下仅 G-UA 族漂移仍合规（G-UA 恒允许，且满足必变义务）
    ok2, errors2 = audit_diff(_capture(), _evolved_capture(), pack)
    assert ok2 is True and errors2 == []


# ---------------------------------------------------------------------------
# run_evolve_sequence（门禁序列骨架，hooks 全 stub）
# ---------------------------------------------------------------------------

class _Recorder:
    """mock hooks：记录调用序，供步骤顺序断言。"""

    def __init__(self, f_old, f_new, *, clr_before=0, clr_after=0):
        self.calls: list[str] = []
        self.f_old, self.f_new = f_old, f_new
        self.clr = {"before": clr_before, "after": clr_after}

    def capture(self, persona, phase):
        self.calls.append(f"capture:{phase}")
        return copy.deepcopy(self.f_old if phase == "before" else self.f_new)

    def rgate(self, capture):
        phase = "before" if len([c for c in self.calls if c == "rgate"]) == 0 else "after"
        self.calls.append("rgate")
        return {"checklist_version": "clr-checklist-v1.1", "total": 82,
                "hits": [{"check_id": "CLR-UA-01"}] * self.clr[phase],
                "passed": 0, "skipped": []}

    def pull(self, persona, pack):
        self.calls.append("pull_image")
        return {"ok": True, "image": f"tishen-image:{pack['to']}"}

    def sample(self, persona, pack):
        self.calls.append("sample_external")
        return {"ok": True, "detail": "CreepJS trust 92 ≥ 基线 ∧ JA4=目标版官方值"}

    def hooks(self, *, with_pull=True, with_sample=True) -> EvolveHooks:
        return EvolveHooks(
            run_rgate=self.rgate,
            capture_fn=self.capture,
            pull_image=self.pull if with_pull else None,
            sample_external=self.sample if with_sample else None,
        )


EXPECTED_ORDER = ["capture:before", "rgate", "pull_image", "capture:after",
                  "rgate", "sample_external"]
EXPECTED_STEPS = ["gate", "rgate_before", "precondition", "pull_image",
                  "rgate_after", "diff_audit", "external_sample", "canary",
                  "history"]


def test_sequence_happy_path_evolved():
    persona = _load_valid()
    pack = _make_pack()
    rec = _Recorder(_capture(), _evolved_capture())
    result = run_evolve_sequence(persona, pack, hooks=rec.hooks(), today=TODAY)

    assert result["outcome"] == "evolved"
    # 序列顺序铁律（§四 0→8）：mock hooks 调用序 + steps 命名序双断言
    assert rec.calls == EXPECTED_ORDER
    assert [s["step"] for s in result["steps"]] == EXPECTED_STEPS
    assert all(s["ok"] for s in result["steps"])
    # canary 属 EVO-4：记录 skipped 说明但不阻塞
    canary = result["steps"][7]
    assert canary["skipped"] is True and "EVO-4" in canary["detail"]

    # history 落账条目字段断言（§二/§四-8）
    entry = result["history_entry"]
    assert entry is not None
    assert entry["from"] == BASELINE and entry["to"] == V139
    assert entry["stable_release_date"] == pack["stable_release_date"]
    assert entry["drift_pack"] == f"{BASELINE}→{V139}"
    assert entry["clr_after"] == 0 and entry["diff_audit"] == "pass"
    assert "T" in entry["at"]                            # 秒级 ISO8601
    # 原地推进：history 追加 + current_chrome 单调推进，且过 persona 结构校验
    assert persona.evolution.history[-1] == entry
    assert persona.evolution.current_chrome == V139
    assert validate_structure(persona) == []


def test_sequence_gate_fail_held_no_hooks_called():
    persona = _load_valid()
    persona.evolution.schedule.next_upgrade_not_before = "2099-01-01"  # 闸门未开
    rec = _Recorder(_capture(), _evolved_capture())
    result = run_evolve_sequence(persona, _make_pack(), hooks=rec.hooks(),
                                 today=TODAY)
    assert result["outcome"] == "held"
    assert [s["step"] for s in result["steps"]] == ["gate"]
    assert "时机闸门未开启" in result["steps"][0]["detail"]
    assert rec.calls == []                               # 门禁未过，真机步骤零调用
    assert result["history_entry"] is None and persona.evolution.history == []


def test_sequence_clr_before_nonzero_held():
    persona = _load_valid()
    rec = _Recorder(_capture(), _evolved_capture(), clr_before=1)
    result = run_evolve_sequence(persona, _make_pack(), hooks=rec.hooks(),
                                 today=TODAY)
    assert result["outcome"] == "held"
    last = result["steps"][-1]
    assert last["step"] == "rgate_before" and last["ok"] is False
    assert "CLR=1" in last["detail"] and "带露馅演化" in last["detail"]
    assert "pull_image" not in rec.calls                 # 绝不带病推进
    assert persona.evolution.history == []


def test_sequence_image_not_connected_held_history_empty():
    persona = _load_valid()
    rec = _Recorder(_capture(), _evolved_capture())
    result = run_evolve_sequence(persona, _make_pack(),
                                 hooks=rec.hooks(with_pull=False), today=TODAY)
    assert result["outcome"] == "held"
    last = result["steps"][-1]
    assert last["step"] == "pull_image"
    assert last["skipped"] is True and "镜像流水线未接入" in last["detail"]
    # 架构红线（§一）：没换镜像就不许产生 F_new/history
    assert "capture:after" not in rec.calls
    assert result["history_entry"] is None and persona.evolution.history == []
    assert persona.evolution.current_chrome == BASELINE  # 滞留原位


def test_sequence_clr_after_nonzero_rejected():
    persona = _load_valid()
    rec = _Recorder(_capture(), _evolved_capture(), clr_after=2)
    result = run_evolve_sequence(persona, _make_pack(), hooks=rec.hooks(),
                                 today=TODAY)
    assert result["outcome"] == "rejected"
    last = result["steps"][-1]
    assert last["step"] == "rgate_after" and "CLR=2" in last["detail"]
    assert result["history_entry"] is None and persona.evolution.history == []


def test_sequence_audit_violation_rejected():
    persona = _load_valid()
    f_new = _evolved_capture()
    f_new["screen"]["width"] = 2560                      # 冻结面被带改 → 双断言违例
    rec = _Recorder(_capture(), f_new)
    result = run_evolve_sequence(persona, _make_pack(), hooks=rec.hooks(),
                                 today=TODAY)
    assert result["outcome"] == "rejected"
    last = result["steps"][-1]
    assert last["step"] == "diff_audit" and last["ok"] is False
    assert "白名单外变化" in last["detail"]
    assert result["history_entry"] is None and persona.evolution.history == []
    assert persona.evolution.current_chrome == BASELINE


def test_sequence_external_sample_not_connected_held():
    persona = _load_valid()
    rec = _Recorder(_capture(), _evolved_capture())
    result = run_evolve_sequence(persona, _make_pack(),
                                 hooks=rec.hooks(with_sample=False), today=TODAY)
    assert result["outcome"] == "held"
    last = result["steps"][-1]
    assert last["step"] == "external_sample"
    assert last["skipped"] is True and "外部抽样未接入" in last["detail"]
    # history 只在 pull_image 与 CLR 重跑真实执行后生成——外部门禁未过仍不落账
    assert result["history_entry"] is None and persona.evolution.history == []


def test_sequence_external_sample_failed_held():
    persona = _load_valid()
    rec = _Recorder(_capture(), _evolved_capture())
    hooks = rec.hooks()
    hooks.sample_external = lambda p, pk: {"ok": False,
                                           "detail": "CreepJS trust 61 < 基线 92"}
    result = run_evolve_sequence(persona, _make_pack(), hooks=hooks, today=TODAY)
    assert result["outcome"] == "held"
    assert "基线" in result["steps"][-1]["detail"]
    assert persona.evolution.history == []


def test_sequence_all_stubs_default_held_at_rgate_before():
    persona = _load_valid()
    result = run_evolve_sequence(persona, _make_pack(), today=TODAY)  # hooks 全 None
    assert result["outcome"] == "held"
    assert [s["step"] for s in result["steps"]] == ["gate", "rgate_before"]
    last = result["steps"][-1]
    assert last["skipped"] is True
    assert "capture_fn" in last["detail"] and "run_rgate" in last["detail"]
    assert result["history_entry"] is None and persona.evolution.history == []


# ---------------------------------------------------------------------------
# CLI evolve --execute（EVO-3；预览默认路径不变）
# ---------------------------------------------------------------------------

@pytest.fixture()
def home(tmp_path, monkeypatch):
    """隔离的 $TISHEN_HOME，并放入一份 persona.yaml。"""
    monkeypatch.setenv("TISHEN_HOME", str(tmp_path))
    personas = tmp_path / "personas"
    personas.mkdir()
    p = _load_valid()
    dump_persona(p, personas / f"{p.meta.id}.yaml")
    return tmp_path, p.meta.id


def _write_pack(tmp_path, pack) -> str:
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack, ensure_ascii=False), encoding="utf-8")
    return str(path)


def test_cli_evolve_execute_all_stubs_held(home, capsys):
    tmp_path, pid = home
    rc = cli.main(["evolve", pid, "--pack", _write_pack(tmp_path, _make_pack()),
                   "--execute"])
    out = capsys.readouterr().out
    assert rc == 1                                       # held=合法滞留，非零退出
    assert "演化门禁序列执行（§四 0–8）" in out
    assert "skipped（真机接入后激活）" in out
    assert "rgate_before" in out and "镜像" not in out.split("rgate_before")[0]
    assert "[结果] held：合法滞留当前版本" in out
    assert "演化门禁检查（预览）" not in out              # execute 不走预览分支
    # held 不落账：persona.yaml 仍是原样（无 history）
    assert load_persona(tmp_path / "personas" / f"{pid}.yaml").evolution.history == []


def test_cli_evolve_preview_default_unchanged(home, capsys):
    # 预览默认路径回归：不带 --execute 时输出与 EVO-2 完全一致
    tmp_path, pid = home
    rc = cli.main(["evolve", pid, "--pack", _write_pack(tmp_path, _make_pack())])
    out = capsys.readouterr().out
    assert rc == 0
    assert "演化门禁检查（预览）" in out and "[放行]" in out
    assert "skipped" not in out and "演化门禁序列执行" not in out
