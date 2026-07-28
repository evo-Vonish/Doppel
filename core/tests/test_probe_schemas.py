"""SPEC-M4 §2/§4 契约校验 + T3 collector TestClient 用例（Coder B）。

纪律：
- 不 import tishen.adversarial 任何模块（A/C 名下，未合并前不存在）；
- 只用手写 fixture JSON 校验 §2 FingerprintCapture / §4 creepjs_export
  必填键存在与类型；
- collector 用例走 fastapi.testclient + 临时库，禁 clone、禁起真服端口。
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_DIR = REPO_ROOT / "tools" / "adversarial" / "harness"
CREEPJS_DIR = REPO_ROOT / "tools" / "adversarial" / "creepjs_selfhost"

# 导入 collector 前把默认库路径指到临时目录，避免在仓库里产生 probe.db 产物
os.environ.setdefault(
    "TISHEN_PROBE_DB",
    str(Path(tempfile.gettempdir()) / "tishen_m4_test_default_probe.db"),
)
sys.path.insert(0, str(HARNESS_DIR))
sys.path.insert(0, str(CREEPJS_DIR))

import collector  # noqa: E402
import import_export  # noqa: E402
import record_result  # noqa: E402

# ---------------------------------------------------------------------------
# 手写 fixture：SPEC-M4 §2 FingerprintCapture 完整样例（缺失=null 口径示意）
# ---------------------------------------------------------------------------

CAPTURE_FIXTURE = {
    "capture_version": 1,
    "collected_at": "2026-07-29T08:00:00.000Z",
    "navigator": {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "platform": "Linux x86_64",
        "vendor": "Google Inc.",
        "languages": ["zh-CN", "zh", "en"],
        "hardwareConcurrency": 8,
        "deviceMemory": 8,
        "maxTouchPoints": 0,
        "webdriver": False,
        "cookieEnabled": True,
        "pdfViewerEnabled": True,
        "doNotTrack": None,
    },
    "sec_ch_ua": {
        "brands": [
            {"brand": "Not)A;Brand", "version": "8"},
            {"brand": "Chromium", "version": "138"},
            {"brand": "Google Chrome", "version": "138"},
        ],
        "mobile": False,
        "platform": "Linux",
        "platformVersion": "6.8.0",
        "uaFullVersion": "138.0.7204.92",
        "fullVersionList": [
            {"brand": "Not)A;Brand", "version": "8.0.0.0"},
            {"brand": "Chromium", "version": "138.0.7204.92"},
        ],
    },
    "screen": {
        "width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1056,
        "colorDepth": 24, "pixelDepth": 24, "devicePixelRatio": 1.0,
        "innerWidth": 1920, "innerHeight": 953,
        "outerWidth": 1920, "outerHeight": 1056,
    },
    "intl": {
        "locale": "zh-CN", "calendar": "gregory", "numberingSystem": "latn",
        "timeZone": "Asia/Shanghai", "tzOffsetMinutes": -480,
    },
    "webgl": {
        "vendor": "WebKit", "renderer": "WebKit WebGL",
        "unmaskedVendor": "Google Inc. (NVIDIA)",
        "unmaskedRenderer": "ANGLE (NVIDIA, GeForce RTX 3060, OpenGL 4.5)",
        "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        "glslVersion": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        "maxTextureSize": 16384, "maxViewportDims": [32767, 32767],
        "maxVertexAttribs": 16, "maxCombinedTextureImageUnits": 32,
        "extensions": ["ANGLE_instanced_arrays", "EXT_blend_minmax"],
    },
    "canvas": {"hash_1": "ab12cd34", "hash_2": "ab12cd34", "read_ms": 3},
    "audio": {"hash": "ef56ab78"},
    "fonts": ["Arial", "DejaVu Sans", "Noto Sans CJK SC"],
    "media": {
        "videoCodecs": ['video/mp4; codecs="avc1.42E01E"'],
        "audioCodecs": ["audio/mpeg"],
        "devices": [
            {"kind": "audioinput", "label": "", "groupId": "g1"},
        ],
    },
    "permissions": {"geolocation": "prompt", "notifications": "prompt"},
    "storage": {"localStorage": True, "indexedDB": True, "sessionStorage": True},
    "webrtc": {"candidates": ["host 192.168.1.x"], "ipHandlingSeen": True},
    "cross_reads": {
        "ua_worker": "Mozilla/5.0 (X11; Linux x86_64)",
        "ua_iframe": "Mozilla/5.0 (X11; Linux x86_64)",
        "platform_worker": "Linux x86_64",
        "platform_iframe": "Linux x86_64",
        "hwc_worker": 8,
        "hwc_iframe": 8,
        "tz_iframe": "Asia/Shanghai",
        "languages_worker": ["zh-CN", "zh", "en"],
    },
    "features": {
        "touchEvent": False, "pointerCoarse": False, "pointerFine": True,
        "batteryApi": False, "bluetooth": True, "midi": True, "usb": True,
        "sharedArrayBuffer": True, "offscreenCanvas": True,
    },
    "cdp_traces": {
        "runtimeEnableArtifacts": False,
        "consoleLogArtifacts": False,
        "stackTracesContainCdp": False,
    },
    "tls_assert": {"ja3": None, "ja4": None, "source": "none"},
}

# SPEC-M4 §2 必填键与类型树（叶子=允许类型元组；["nullable", x]=可为 null；
# ["listof", 元素spec]=数组逐元素校验；dict=键集合须精确一致）
CAPTURE_SPEC_TREE = {
    "capture_version": (int,),
    "collected_at": (str,),
    "navigator": {
        "userAgent": (str,), "platform": (str,), "vendor": (str,),
        "languages": ["listof", (str,)],
        "hardwareConcurrency": (int, type(None)),
        "deviceMemory": ((int, float), type(None)),
        "maxTouchPoints": (int,),
        "webdriver": (bool, type(None)),
        "cookieEnabled": (bool,),
        "pdfViewerEnabled": (bool, type(None)),
        "doNotTrack": (str, type(None)),
    },
    "sec_ch_ua": ["nullable", {
        "brands": ["listof", {"brand": (str,), "version": (str,)}],
        "mobile": (bool,),
        "platform": (str,),
        "platformVersion": (str, type(None)),
        "uaFullVersion": (str, type(None)),
        "fullVersionList": ["nullable",
                            ["listof", {"brand": (str,), "version": (str,)}]],
    }],
    "screen": {k: (int,) for k in (
        "width", "height", "availWidth", "availHeight", "colorDepth",
        "pixelDepth", "innerWidth", "innerHeight", "outerWidth", "outerHeight")
    } | {"devicePixelRatio": ((int, float),)},
    "intl": {
        "locale": (str,),
        "calendar": (str, type(None)),
        "numberingSystem": (str, type(None)),
        "timeZone": (str, type(None)),
        "tzOffsetMinutes": (int,),
    },
    "webgl": {
        "vendor": (str, type(None)), "renderer": (str, type(None)),
        "unmaskedVendor": (str, type(None)), "unmaskedRenderer": (str, type(None)),
        "version": (str, type(None)), "glslVersion": (str, type(None)),
        "maxTextureSize": (int, type(None)),
        "maxViewportDims": ["nullable", ["listof", (int,)]],
        "maxVertexAttribs": (int, type(None)),
        "maxCombinedTextureImageUnits": (int, type(None)),
        "extensions": ["listof", (str,)],
    },
    "canvas": {
        "hash_1": (str, type(None)), "hash_2": (str, type(None)),
        "read_ms": (int,),
    },
    "audio": {"hash": (str, type(None))},
    "fonts": ["listof", (str,)],
    "media": {
        "videoCodecs": ["listof", (str,)],
        "audioCodecs": ["listof", (str,)],
        "devices": ["listof",
                    {"kind": (str,), "label": (str,), "groupId": (str,)}],
    },
    "permissions": {"__values__": (str,)},  # 开放键集：值须 granted|denied|prompt
    "storage": {k: (bool,) for k in ("localStorage", "indexedDB", "sessionStorage")},
    "webrtc": {
        "candidates": ["listof", (str,)],
        "ipHandlingSeen": (bool,),
    },
    "cross_reads": {
        "ua_worker": (str, type(None)), "ua_iframe": (str, type(None)),
        "platform_worker": (str, type(None)), "platform_iframe": (str, type(None)),
        "hwc_worker": (int, type(None)), "hwc_iframe": (int, type(None)),
        "tz_iframe": (str, type(None)),
        "languages_worker": ["listof", (str,)],
    },
    "features": {k: (bool,) for k in (
        "touchEvent", "pointerCoarse", "pointerFine", "batteryApi", "bluetooth",
        "midi", "usb", "sharedArrayBuffer", "offscreenCanvas")},
    "cdp_traces": {k: (bool,) for k in (
        "runtimeEnableArtifacts", "consoleLogArtifacts", "stackTracesContainCdp")},
    "tls_assert": {
        "ja3": (str, type(None)), "ja4": (str, type(None)),
        "source": (str,),
    },
}

# SPEC-M4 §4 creepjs_export 手写样例
CREEPJS_EXPORT_FIXTURE = {
    "source": "creepjs-selfhost",
    "creepjs_commit": "0123456789abcdef0123456789abcdef01234567",
    "trust_score": 87.5,
    "lies": [{"name": "navigator.userAgent", "detail": "platform 与 UA 不一致"}],
    "resistance": {"detected": False, "patterns": []},
    "fp_hash": "abcdef0123456789",
    "raw_summary": {"title": "CreepJS", "collected_at": "2026-07-29T08:00:00Z"},
}


def _check(value, spec, path, errors):
    """递归校验 fixture：必填键存在、类型符合（bool 是 int 子类须单独防）。"""
    if isinstance(spec, list) and spec and spec[0] == "nullable":
        if value is None:
            return
        spec = spec[1]
    if isinstance(spec, tuple):  # 叶子：类型元组
        types = spec
        if isinstance(value, bool) and bool not in types:
            errors.append(f"{path}: bool 不在允许类型 {types}")
        elif not isinstance(value, types):
            errors.append(f"{path}: 类型 {type(value).__name__} 不在 {types}")
        return
    if isinstance(spec, list) and spec and spec[0] == "listof":
        if not isinstance(value, list):
            errors.append(f"{path}: 须为数组，实际 {type(value).__name__}")
            return
        for i, item in enumerate(value):
            _check(item, spec[1], f"{path}[{i}]", errors)
        return
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            errors.append(f"{path}: 须为对象，实际 {type(value).__name__}")
            return
        if "__values__" in spec:  # 开放键集：只校验每个值
            for k, v in value.items():
                _check(v, spec["__values__"], f"{path}.{k}", errors)
            return
        missing = set(spec) - set(value)
        extra = set(value) - set(spec)
        if missing:
            errors.append(f"{path}: 缺键 {sorted(missing)}")
        if extra:
            errors.append(f"{path}: 多键 {sorted(extra)}")
        for k in sorted(set(spec) & set(value)):
            _check(value[k], spec[k], f"{path}.{k}", errors)
        return
    raise AssertionError(f"spec 树非法节点 {path}: {spec!r}")


# ---------------------------------------------------------------------------
# §2/§4 fixture 形状用例
# ---------------------------------------------------------------------------

def test_capture_fixture_conforms_spec2():
    """手写 capture fixture 逐键逐型对照 §2 契约树，零误差。"""
    errors: list[str] = []
    _check(CAPTURE_FIXTURE, CAPTURE_SPEC_TREE, "$", errors)
    assert errors == [], "fixture 与 SPEC-M4 §2 不一致：\n" + "\n".join(errors)


def test_capture_fixture_top_level_keys_exact():
    """§2 顶层 18 键精确枚举（防漏字段/防多字段）。"""
    expected = {
        "capture_version", "collected_at", "navigator", "sec_ch_ua", "screen",
        "intl", "webgl", "canvas", "audio", "fonts", "media", "permissions",
        "storage", "webrtc", "cross_reads", "features", "cdp_traces",
        "tls_assert",
    }
    assert set(CAPTURE_FIXTURE) == expected
    assert CAPTURE_FIXTURE["capture_version"] == 1


def test_capture_fixture_json_roundtrip():
    """fixture 须可 JSON 序列化往返（入库 payload 原文口径）。"""
    assert json.loads(json.dumps(CAPTURE_FIXTURE)) == CAPTURE_FIXTURE


def test_creepjs_export_fixture_conforms_spec4():
    """手写 creepjs_export fixture 对照 §4 形状，validate_export 零误差。"""
    assert import_export.validate_export(CREEPJS_EXPORT_FIXTURE) is None
    assert json.loads(json.dumps(CREEPJS_EXPORT_FIXTURE)) == CREEPJS_EXPORT_FIXTURE


def test_creepjs_export_validate_rejects_bad_shape():
    """缺键/错类型/错 source 必须被拒（不猜、不迁移）。"""
    bad_missing = {k: v for k, v in CREEPJS_EXPORT_FIXTURE.items() if k != "lies"}
    assert import_export.validate_export(bad_missing) is not None
    bad_type = dict(CREEPJS_EXPORT_FIXTURE, trust_score="87")
    assert import_export.validate_export(bad_type) is not None
    bad_source = dict(CREEPJS_EXPORT_FIXTURE, source="other")
    assert import_export.validate_export(bad_source) is not None
    assert import_export.validate_export([1, 2]) is not None


# ---------------------------------------------------------------------------
# §4 库结构用例
# ---------------------------------------------------------------------------

def test_probe_db_schema_spec4(tmp_path):
    """建表后四表齐备且关键列与 §4 一致（SQLite 内省，不依赖真服）。"""
    db = str(tmp_path / "probe.db")
    collector.init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"captures", "clr_reports", "fcr_results", "edr_results"} <= tables
        cols = {r[1] for r in conn.execute("PRAGMA table_info(captures)")}
        assert {"id", "group_tag", "persona_id", "entry", "captured_at",
                "payload"} == cols
        cols = {r[1] for r in conn.execute("PRAGMA table_info(fcr_results)")}
        assert {"id", "group_tag", "persona_id", "site", "outcome", "score",
                "recorded_at", "note"} == cols
        cols = {r[1] for r in conn.execute("PRAGMA table_info(edr_results)")}
        assert {"id", "group_tag", "persona_id", "dimension", "detected",
                "evidence", "recorded_at"} == cols
        cols = {r[1] for r in conn.execute("PRAGMA table_info(clr_reports)")}
        assert {"id", "capture_id", "report"} == cols
        # WAL 模式（§4 标题口径）
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"


# ---------------------------------------------------------------------------
# collector TestClient 用例（禁起真服端口）
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path):
    app = collector.create_app(str(tmp_path / "probe.db"))
    return TestClient(app), str(tmp_path / "probe.db")


def test_health(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_post_valid_capture(client, monkeypatch):
    """合法 capture：201 入库，payload 原文落 captures（entry=probe）。

    降级路径：monkeypatch 屏蔽 tishen.adversarial.rgate（模拟未安装环境，
    与 M3 test_events_without_observ_module 同款手法），占位钩子只存不评。
    """
    monkeypatch.setitem(sys.modules, "tishen.adversarial.rgate", None)
    c, db = client
    r = c.post("/capture?group_tag=T-cold&persona_id=p1",
               json=CAPTURE_FIXTURE)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ok"] is True and isinstance(body["capture_id"], int)
    # rgate 不可用（模拟）：占位钩子只存不评
    assert body["rgate"] == "unavailable"
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT group_tag, persona_id, entry, captured_at, payload"
            " FROM captures WHERE id=?", (body["capture_id"],)).fetchone()
    assert row[0:3] == ("T-cold", "p1", "probe")
    assert row[3] == CAPTURE_FIXTURE["collected_at"]
    assert json.loads(row[4]) == CAPTURE_FIXTURE  # 原文不改一字


def test_post_valid_capture_default_group(client):
    """缺省 group_tag=T-cold；对照组 persona_id 可为 null。"""
    c, db = client
    r = c.post("/capture", json=CAPTURE_FIXTURE)
    assert r.status_code == 201
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT group_tag, persona_id FROM captures").fetchone()
    assert row == ("T-cold", None)


def test_post_wrong_capture_version(client):
    c, _ = client
    bad = dict(CAPTURE_FIXTURE, capture_version=2)
    r = c.post("/capture", json=bad)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_CAPTURE_VERSION"


def test_post_missing_capture_version(client):
    c, _ = client
    bad = {k: v for k, v in CAPTURE_FIXTURE.items() if k != "capture_version"}
    r = c.post("/capture", json=bad)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_CAPTURE_VERSION"


def test_post_non_object_body(client):
    c, _ = client
    r = c.post("/capture", json=[1, 2, 3])
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_CAPTURE"


def test_post_invalid_group_tag(client):
    c, _ = client
    r = c.post("/capture?group_tag=X-native", json=CAPTURE_FIXTURE)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_PARAM"


def test_rgate_placeholder_no_report_written(client, monkeypatch):
    """rgate 不可导入时不写 clr_reports（只存不评），捕获仍入库。"""
    # 合并后 rgate 常驻可用——monkeypatch 屏蔽以固定"降级路径"语义
    monkeypatch.setitem(sys.modules, "tishen.adversarial.rgate", None)
    c, db = client
    assert sys.modules.get("tishen.adversarial.rgate") is None
    r = c.post("/capture", json=CAPTURE_FIXTURE)
    assert r.status_code == 201
    with sqlite3.connect(db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM clr_reports").fetchone()[0]
        m = conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
    assert n == 0 and m == 1


def test_post_valid_capture_rgate_integrated(client):
    """集成分支（A/B 合并后的真实行为）：rgate 可用 → 评估并写 clr_reports。

    SPEC-M4 §7 契约抽查：B 的 CAPTURE_FIXTURE 须能被 A 的 run_rgate 消费，
    报告含清单版本 clr-checklist-v1（跨 Coder 集成断言）。
    """
    c, db = client
    r = c.post("/capture", json=CAPTURE_FIXTURE)
    assert r.status_code == 201, r.text
    assert r.json()["rgate"] == "evaluated"
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT report FROM clr_reports").fetchone()
    assert row is not None
    report = json.loads(row[0])
    assert report["checklist_version"] == "clr-checklist-v1"
    assert report["total"] > 0 and "hits" in report and "skipped" in report


# ---------------------------------------------------------------------------
# record_result CLI 用例（临时库，不起服）
# ---------------------------------------------------------------------------

def test_record_result_fcr(tmp_path, capsys):
    db = str(tmp_path / "probe.db")
    rc = record_result.main([
        "--db", db, "--group", "T-cold", "--persona", "p1",
        "--site", "recaptcha_v3", "--outcome", "score_bucket",
        "--score", "0.7", "--note", "第1次",
    ])
    assert rc == 0
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT group_tag, persona_id, site, outcome, score, note"
            " FROM fcr_results").fetchone()
    assert row == ("T-cold", "p1", "recaptcha_v3", "score_bucket", "0.7", "第1次")


def test_record_result_edr(tmp_path):
    db = str(tmp_path / "probe.db")
    rc = record_result.main([
        "--db", db, "--group", "A-native",
        "--dimension", "headless", "--detected", "0",
        "--evidence", "areyouheadless 未识别",
    ])
    assert rc == 0
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT group_tag, persona_id, dimension, detected, evidence"
            " FROM edr_results").fetchone()
    assert row == ("A-native", None, "headless", 0, "areyouheadless 未识别")


def test_record_result_rejects_bad_args(tmp_path):
    db = str(tmp_path / "probe.db")
    with pytest.raises(SystemExit):  # v2 入口填 score：口径外，拒收
        record_result.main([
            "--db", db, "--group", "T-cold",
            "--site", "recaptcha_v2", "--outcome", "pass", "--score", "0.5",
        ])
    with pytest.raises(SystemExit):  # 非法 group
        record_result.main([
            "--db", db, "--group", "ZZZ",
            "--site", "turnstile", "--outcome", "pass",
        ])
    with pytest.raises(SystemExit):  # FCR/EDR 参数混用
        record_result.main([
            "--db", db, "--group", "T-cold",
            "--site", "turnstile", "--outcome", "pass",
            "--dimension", "bot", "--detected", "1",
        ])
