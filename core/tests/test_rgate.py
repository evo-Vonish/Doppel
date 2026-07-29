"""R-Gate（T1）单测：SPEC-M4 §7 验收口径。

覆盖：HC→DM 全表、噪声双读不一致命中、字段缺失记 skipped 不计命中、
跨线程/iframe 读值不一致命中、TLS 断言族、清单配额与 id 唯一性、
干净 capture 零命中、自定义 checklist 注入与 ClrReport 契约结构。
全部本地 fixture，不依赖外网。
"""

from __future__ import annotations

import copy
from collections import Counter

import pytest

from tishen.adversarial.clr_checklist_v1 import CHECKLIST_V1
from tishen.adversarial.rgate import CHECKLIST_VERSION, run_rgate

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/138.0.0.0 Safari/537.36")

# SPEC-M4 §3 tishen 自研 HC→DM 合法对表
HC_DM_TABLE = {2: {2, 4}, 4: {2, 4, 8}, 6: {4, 8},
               8: {4, 8, 16}, 12: {8, 16}, 16: {16}}


def clean_capture() -> dict:
    """一份完全自洽的 Linux 桌面 Chrome capture（所有 82 条应全部 passed）。"""
    return {
        "capture_version": 1,
        "collected_at": "2026-07-29T08:00:00.000Z",
        "navigator": {
            "userAgent": UA, "platform": "Linux x86_64", "vendor": "Google Inc.",
            "languages": ["zh-CN", "zh", "en"], "hardwareConcurrency": 8,
            "deviceMemory": 8, "maxTouchPoints": 0, "webdriver": False,
            "cookieEnabled": True, "pdfViewerEnabled": True, "doNotTrack": None,
        },
        "sec_ch_ua": {
            "brands": [{"brand": "Not;A=Brand", "version": "99"},
                       {"brand": "Chromium", "version": "138"},
                       {"brand": "Google Chrome", "version": "138"}],
            "mobile": False, "platform": "Linux", "platformVersion": "6.5.0",
            "uaFullVersion": "138.0.7204.50",
            "fullVersionList": [{"brand": "Not;A=Brand", "version": "99.0.0.0"},
                                {"brand": "Chromium", "version": "138.0.7204.50"},
                                {"brand": "Google Chrome", "version": "138.0.7204.50"}],
        },
        "screen": {
            "width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040,
            "colorDepth": 24, "pixelDepth": 24, "devicePixelRatio": 1.0,
            "innerWidth": 1920, "innerHeight": 953,
            "outerWidth": 1920, "outerHeight": 1040,
        },
        "intl": {"locale": "zh-CN", "calendar": "gregory", "numberingSystem": "latn",
                 "timeZone": "Asia/Shanghai", "tzOffsetMinutes": -480},
        "webgl": {
            "vendor": "WebKit", "renderer": "WebKit WebGL",
            "unmaskedVendor": "Google Inc. (Intel)",
            "unmaskedRenderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), "
                                "OpenGL 4.6)",
            "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
            "glslVersion": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
            "maxTextureSize": 16384, "maxViewportDims": [16384, 16384],
            "maxVertexAttribs": 16, "maxCombinedTextureImageUnits": 32,
            "extensions": ["EXT_color_buffer_float", "OES_texture_float_linear",
                           "WEBGL_compressed_texture_s3tc"],
        },
        "canvas": {"hash_1": "a1b2c3d4e5f6", "hash_2": "a1b2c3d4e5f6", "read_ms": 1500},
        "audio": {"hash": "f6e5d4c3b2a1"},
        "fonts": ["DejaVu Sans", "Liberation Sans", "Noto Sans",
                  "Noto Sans CJK SC", "Ubuntu"],
        "media": {"videoCodecs": ["h264", "vp8", "vp9"],
                  "audioCodecs": ["aac", "opus"], "devices": []},
        "permissions": {"notifications": "prompt"},
        "storage": {"localStorage": True, "indexedDB": True, "sessionStorage": True},
        "webrtc": {"candidates": [], "ipHandlingSeen": False},
        "cross_reads": {
            "ua_worker": UA, "ua_iframe": UA,
            "platform_worker": "Linux x86_64", "platform_iframe": "Linux x86_64",
            "hwc_worker": 8, "hwc_iframe": 8,
            "tz_iframe": "Asia/Shanghai",
            "languages_worker": ["zh-CN", "zh", "en"],
        },
        "features": {"touchEvent": False, "pointerCoarse": False, "pointerFine": True,
                     "batteryApi": True, "bluetooth": True, "midi": True, "usb": True,
                     "sharedArrayBuffer": False, "offscreenCanvas": True},
        "cdp_traces": {"runtimeEnableArtifacts": False, "consoleLogArtifacts": False,
                       "stackTracesContainCdp": False},
        "tls_assert": {"ja3": "771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23-24,0",
                       "ja4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
                       "source": "tls.peet.ws"},
        "hook_stealth": {"fn_to_string_native": True,
                         "error_stack_has_tishen_frame": False,
                         "main_world_runtime_id_reachable": False,
                         "loopback_resource_entries": []},
    }


def hit_ids(report: dict) -> set:
    return {h["check_id"] for h in report["hits"]}


def skip_ids(report: dict) -> set:
    return {s["check_id"] for s in report["skipped"]}


# ---------------------------------------------------------------------------
# 清单本身：配额 / id 唯一性 / 来源与严重度值域
# ---------------------------------------------------------------------------

def test_checklist_quota_and_unique_ids():
    assert 60 <= len(CHECKLIST_V1) <= 90
    assert len(CHECKLIST_V1) == 82
    ids = [c.id for c in CHECKLIST_V1]
    assert len(ids) == len(set(ids)), "清单 id 不得重复"
    family_counts = Counter(i.split("-")[1] for i in ids)
    assert family_counts == {"UA": 10, "TZ": 8, "SCR": 8, "GPU": 10, "FONT": 6,
                             "HW": 6, "BOT": 10, "FEAT": 8, "NET": 6, "NOISE": 6,
                             "HOOK": 4}


def test_checklist_source_and_severity_domain():
    for c in CHECKLIST_V1:
        assert c.source in ("creepjs", "sannysoft", "browserleaks",
                            "incolumitas", "tishen"), c.id
        assert c.severity in ("critical", "major", "minor"), c.id
        assert c.assertion and c.layers, c.id
    # tishen 自研项必须真实存在（HC→DM 对表、Linux+ANGLE 特征等）
    tishen_ids = {c.id for c in CHECKLIST_V1 if c.source == "tishen"}
    assert {"CLR-HW-01", "CLR-HW-02", "CLR-GPU-04"} <= tishen_ids


# ---------------------------------------------------------------------------
# 干净 capture：零命中零跳过，报告结构符合契约
# ---------------------------------------------------------------------------

def test_clean_capture_all_passed():
    report = run_rgate(clean_capture())
    assert report["checklist_version"] == CHECKLIST_VERSION == "clr-checklist-v1.1"
    assert report["total"] == 82
    assert report["hits"] == []
    assert report["skipped"] == []
    assert report["passed"] == 82


def test_report_contract_structure_and_accounting():
    cap = clean_capture()
    cap["navigator"]["webdriver"] = True
    report = run_rgate(cap)
    assert set(report) == {"checklist_version", "total", "hits", "passed", "skipped"}
    assert report["passed"] + len(report["hits"]) + len(report["skipped"]) == report["total"]
    hit = report["hits"][0]
    assert set(hit) == {"check_id", "assertion", "severity", "evidence"}
    assert hit["check_id"] == "CLR-BOT-01"
    assert hit["severity"] == "critical"
    assert hit["evidence"] == {"navigator.webdriver": True}


def test_custom_checklist_injection():
    custom = [c for c in CHECKLIST_V1 if c.id == "CLR-BOT-01"]
    cap = clean_capture()
    cap["navigator"]["webdriver"] = True
    report = run_rgate(cap, checklist=custom)
    assert report["total"] == 1
    assert hit_ids(report) == {"CLR-BOT-01"}


# ---------------------------------------------------------------------------
# HC→DM 合法对表（tishen 自研项全表）
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hc,dm", [(h, d) for h, ds in HC_DM_TABLE.items() for d in ds])
def test_hc_dm_table_legal_pairs_pass(hc, dm):
    cap = clean_capture()
    cap["navigator"]["hardwareConcurrency"] = hc
    cap["navigator"]["deviceMemory"] = dm
    cap["cross_reads"]["hwc_worker"] = hc
    cap["cross_reads"]["hwc_iframe"] = hc
    report = run_rgate(cap)
    assert "CLR-HW-01" not in hit_ids(report)
    assert "CLR-HW-02" not in hit_ids(report)


@pytest.mark.parametrize("hc,dm", [(2, 8), (2, 16), (4, 16), (6, 2), (6, 16),
                                   (8, 2), (12, 4), (16, 4), (16, 8)])
def test_hc_dm_table_illegal_pairs_hit(hc, dm):
    cap = clean_capture()
    cap["navigator"]["hardwareConcurrency"] = hc
    cap["navigator"]["deviceMemory"] = dm
    cap["cross_reads"]["hwc_worker"] = hc
    cap["cross_reads"]["hwc_iframe"] = hc
    report = run_rgate(cap)
    assert "CLR-HW-01" in hit_ids(report)
    evidence = next(h for h in report["hits"] if h["check_id"] == "CLR-HW-01")["evidence"]
    assert evidence == {"navigator.hardwareConcurrency": hc,
                        "navigator.deviceMemory": dm}


def test_hc_illegal_tier_hit_hw02_not_hw01():
    cap = clean_capture()
    cap["navigator"]["hardwareConcurrency"] = 3
    cap["cross_reads"]["hwc_worker"] = 3
    cap["cross_reads"]["hwc_iframe"] = 3
    report = run_rgate(cap)
    assert "CLR-HW-02" in hit_ids(report)
    assert "CLR-HW-01" not in hit_ids(report), "同一根因不得重复报错"


# ---------------------------------------------------------------------------
# 噪声稳定性族：双读不一致命中；audio 撞 hash；双读间隔
# ---------------------------------------------------------------------------

def test_canvas_double_read_mismatch_hit():
    cap = clean_capture()
    cap["canvas"]["hash_2"] = "ffffffffffff"
    report = run_rgate(cap)
    assert "CLR-NOISE-01" in hit_ids(report)
    evidence = next(h for h in report["hits"]
                    if h["check_id"] == "CLR-NOISE-01")["evidence"]
    assert evidence["canvas.hash_1"] != evidence["canvas.hash_2"]


def test_canvas_audio_hash_collision_hit():
    cap = clean_capture()
    cap["audio"]["hash"] = cap["canvas"]["hash_1"]
    report = run_rgate(cap)
    assert "CLR-NOISE-05" in hit_ids(report)


def test_canvas_read_interval_too_short_hit():
    cap = clean_capture()
    cap["canvas"]["read_ms"] = 300
    report = run_rgate(cap)
    assert "CLR-NOISE-06" in hit_ids(report)


# ---------------------------------------------------------------------------
# skipped 语义：字段缺失（或为 null）记 skipped 不计命中
# ---------------------------------------------------------------------------

def test_missing_field_skipped_not_hit():
    cap = clean_capture()
    del cap["canvas"]
    report = run_rgate(cap)
    noise_skipped = {"CLR-NOISE-01", "CLR-NOISE-02", "CLR-NOISE-03",
                     "CLR-NOISE-05", "CLR-NOISE-06"}
    assert noise_skipped <= skip_ids(report)
    assert not (noise_skipped & hit_ids(report)), "字段缺失不得计命中"
    assert all(s["reason"] == "field_missing" for s in report["skipped"])


def test_null_field_treated_as_missing():
    cap = clean_capture()
    cap["navigator"]["webdriver"] = None          # 探针契约：字段缺失=null
    cap["cross_reads"]["ua_worker"] = None
    report = run_rgate(cap)
    assert "CLR-BOT-01" in skip_ids(report)
    assert "CLR-UA-06" in skip_ids(report)
    assert "CLR-BOT-01" not in hit_ids(report)


# ---------------------------------------------------------------------------
# 跨线程 / iframe 读值不一致命中（CreepJS lies 思想）
# ---------------------------------------------------------------------------

def test_cross_read_ua_worker_mismatch_hit():
    cap = clean_capture()
    cap["cross_reads"]["ua_worker"] = UA.replace("Chrome/138", "Chrome/120")
    report = run_rgate(cap)
    assert "CLR-UA-06" in hit_ids(report)


def test_cross_read_ua_iframe_mismatch_hit():
    cap = clean_capture()
    cap["cross_reads"]["ua_iframe"] = UA.replace("X11; Linux x86_64", "Windows NT 10.0")
    report = run_rgate(cap)
    assert "CLR-UA-07" in hit_ids(report)


def test_cross_read_hwc_iframe_mismatch_hit():
    cap = clean_capture()
    cap["cross_reads"]["hwc_iframe"] = 4
    report = run_rgate(cap)
    assert "CLR-HW-04" in hit_ids(report)


def test_cross_read_platform_worker_mismatch_hit():
    cap = clean_capture()
    cap["cross_reads"]["platform_worker"] = "Win32"
    report = run_rgate(cap)
    assert "CLR-HW-05" in hit_ids(report)


def test_cross_read_tz_and_languages_mismatch_hit():
    cap = clean_capture()
    cap["cross_reads"]["tz_iframe"] = "America/New_York"
    cap["cross_reads"]["languages_worker"] = ["en-US", "en"]
    report = run_rgate(cap)
    assert {"CLR-TZ-02", "CLR-TZ-04"} <= hit_ids(report)


# ---------------------------------------------------------------------------
# TLS 断言族（incolumitas 式 UA↔JA3/JA4 互洽）
# ---------------------------------------------------------------------------

def test_tls_ja3_cipher_order_mismatch_hit():
    cap = clean_capture()
    # 未以 4865-4866-4867 开头：非 Chrome 的 ClientHello 套件序
    cap["tls_assert"]["ja3"] = "771,49195-49199-4865-4866,0-23-65281,29-23-24,0"
    report = run_rgate(cap)
    assert "CLR-NET-04" in hit_ids(report)


def test_tls_ja3_grease_stripped_before_compare():
    cap = clean_capture()
    # 首部 GREASE（2570=0x0A0A）剔除后仍以 4865 开头：应通过
    cap["tls_assert"]["ja3"] = "771,2570-4865-4866-4867-49195,0-23-65281,29-23-24,0"
    report = run_rgate(cap)
    assert "CLR-NET-04" not in hit_ids(report)


def test_tls_ja3_bad_shape_hit():
    cap = clean_capture()
    cap["tls_assert"]["ja3"] = "not-a-ja3"
    report = run_rgate(cap)
    assert "CLR-NET-02" in hit_ids(report)


def test_tls_ja4_bad_shape_and_version_hit():
    cap = clean_capture()
    cap["tls_assert"]["ja4"] = "t12d1516h2_8daaf6152771_b1ff8ab2d16f"
    report = run_rgate(cap)
    # 形状合法但 TLS 版本标记为 12，与 UA 声称的 Chrome 138 矛盾
    assert "CLR-NET-05" in hit_ids(report)
    cap["tls_assert"]["ja4"] = "garbage"
    report = run_rgate(cap)
    assert "CLR-NET-03" in hit_ids(report)


def test_tls_source_consistency():
    cap = clean_capture()
    cap["tls_assert"]["source"] = "none"          # 声称没采集却带着 ja3/ja4
    report = run_rgate(cap)
    assert "CLR-NET-01" in hit_ids(report)

    cap = clean_capture()
    cap["tls_assert"] = {"ja3": None, "ja4": None, "source": "tls.peet.ws"}
    report = run_rgate(cap)
    assert "CLR-NET-01" in hit_ids(report)        # 声称已采集却两指纹皆空

    cap = clean_capture()
    cap["tls_assert"] = {"ja3": None, "ja4": None, "source": "none"}
    report = run_rgate(cap)
    assert "CLR-NET-01" not in hit_ids(report)    # 没采集且确实没指纹：自洽


def test_tls_ja3_ja4_must_coexist():
    cap = clean_capture()
    cap["tls_assert"]["ja4"] = None
    report = run_rgate(cap)
    assert "CLR-NET-06" in hit_ids(report)


# ---------------------------------------------------------------------------
# 跨层互洽抽查：UA↔platform、时区↔偏移、Linux+ANGLE、webdriver/CDP
# ---------------------------------------------------------------------------

def test_ua_platform_os_mismatch_hit():
    cap = clean_capture()
    cap["navigator"]["platform"] = "Win32"
    cap["cross_reads"]["platform_worker"] = "Win32"
    cap["cross_reads"]["platform_iframe"] = "Win32"
    report = run_rgate(cap)
    assert "CLR-UA-02" in hit_ids(report)         # UA 称 Linux，platform 称 Win32
    assert "CLR-GPU-04" not in hit_ids(report)    # 非 Linux 平台不适用 ANGLE 特征


def test_timezone_offset_mismatch_hit():
    cap = clean_capture()
    cap["intl"]["tzOffsetMinutes"] = 300          # Asia/Shanghai 合法值仅 -480
    report = run_rgate(cap)
    assert "CLR-TZ-01" in hit_ids(report)


def test_timezone_locale_region_conflict_without_language_chain_hit():
    cap = clean_capture()
    cap["intl"]["timeZone"] = "America/New_York"
    cap["intl"]["tzOffsetMinutes"] = 240
    cap["cross_reads"]["tz_iframe"] = "America/New_York"
    # 语言链剔除 en：只剩 zh，无法解释美国时区
    cap["navigator"]["languages"] = ["zh-CN", "zh"]
    cap["cross_reads"]["languages_worker"] = ["zh-CN", "zh"]
    report = run_rgate(cap)
    assert "CLR-TZ-05" in hit_ids(report)


def test_linux_angle_feature_hit():
    cap = clean_capture()
    cap["webgl"]["unmaskedRenderer"] = "NVIDIA GeForce RTX 3060/PCIe/SSE2"
    cap["webgl"]["unmaskedVendor"] = "Google Inc. (NVIDIA)"
    report = run_rgate(cap)
    assert "CLR-GPU-04" in hit_ids(report)        # Linux Chrome 必须是 ANGLE (...)
    assert "CLR-GPU-05" not in hit_ids(report)    # vendor 括号内厂商名仍在渲染器串中


def test_webdriver_and_cdp_traces_hit():
    cap = clean_capture()
    cap["navigator"]["webdriver"] = True
    cap["cdp_traces"]["runtimeEnableArtifacts"] = True
    report = run_rgate(cap)
    assert {"CLR-BOT-01", "CLR-BOT-02"} <= hit_ids(report)


def test_run_rgate_is_pure_function():
    cap = clean_capture()
    snapshot = copy.deepcopy(cap)
    r1 = run_rgate(cap)
    r2 = run_rgate(cap)
    assert cap == snapshot, "run_rgate 不得改写入参"
    assert r1 == r2, "同一输入必须得到同一报告（纯函数）"


# ---------------------------------------------------------------------------
# v1.1 追加：hook 隐蔽性族（SPEC-E4 J2，《hook 层专项方案》§六-2）
# ---------------------------------------------------------------------------

def test_hook_entries_exist_and_id_prefix():
    hook = {c.id: c for c in CHECKLIST_V1 if c.id.startswith("CLR-HOOK-")}
    assert set(hook) == {"CLR-HOOK-01", "CLR-HOOK-02", "CLR-HOOK-03", "CLR-HOOK-04"}
    for c in hook.values():
        assert c.layers and all(l.startswith("hook_stealth.") for l in c.layers)


def test_hook_entries_source_all_tishen():
    hook = [c for c in CHECKLIST_V1 if c.id.startswith("CLR-HOOK-")]
    assert all(c.source == "tishen" for c in hook), "HOOK 族须全标 tishen 自研"


def test_tishen_quota_9_to_13():
    tishen_ids = {c.id for c in CHECKLIST_V1 if c.source == "tishen"}
    assert len(tishen_ids) == 13  # 出厂 9 项 + v1.1 HOOK 4 项
    assert {"CLR-HOOK-01", "CLR-HOOK-02", "CLR-HOOK-03", "CLR-HOOK-04"} <= tishen_ids


def test_checklist_version_v1_1():
    report = run_rgate(clean_capture())
    assert CHECKLIST_VERSION == "clr-checklist-v1.1"
    assert report["checklist_version"] == "clr-checklist-v1.1"


def test_hook_checks_hit_on_stealth_failure():
    cap = clean_capture()
    cap["hook_stealth"]["fn_to_string_native"] = False
    cap["hook_stealth"]["error_stack_has_tishen_frame"] = True
    cap["hook_stealth"]["main_world_runtime_id_reachable"] = True
    cap["hook_stealth"]["loopback_resource_entries"] = [
        "http://127.0.0.1:9123/beacon"]
    report = run_rgate(cap)
    assert {"CLR-HOOK-01", "CLR-HOOK-02", "CLR-HOOK-03", "CLR-HOOK-04"} \
        <= hit_ids(report)


def test_hook_checks_skipped_when_fields_missing():
    cap = clean_capture()
    del cap["hook_stealth"]
    report = run_rgate(cap)
    hook_ids = {"CLR-HOOK-01", "CLR-HOOK-02", "CLR-HOOK-03", "CLR-HOOK-04"}
    assert hook_ids <= skip_ids(report)
    assert not (hook_ids & hit_ids(report)), "字段缺失不得计命中"
