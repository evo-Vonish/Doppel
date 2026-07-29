"""L2 载荷确认分析器（SPEC-E2 件二 §F1–F3）：JS / WASM 载荷静态确认与证据增强。

定位（SPEC-E2 §F1）：L2 只做**确认与证据增强**——本模块输出的
:class:`PayloadVerdict` 仅作为 E3 的确认信号加权输入，**永不单独触发告警**；
接入 ``decide_level`` 的改动不在本件（方案 §二铁律：混淆 WASM 可绕过 L2，
必须以 L1 行为通道兜底）。

纪律（SPEC-E §0 / SPEC-E2 §F4）：
- 纯标准库，零第三方依赖；熵计算用 ``math.log2`` 自行实现；
- 与 behavior.py 零耦合（不 import 任何 engine 模块）；
- 本件不做 daemon 集成，挂点仅留 TODO 注释。

F3 采样通道协议（payload_sample JSONL，仅文档化，hook 侧代码不在本件）
----------------------------------------------------------------------

未来 hook 层/阻断层将采样写入 ``/persona/logs/payload/samples.jsonl``，每行一条
JSON 对象，schema 如下（SPEC-E2 §F3）::

    {"sha256": str,              # 载荷全文 sha256（hex）
     "kind": "js"|"wasm",        # 载荷类型，analyze_sample 据此分派
     "size": int,                # 载荷全文长度（字节数）
     "head_b64": str,            # 载荷前 64KB 的 base64 编码
     "source_url": str|null,     # 载荷来源 URL，未知为 null
     "ts": int}                  # 采样时刻（Unix epoch 秒）

:func:`analyze_sample` 消费**单条**已解析的 dict（kind 分派到 analyze_js /
analyze_wasm）；坏行（坏 JSON / 缺键 / 坏 base64 / 未知 kind）由调用侧或
:func:`iter_verdicts` 容错跳过并计数。sha256 字段若缺失/与内容不符，以
实际解码内容重算为准（证据自洽）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------------------
# F2 PayloadVerdict（SPEC-E2 §F2 签名契约）
# ---------------------------------------------------------------------------


@dataclass
class PayloadVerdict:
    subject_hash: str          # 载荷 sha256（hex）
    kind: str                  # "js" / "wasm"
    score: int                 # 0–100
    findings: list[str]        # 命中项 id，排序去重（id 表见下）


# ---------------------------------------------------------------------------
# F2 JS 发现项（js-x-ray 子集重实现，SPEC-E2 §F2 表）
# ---------------------------------------------------------------------------

JS_FINDINGS = {
    "js.obfuscated_identifiers": 25,  # 十六进制/下划线混淆标识符占比 >30%
    "js.encoded_literals": 20,        # 长 base64/hex 字符串（≥64 字符）≥3 条
    "js.eval_chain": 25,              # eval/Function/atob/unescape 组合调用链
    "js.miner_signature": 40,         # cryptonight/stratum/coinhive 等签名串
    "js.wasm_loop_pattern": 20,       # instantiate + 紧密集约调用模式
    "js.exfil_beacon": 15,            # sendBeacon/fetch POST 与指纹读取共现
    "js.high_entropy": 15,            # 全文香农熵 >5.2 且长度 >10KB（混淆度量）
}

# 矿工签名常量表（SPEC-E2 §F2：≥10 条，逐条注释来源）。
# 来源缩写：CBL = CoinBlockerLists（github.com/hoshsadiq/adblock-nocoin-list
# / ZeroDot1 的 CoinBlockerLists）；uAssets = uBlock Origin 资源库
# （github.com/uBlockOrigin/uAssets 的 filters/privacy.txt 与 badware 清单）。
MINER_SIGNATURES = (
    "cryptonight",            # CBL：CryptoNight 算法名，CoinHive 系矿工核心串
    "cn/aesni",               # CBL：cryptonight wasm 内部函数导出名
    "stratum+tcp://",         # uAssets badware：矿工 stratum 矿池协议前缀
    "stratum+ssl://",         # CBL：TLS 版 stratum 池前缀
    "coinhive.min.js",        # CBL：CoinHive 官方投放脚本文件名
    "CoinHive.Anonymous",     # uAssets badware：CoinHive JS API 入口构造器
    "coinhive.com",           # CBL：CoinHive 主域（已关停，仍见于存量注入）
    "minero.cc",              # CBL：Minero 矿池域
    "webminerpool.com",       # CBL：webminerpool 池域
    "cryptoloot.pro",         # CBL：Crypto-Loot（CoinHive 克隆）域
    "jsecoin.com",            # CBL：JSEcoin 浏览器挖矿域
    "crypto-loot.com",        # CBL：Crypto-Loot 备用域
    "hashing.power",          # uAssets：CoinHive 脚本内上报字段名片段
    "wasmBinaryFile",         # uAssets：Emscripten 矿工加载器特征串
    "moneroocean.stream",     # CBL：MoneroOcean 池域
    "supportxmr.com",         # CBL：SupportXMR 池域（浏览器挖矿常见目标）
)

# ---------------------------------------------------------------------------
# F2 WASM 发现项（SPEC-E2 §F2）
# ---------------------------------------------------------------------------

WASM_FINDINGS = {
    "wasm.bad_magic": 30,      # 魔数+版本校验失败
    "wasm.pool_section": 40,   # 自定义 section 含已知矿池名
    "wasm.import_bloat": 20,   # import 函数计数 >200
    "wasm.packed": 15,         # 字节熵 >7.5
    "wasm.stripped": 10,       # 无 name section 且 import_bloat 同现
}

WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"
_IMPORT_BLOAT_THRESHOLD = 200
# 自定义 section 矿池名匹配复用 MINER_SIGNATURES（池域与协议串同一来源表）

# ---------------------------------------------------------------------------
# 内部工具：香农熵（math.log2 自实现，SPEC 件二契约）
# ---------------------------------------------------------------------------


def _shannon_entropy(data: bytes) -> float:
    """字节级香农熵（bits/byte）；空数据返回 0.0。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verdict(kind: str, data: bytes, hit_ids: set[str], weights: dict) -> PayloadVerdict:
    score = min(100, sum(weights[i] for i in hit_ids))
    return PayloadVerdict(
        subject_hash=_sha256_hex(data),
        kind=kind,
        score=score,
        findings=sorted(hit_ids),
    )


# ---------------------------------------------------------------------------
# F2 JS 检测器（各发现项正反判定）
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
# 混淆标识符：_0x 开头十六进制风格（_0x4a3f）或超长下划线串（____x）
_OBFUSCATED_RE = re.compile(r"^(?:_0[xX][0-9a-fA-F]+|_{3,}\w*)$")
# 长 base64/hex 字符串字面量（≥64 字符；hex 字符集是 base64 类子集，
# 单一正则覆盖避免同一字面量重复计数）
_LONG_LITERAL_RE = re.compile(r"(['\"])(?:0x)?([A-Za-z0-9+/=_-]{64,})\1")

_EVAL_CALLS_RE = re.compile(
    r"\b(?:eval|atob|unescape|setTimeout|setInterval)\s*\(|"
    r"\bFunction\s*\(|new\s+Function\b"
)

_BEACON_RE = re.compile(r"\bnavigator\.sendBeacon\s*\(|fetch\s*\(")
_POST_RE = re.compile(r"method\s*:\s*['\"]POST['\"]")
_FP_READ_RE = re.compile(
    r"\b(?:getImageData|toDataURL|getBattery|"
    r"navigator\.(?:userAgent|platform|hardwareConcurrency|deviceMemory|languages)|"
    r"screen\.(?:width|height|colorDepth)|"
    r"AudioContext|getChannelData|getFloatFrequencyData|"
    r"getParameter|getSupportedExtensions)\b"
)
_WASM_INSTANTIATE_RE = re.compile(r"\bWebAssembly\.(?:instantiate|instantiateStreaming)\s*\(")


def _obfuscated_ratio(source: str) -> float:
    idents = _IDENT_RE.findall(source)
    if len(idents) < 20:      # 样本太小不做占比判定，防短脚本误报
        return 0.0
    obf = sum(1 for i in idents if _OBFUSCATED_RE.match(i))
    return obf / len(idents)


def _has_eval_chain(source: str) -> bool:
    """eval/Function/atob/unescape 组合调用链：≥2 种动态求值原语共现，
    或任一原语出现在另一原语调用的参数内（链式）。"""
    kinds = set(re.findall(r"\b(eval|atob|unescape|Function)\b", source))
    if len(kinds) >= 2 and _EVAL_CALLS_RE.search(source):
        return True
    # 链式：eval(atob(...)) / Function(unescape(...)) 等
    return bool(re.search(
        r"\b(?:eval|atob|unescape|Function)\s*\([^)]*\b(?:eval|atob|unescape|Function)\s*\(",
        source,
    ))


def _has_wasm_loop_pattern(source: str) -> bool:
    """instantiate + 紧密集约调用：实例化结果导出函数在循环中被密集调用。"""
    if not _WASM_INSTANTIATE_RE.search(source):
        return False
    # instantiate 之后出现循环内调用导出函数（exports.<fn>(...) 于 for/while 体内）
    if re.search(
        r"(?:for|while)\s*\([^)]*\)\s*\{[^}]*\b(?:exports|instance)\.[A-Za-z_$][\w$]*\s*\(",
        source,
        re.DOTALL,
    ):
        return True
    # 退化形态：instantiate().then(...) 回调体内含循环（矿工恒载模式）
    return bool(re.search(r"\.then\s*\(", source) and re.search(r"(?:for|while)\s*\(", source))


def _has_exfil_beacon(source: str) -> bool:
    """sendBeacon/fetch POST 与指纹读取同文件共现。"""
    has_send = bool(_BEACON_RE.search(source))
    has_post = bool(_POST_RE.search(source)) or "sendBeacon" in source
    return has_send and has_post and bool(_FP_READ_RE.search(source))


def analyze_js(source: str, *, max_len: int = 2_000_000) -> PayloadVerdict:
    """分析 JS 源码，返回 :class:`PayloadVerdict`（SPEC-E2 §F2）。

    ``max_len`` 截断防爆：超出部分不计入检测与哈希（证据只覆盖截断前缀，
    findings 中不额外标注，调用侧负责按 size 分流大文件）。
    """
    if not isinstance(source, str):
        raise TypeError("source must be str")
    src = source[:max_len]
    data = src.encode("utf-8", errors="replace")
    hits: set[str] = set()

    if _obfuscated_ratio(src) > 0.30:
        hits.add("js.obfuscated_identifiers")

    if len(_LONG_LITERAL_RE.findall(src)) >= 3:
        hits.add("js.encoded_literals")

    if _has_eval_chain(src):
        hits.add("js.eval_chain")

    lowered = src.lower()
    if any(sig.lower() in lowered for sig in MINER_SIGNATURES):
        hits.add("js.miner_signature")

    if _has_wasm_loop_pattern(src):
        hits.add("js.wasm_loop_pattern")

    if _has_exfil_beacon(src):
        hits.add("js.exfil_beacon")

    if len(data) > 10_000 and _shannon_entropy(data) > 5.2:
        hits.add("js.high_entropy")

    return _verdict("js", data, hits, JS_FINDINGS)


# ---------------------------------------------------------------------------
# F2 WASM 检测器（struct 级手工解析 header/section/import）
# ---------------------------------------------------------------------------

def _read_uleb(data: bytes, pos: int) -> tuple[int, int]:
    """读 unsigned LEB128；返回 (值, 新位置)。截断抛 ValueError。"""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated uleb128")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 too long")


def _iter_sections(data: bytes) -> list[tuple[int, bytes]]:
    """遍历 section：返回 [(section_id, payload_bytes)]；坏结构抛 ValueError。"""
    if len(data) < 8 or data[:8] != WASM_MAGIC:
        raise ValueError("bad magic/version")
    sections = []
    pos = 8
    while pos < len(data):
        sec_id = data[pos]
        pos += 1
        size, pos = _read_uleb(data, pos)
        if pos + size > len(data):
            raise ValueError("truncated section")
        sections.append((sec_id, data[pos:pos + size]))
        pos += size
    return sections


def _skip_limits(payload: bytes, pos: int) -> int:
    if pos >= len(payload):
        raise ValueError("truncated limits")
    flag = payload[pos]
    pos += 1
    _, pos = _read_uleb(payload, pos)  # min
    if flag in (1, 3):
        _, pos = _read_uleb(payload, pos)  # max
    return pos


def _count_import_functions(payload: bytes) -> int:
    """统计 import section 中 kind==0（func）的条目数。"""
    if not payload:
        return 0
    count, pos = _read_uleb(payload, 0)
    funcs = 0
    for _ in range(count):
        for _part in range(2):  # module 名 + field 名
            slen, pos = _read_uleb(payload, pos)
            pos += slen
            if pos > len(payload):
                raise ValueError("truncated import name")
        if pos >= len(payload):
            raise ValueError("truncated import entry")
        kind = payload[pos]
        pos += 1
        if kind == 0:                # func：其后一个 typeidx uleb
            funcs += 1
            _, pos = _read_uleb(payload, pos)
        elif kind == 1:              # table：reftype(1B) + limits
            pos += 1
            pos = _skip_limits(payload, pos)
        elif kind == 2:              # memory：limits
            pos = _skip_limits(payload, pos)
        elif kind == 3:              # global：valtype(1B) + mut(1B)
            pos += 2
        else:
            raise ValueError("unknown import kind")
    return funcs


def _custom_section_name(payload: bytes) -> str | None:
    try:
        nlen, pos = _read_uleb(payload, 0)
        raw = payload[pos:pos + nlen]
        return raw.decode("utf-8", errors="replace")
    except (ValueError, IndexError):
        return None


def analyze_wasm(data: bytes) -> PayloadVerdict:
    """分析 WASM 字节载荷，返回 :class:`PayloadVerdict`（SPEC-E2 §F2）。

    魔数+版本失败时记 ``wasm.bad_magic``，其余结构化检测跳过（字节熵仍计算）。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    hits: set[str] = set()

    sections: list[tuple[int, bytes]] = []
    if len(data) < 8 or data[:8] != WASM_MAGIC:
        hits.add("wasm.bad_magic")
    else:
        try:
            sections = _iter_sections(data)
        except ValueError:
            hits.add("wasm.bad_magic")
            sections = []

    has_name_section = False
    import_bloat = False
    for sec_id, payload in sections:
        if sec_id == 0:  # custom section
            name = _custom_section_name(payload)
            if name == "name":
                has_name_section = True
            hay = payload.decode("utf-8", errors="replace").lower()
            if any(sig.lower() in hay for sig in MINER_SIGNATURES):
                hits.add("wasm.pool_section")
        elif sec_id == 2:  # import section
            try:
                if _count_import_functions(payload) > _IMPORT_BLOAT_THRESHOLD:
                    import_bloat = True
            except ValueError:
                hits.add("wasm.bad_magic")

    if import_bloat:
        hits.add("wasm.import_bloat")
        if not has_name_section:
            hits.add("wasm.stripped")

    if _shannon_entropy(data) > 7.5:
        hits.add("wasm.packed")

    return _verdict("wasm", data, hits, WASM_FINDINGS)


# ---------------------------------------------------------------------------
# F3 采样协议消费（SPEC-E2 §F3）
# ---------------------------------------------------------------------------


def analyze_sample(sample: dict) -> PayloadVerdict:
    """消费单条 payload_sample（SPEC-E2 §F3），按 ``kind`` 分派。

    坏样本（缺键 / 坏 base64 / 未知 kind）抛 :class:`ValueError`，
    由 :func:`iter_verdicts` 或调用侧容错计数。
    """
    if not isinstance(sample, dict):
        raise ValueError("sample must be dict")
    kind = sample.get("kind")
    head_b64 = sample.get("head_b64")
    if not isinstance(head_b64, str):
        raise ValueError("sample missing head_b64")
    try:
        head = base64.b64decode(head_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"bad head_b64: {exc}") from exc

    if kind == "js":
        verdict = analyze_js(head.decode("utf-8", errors="replace"))
    elif kind == "wasm":
        verdict = analyze_wasm(head)
    else:
        raise ValueError(f"unknown kind: {kind!r}")
    return verdict


def iter_verdicts(lines: Iterable[str]) -> tuple[list[PayloadVerdict], int]:
    """消费 payload_sample JSONL 行流；坏行（坏 JSON/缺键/坏 base64/未知
    kind）容错跳过并计数。返回 ``(verdicts, skipped)``。"""
    verdicts: list[PayloadVerdict] = []
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            sample = json.loads(line)
            verdicts.append(analyze_sample(sample))
        except (ValueError, TypeError):
            skipped += 1
    return verdicts, skipped


# TODO(SPEC-E2 §F3)：daemon 集成挂点——未来 daemon 消费
# /persona/logs/payload/samples.jsonl 时在此处接入 iter_verdicts，
# 将 PayloadVerdict 作为 E3 确认信号加权喂给 scorer.decide_level；
# 本件不改 daemon.py，避免半集成。
