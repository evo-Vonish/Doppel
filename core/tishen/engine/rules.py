"""E2 请求匹配层（SPEC-E §2，Coder A 拥有）。

ABP 过滤规则语法子集（SPEC-E §2.1）：
- 支持：`@@` 例外、`||domain.tld` 域名锚定（含 path 通配 `*`、`^` 分隔边界）、
  裸 substring（含 `*`）、`$third-party`/`$~third-party`、`$domain=a.com|~b.com`；
- 不支持（跳过并计数，不报错不假装支持）：元素隐藏 `##`/`#@#`、正则 `/.../ `、
  其余 `$` 修饰（script/image/csp/redirect/important 等）。

匹配算法（SPEC-E §2.2 四步）：
① host 列索引候选（domain_anchor：target_host == host 或以其为后缀边界）
   + 全表 substring 候选；
② 例外规则优先于 block；
③ third_party 由 target_host 与 page_host 的注册域名比较得出——注册域名
   取**末两段**（如 `a.b.example.co.uk` → `co.uk`），eTLD 精度不做，属
   **近似判断**口径（在函数 docstring 中亦注明）；
④ domain_modifier 过滤。命中多条时：例外 > block，同 kind 取 rule_id
字典序最小（确定性）。
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit

# 支持的修饰符（SPEC-E §2.1）；其余 $ 修饰一律跳过计数
_SUPPORTED_MODIFIERS = {"third-party", "~third-party"}

# ABP `^` 分隔符语义：非字母数字及 _-.% 的字符，或串尾（SPEC-E §2.1 "视作边界"）
_SEPARATOR_RE = r"(?:[^A-Za-z0-9_\-.%]|$)"


@dataclass
class Rule:
    """与 rules 表列一一对应（SPEC-E §2.2）。"""

    rule_id: str            # "<source>:<sha1(raw)[:12]>"
    raw: str                # 原始规则行
    kind: str               # block / exception
    pattern_type: str       # domain_anchor / substring
    host: str | None        # domain_anchor 的锚定域名
    path_pattern: str | None  # 域名之后的 path 通配（无则 None）
    third_party: int | None  # 1 仅第三方 / 0 仅第一方 / None 不限
    domain_modifier: str | None  # $domain= 原样存（'|' 分隔）
    source: str             # easyprivacy / trackerdb


@dataclass
class ParseStats:
    """解析计数（SPEC-E §2.2）。不变量：total == supported + skipped。"""

    total: int = 0
    supported: int = 0
    skipped: int = 0
    by_skip_reason: dict[str, int] = field(default_factory=dict)


@dataclass
class MatchResult:
    """match_url 返回（SPEC-E §2.2）。hit=False 时其余字段为 False/None。"""

    hit: bool
    exception: bool
    rule_id: str | None
    raw: str | None


def _rule_id(raw: str, source: str) -> str:
    """SPEC-E §1.1：rule_id = "<source>:<sha1(raw)[:12]>"。"""
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{source}:{digest}"


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """把 ABP 通配片段编译成正则：`*`→任意串，`^`→分隔符边界，其余转义。"""
    out: list[str] = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(_SEPARATOR_RE)
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out))


def _split_modifiers(body: str) -> tuple[str, list[str]] | None:
    """拆 `$` 修饰段；返回 (pattern, modifiers)。pattern 含 `$` 非法形态时返回 None。"""
    if "$" not in body:
        return body, []
    pattern, _, mod_str = body.partition("$")
    if not mod_str:
        return None
    return pattern, [m.strip() for m in mod_str.split(",") if m.strip()]


def parse_abp_lines(lines: Iterable[str], source: str) -> tuple[list[Rule], ParseStats]:
    """解析 ABP 规则行流（SPEC-E §2.1 子集），返回 (规则列表, 计数)。

    不支持的语法一律跳过并在 ParseStats.by_skip_reason 计数，绝不报错、
    绝不降级成错误的支持。total 覆盖所有行（含注释与空行）。
    """
    rules: list[Rule] = []
    stats = ParseStats()

    def _skip(reason: str) -> None:
        stats.skipped += 1
        stats.by_skip_reason[reason] = stats.by_skip_reason.get(reason, 0) + 1

    for line in lines:
        stats.total += 1
        text = line.strip()
        if not text:
            _skip("blank")
            continue
        if text.startswith("!") or (text.startswith("[") and text.endswith("]")):
            _skip("comment")
            continue
        if "##" in text or "#@#" in text:
            _skip("element_hiding")
            continue

        kind = "block"
        body = text
        if body.startswith("@@"):
            kind = "exception"
            body = body[2:]

        if body.startswith("/") and (body.endswith("/") or "/$" in body):
            _skip("regex")  # /.../ 或 /.../$modifiers 正则规则不支持
            continue

        split = _split_modifiers(body)
        if split is None:
            _skip("malformed")
            continue
        pattern, modifiers = split

        third_party: int | None = None
        domain_modifier: str | None = None
        unsupported = False
        for mod in modifiers:
            low = mod.lower()
            if low == "third-party":
                third_party = 1
            elif low == "~third-party":
                third_party = 0
            elif low.startswith("domain="):
                domain_modifier = mod[len("domain="):]
            else:
                unsupported = True
                break
        if unsupported:
            _skip("unsupported_modifier")
            continue

        host: str | None = None
        path_pattern: str | None = None
        if pattern.startswith("||"):
            # 域名锚定：host 取到首个 '^'/'/' 为止，其余为 path 通配
            rest = pattern[2:]
            m = re.match(r"^([^\^/*]+)(.*)$", rest)
            if not m:
                _skip("malformed")
                continue
            host = m.group(1).lower()
            if not host or "." not in host or any(c in host for c in " \t"):
                _skip("malformed")
                continue
            tail = m.group(2)
            # host 之后必有边界（'/'、query 或串尾），path 通配前导的 '^'
            # 分隔符按 SPEC-E §2.1"视作边界"剥除字面值，否则匹配时会错误
            # 消费掉 URL path 的首字符导致永不命中
            if tail.startswith("^"):
                tail = tail[1:]
            if tail:
                path_pattern = tail
            pattern_type = "domain_anchor"
        else:
            if not pattern:
                _skip("malformed")
                continue
            pattern_type = "substring"

        rules.append(Rule(
            rule_id=_rule_id(text, source),
            raw=text,
            kind=kind,
            pattern_type=pattern_type,
            host=host,
            path_pattern=path_pattern,
            third_party=third_party,
            domain_modifier=domain_modifier,
            source=source,
        ))
        stats.supported += 1

    return rules, stats


def import_rules(conn: sqlite3.Connection, rules: list[Rule],
                 source: str) -> ParseStats:
    """事务批量导入（SPEC-E §2.2）：先删该 source 旧规则（幂等重导）。"""
    sql = (
        "INSERT OR REPLACE INTO rules"
        " (rule_id, raw, kind, pattern_type, host, path_pattern,"
        "  third_party, domain_modifier, source)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    rows = [(r.rule_id, r.raw, r.kind, r.pattern_type, r.host, r.path_pattern,
             r.third_party, r.domain_modifier, r.source) for r in rules]
    with conn:
        conn.execute("DELETE FROM rules WHERE source = ?", (source,))
        conn.executemany(sql, rows)
    return ParseStats(total=len(rules), supported=len(rules), skipped=0,
                      by_skip_reason={})



def _fetch_rule_dicts(conn: sqlite3.Connection, sql: str,
                      params) -> list[dict]:
    """查询 rules 并返回 dict 行。

    不设置 conn.row_factory——match_url 不得污染调用方共享连接的
    属性（Wave2 daemon 复用同一连接）。
    """
    cur = conn.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def registered_domain(host: str) -> str:
    """注册域名近似判断：**取末两段**（SPEC-E §2.2 ③口径）。

    不做 eTLD 精度（`a.example.co.uk` 近似为 `co.uk`），仅用于 third-party
    的比较判定；误判代价已按 SPEC 接受。
    """
    labels = host.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _host_boundary_match(host: str, anchor: str) -> bool:
    """target_host == anchor 或以 anchor 为后缀边界（`.` 分隔）。"""
    return host == anchor or host.endswith("." + anchor)


def _domain_modifier_ok(rule: dict | Rule, page_host: str | None) -> bool:
    """$domain= 修饰过滤（SPEC-E §2.2 ④，作用于 page_host）。

    列表含正项时 page_host 必须命中其一；`~` 取反项命中则否决。
    page_host 为 None 时：有正项即不满足，纯取反列表视为通过。
    """
    raw = rule["domain_modifier"] if isinstance(rule, dict) else rule.domain_modifier
    if not raw:
        return True
    positives: list[str] = []
    negatives: list[str] = []
    for item in raw.split("|"):
        item = item.strip().lower()
        if not item:
            continue
        (negatives if item.startswith("~") else positives).append(
            item[1:] if item.startswith("~") else item)

    def _hit(d: str) -> bool:
        return page_host is not None and _host_boundary_match(page_host.lower(), d)

    if any(_hit(d) for d in negatives):
        return False
    if positives:
        return any(_hit(d) for d in positives)
    return True


def match_url(conn: sqlite3.Connection, target_url: str,
              page_host: str | None) -> MatchResult:
    """按 SPEC-E §2.2 四步匹配 target_url，返回确定性结果。

    注册域名近似判断口径：末两段（不做 eTLD 精度）；page_host 为 None 时
    请求按第三方处理（无法证明同站，从严）。
    """
    try:
        target_host = (urlsplit(target_url).hostname or "").lower()
    except ValueError:
        target_host = ""
    if not target_host:
        return MatchResult(hit=False, exception=False, rule_id=None, raw=None)

    # ① 候选：host 列索引（target_host 的全部父域后缀）+ 全表 substring
    labels = target_host.split(".")
    suffixes = [".".join(labels[i:]) for i in range(0, max(len(labels) - 1, 1))]
    anchored: list[dict] = []
    if suffixes:
        marks = ",".join("?" for _ in suffixes)
        anchored = _fetch_rule_dicts(conn,
            f"SELECT * FROM rules WHERE pattern_type = 'domain_anchor'"
            f" AND host IN ({marks})", suffixes)
    substrings = _fetch_rule_dicts(conn,
        "SELECT * FROM rules WHERE pattern_type = 'substring'", ())

    # ③ third_party：注册域名（末两段近似）比较；page 未知从严按第三方
    is_third_party = True
    if page_host:
        is_third_party = registered_domain(target_host) != registered_domain(page_host.lower())

    url_after_host = urlsplit(target_url).path or "/"
    if urlsplit(target_url).query:
        url_after_host += "?" + urlsplit(target_url).query
    regex_cache: dict[str, re.Pattern[str]] = {}

    def _pattern_ok(row: dict) -> bool:
        if row["pattern_type"] == "domain_anchor":
            if not _host_boundary_match(target_host, row["host"]):
                return False
            pp = row["path_pattern"]
            if pp is None:
                return True
            rx = regex_cache.get(row["rule_id"])
            if rx is None:
                rx = _pattern_to_regex(pp)
                regex_cache[row["rule_id"]] = rx
            return rx.match(url_after_host) is not None
        raw_pat = row["raw"]
        body = raw_pat[2:] if raw_pat.startswith("@@") else raw_pat
        pat = body.partition("$")[0]
        rx = regex_cache.get(row["rule_id"])
        if rx is None:
            rx = _pattern_to_regex(pat)
            regex_cache[row["rule_id"]] = rx
        return rx.search(target_url) is not None

    hits: list[dict] = []
    for row in (*anchored, *substrings):
        if not _pattern_ok(row):
            continue
        if row["third_party"] is not None and int(row["third_party"]) != (1 if is_third_party else 0):
            continue  # ③ 第三方限定不符
        if not _domain_modifier_ok(row, page_host):
            continue  # ④ domain 修饰过滤
        hits.append(row)

    if not hits:
        return MatchResult(hit=False, exception=False, rule_id=None, raw=None)

    # ② 例外优先于 block；同 kind 取 rule_id 字典序最小（确定性）
    hits.sort(key=lambda r: (0 if r["kind"] == "exception" else 1, r["rule_id"]))
    top = hits[0]
    return MatchResult(hit=True, exception=top["kind"] == "exception",
                       rule_id=top["rule_id"], raw=top["raw"])
