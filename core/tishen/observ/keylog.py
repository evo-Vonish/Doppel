"""NSS SSLKEYLOGFILE 解析（M3 方案 §2.1：Chrome --ssl-key-log-file 落盘格式）。

格式（每行一条，# 开头为注释）：
    CLIENT_RANDOM <client_random_hex> <secret_hex>
    CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
    ...（TLS 1.3 其余 label 同构）

对外兼容接口 parse_keylog() 只回 CLIENT_RANDOM 映射；现代 Chrome 的 TLS 1.3
会话可能完全不写该标签，因此对齐器使用 parse_keylog_index() 合并所有合法标签的
client_random，避免把已由 tshark 解密的 TLS 1.3 会话误报为 no_key。
"""

from __future__ import annotations

from pathlib import Path

# 已知 label 全集（NSS 1.3 扩展），未识别 label 行同样收录进 labels 桶
KNOWN_LABELS = frozenset({
    "CLIENT_RANDOM",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET", "EARLY_EXPORTER_SECRET",
})


def parse_keylog_lines(lines) -> dict[str, dict[str, str]]:
    """逐行解析 → {label: {client_random_hex: secret_hex}}。

    容错纪律：空行 / 注释 / 列数不对 / 非十六进制——一律跳过，
    keylog 是浏览器热写文件，读到半行属常态，绝不能因此中断观测。
    """
    buckets: dict[str, dict[str, str]] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, client_random, secret = parts
        # 十六进制粗校验（不要求定长，TLS1.2/1.3 密钥长度不同）
        try:
            bytes.fromhex(client_random)
            bytes.fromhex(secret)
        except ValueError:
            continue
        buckets.setdefault(label, {})[client_random.lower()] = secret
    return buckets


def parse_keylog(path) -> dict[str, str]:
    """解析 keylog 文件 → {client_random_hex: secret_hex}（仅 CLIENT_RANDOM 行）。

    client_random 统一小写，便于与 tshark 提取的握手 random 对齐。
    文件不存在 / 不可读时返回空 dict——缺钥按 no_key 口径统计，不 crash。
    """
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            buckets = parse_keylog_lines(f)
    except OSError:
        return {}
    return buckets.get("CLIENT_RANDOM", {})


def parse_keylog_all(path) -> dict[str, dict[str, str]]:
    """解析全部 label 分桶（TLS 1.3 会话密钥在独立 label 行，供后续解密环节使用）。"""
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            return parse_keylog_lines(f)
    except OSError:
        return {}


def parse_keylog_index(path) -> dict[str, str]:
    """构造跨 TLS 1.2/1.3 标签的 ClientHello random 对齐索引。

    NSS keylog 每个合法三列标签的第二列均为 ClientHello random。对齐只检查
    random 是否存在，不使用映射值做解密；实际密钥仍由完整 keylog 文件交给
    tshark。未知未来标签也由 parse_keylog_lines 做十六进制校验后纳入。
    """
    buckets = parse_keylog_all(path)
    index: dict[str, str] = {}
    for values in buckets.values():
        for client_random, secret in values.items():
            index.setdefault(client_random, secret)
    return index
