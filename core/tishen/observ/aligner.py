"""密钥-会话对齐器（M3 方案 §2.1 环节①、§4 完整率工程）。

职责：tshark 提取的握手 ClientHello.random ↔ keylog CLIENT_RANDOM 索引做匹配，
显式标出"缺密钥会话"（no_key）——这是完整率口径的分母来源，
tshark 自身不会主动报告，故对齐必须自研前置（M3 方案 §2.2 表）。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HandshakeRecord:
    """一次 TLS 握手的元数据（由 decrypt.extract_handshakes 从 tshark JSON 提取）。"""
    client_random: str                 # ClientHello.random，小写十六进制
    sni: str | None = None             # ClientHello SNI（可能为空）
    ts_ms: int = 0                     # Unix 毫秒（pcap 包时间戳）
    frame_number: int = 0              # pcap 帧号（evidence_ref 用）
    stream: str | None = None          # tshark 流标识（tcp.stream / quic.stream）

    @property
    def host(self) -> str:
        """按 host 聚合口径：优先 SNI，无 SNI 归入 (unknown)。"""
        return self.sni if self.sni else "(unknown)"


@dataclass
class HostCoverage:
    """单 host 的覆盖率统计。"""
    matched: int = 0                   # 有密钥可解密的握手数
    total: int = 0                     # 观测到的握手总数
    gap_frames: list[int] = field(default_factory=list)  # 缺钥握手的帧号列表


@dataclass
class AlignmentReport:
    """对齐结果全集（§4.3 流完整率口径的直接数据源）。

    流完整率 = matched ÷ total（按 ClientHello 计）。
    """
    matched: int = 0                   # 命中 keylog 的握手数
    total: int = 0                     # 握手总数
    no_key: list[HandshakeRecord] = field(default_factory=list)   # 缺钥会话清单
    per_host: dict[str, HostCoverage] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        """流完整率；无握手时定义为空洞率未知，返回 1.0（不制造假缺口）。"""
        if self.total == 0:
            return 1.0
        return self.matched / self.total

    def as_dict(self) -> dict:
        """序列化为可落盘/落日志的 dict（daemon 写对齐报告用）。"""
        return {
            "matched": self.matched,
            "total": self.total,
            "coverage": round(self.coverage, 6),
            "no_key": [
                {"sni": r.sni, "frame_number": r.frame_number,
                 "client_random": r.client_random}
                for r in self.no_key
            ],
            "per_host": {
                host: {"matched": c.matched, "total": c.total,
                       "gap_frames": list(c.gap_frames)}
                for host, c in sorted(self.per_host.items())
            },
        }


def normalize_client_random(value: str) -> str:
    """统一 NSS 无分隔与 tshark 冒号分隔的 ClientHello random。"""
    return str(value).replace(":", "").lower()


def align(handshakes, keylog_map: dict[str, str]) -> AlignmentReport:
    """握手清单 ↔ keylog 映射对齐，输出覆盖率报告。

    - handshakes: HandshakeRecord 列表（一个 ClientHello 一条）；
    - keylog_map: parse_keylog_index() 产物
      {client_random_hex: representative_secret_hex}（小写键）；
    - 匹配不区分大小写（tshark 输出十六进制大小写依版本不定）。
    """
    report = AlignmentReport()
    normalized = {normalize_client_random(k): v for k, v in keylog_map.items()}
    for rec in handshakes:
        report.total += 1
        cov = report.per_host.setdefault(rec.host, HostCoverage())
        cov.total += 1
        if normalize_client_random(rec.client_random) in normalized:
            report.matched += 1
            cov.matched += 1
        else:
            report.no_key.append(rec)
            cov.gap_frames.append(rec.frame_number)
    return report
