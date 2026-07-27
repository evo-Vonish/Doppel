"""观测流水线包（M3：解密 → 结构化 → 落库）。

模块分工见 SPEC-M2M3 §2.1：
    events   事件 Schema v0.1（字段/枚举一字不动按 M3 方案 §3.1/§3.2）
    keylog   NSS SSLKEYLOGFILE 解析
    aligner  握手 random ↔ keylog 对齐与覆盖率统计
    decrypt  tshark 批处理解密封装（-o tls.keylog_file → -T json）
    store    events.db 落库（WAL、批量、retain_days 清理）
    query    query_events（cli events 子命令消费，签名固定）
    daemon   环形分片批处理主循环（容器内旁路运行）
"""
