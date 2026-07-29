"""判别引擎工具链（SPEC-E §0 纪律、§9 文件所有权表）。

包内分层：
- trackerdb.py：数据集归一化库 trackerdb.db（SPEC-E §1.1）；
- rules.py：E2 请求匹配层，ABP 子集解析与匹配（SPEC-E §2）；
- entity.py / daemon.py / datasets/*：E1 实体归因与在线消费循环（Wave2）。

纪律（SPEC-E §0）：纯标准库 + sqlite3；观测层 events.db 只回写
`alert_level` 与 `engine_tags` 两列；单一可疑 API 调用永不触发
级别 ≥2 告警；核心路径只依赖非 NC 数据源。
"""

from __future__ import annotations
