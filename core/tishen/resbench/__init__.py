"""resbench —— M5 资源基线工具链（SPEC-M5，上位文档《替身计划-M5实施方案》）。

回答一个问题：一个替身日常使用要吃多少资源，休眠-唤醒是否可靠，2GB 验收线是否成立。

模块划分（SPEC-M5 §1 文件所有权）：
- sampler   R1 资源采样器（docker stats 解析 + 周期采样落 resbench.db），Coder X；
- bootprobe R2 启动计时探针（BOOT_MARK 解析 + boots/boot_segments 落库 + 端口探测），Coder X；
- fidelity  R3 休眠-唤醒保真校验，Coder Y；
- report    R4 中文 Markdown 报告，Coder Y。

跨模块唯一集成事实源是 resbench.db 的 Schema（SPEC-M5 §2，一字不动）；
本 __init__ 不导出任何符号（Y 侧模块经命名空间包机制并存，互不 import）。
"""
