"""替身 M4 对抗测试工具包（SPEC-M4 §1）。

本包承载「运行时兑现」侧的对抗测试能力：
- ``clr_checklist_v1``：CLR 跨层一致性清单 v1（60–80 条，四来源 + tishen 自研标注）；
- ``rgate``：R-Gate 运行时一致性 linter，吃探针采集的 FingerprintCapture JSON，
  执行清单全部断言并输出命中项与证据（纯函数，无 I/O）；
- ``report``（T4）：分组/分入口统计与 Markdown 报告生成。

与出厂门禁 V-Gate（``tishen.linter``，规格层查 persona.yaml）互补：
V-Gate 查「规格自洽」，本包查「运行时兑现」。
"""
