# 替身 Tishen M4 · 对抗测试工具链（T2 CreepJS 自托管 + T3 探针 harness）

契约依据：SPEC-M4（§2 FingerprintCapture / §4 probe.db / §5 T2-T3 交付）。
唯一契约，跨 Coder 集成全靠它；本目录文件归 Coder B 所有。

## 目录

```
tools/adversarial/
  README.md                    # 本文件
  creepjs_selfhost/            # T2：CreepJS（MIT）自托管 + 结果导出
    setup.sh                   # 幂等 clone（--depth 1）到 ./repo，commit 落 commit.txt
    serve.sh                   # 静态 serve repo 于 127.0.0.1:8791
    extract_inpage.js          # 在 CreepJS 页控制台执行：产出 §4 creepjs_export JSON
    import_export.py           # 把提取的 JSON 写入 probe.db（entry=creepjs）
  harness/                     # T3：探针页 + 收集器 + 结果录入
    probe.html                 # 探针页（纯原生 JS 零外链）：采集 §2 全部字段
    serve_probe.sh             # 静态 serve harness/ 于 127.0.0.1:8789
    collector.py               # FastAPI 独立 app（127.0.0.1:8790）：POST /capture 入库
    record_result.py           # CLI：FCR/EDR 结果录入 probe.db
```

## 测量零污染纪律（实施方案 §三）

- 探针一律页面内自采集，**禁用 CDP/Playwright/Puppeteer 驱动被测浏览器**；
  导航靠容器启动参数指定首屏 URL 序列。
- 探针页纯原生 JS，零外链零 CDN（唯一例外：tls.peet.ws 的 JA3/JA4 断言请求，
  失败自动降级为 source=none）。
- 只测量、不绕过：被挑战如实记录 challenged/blocked，不做任何打码/绕过（R10）。

## 一、起服（三个本地回环端口）

```bash
# 终端 1：探针页静态服（8789）
bash tools/adversarial/harness/serve_probe.sh

# 终端 2：收集器（8790）
python3 tools/adversarial/harness/collector.py --db probe.db
# 或 uvicorn collector:app --host 127.0.0.1 --port 8790（cwd=harness/）

# 终端 3：CreepJS 自托管（8791，首次需 clone，沙盒外网一次性动作）
bash tools/adversarial/creepjs_selfhost/setup.sh
bash tools/adversarial/creepjs_selfhost/serve.sh
```

## 二、采集（L1 自洽性静态面）

1. 被测浏览器（替身容器 / 对照组 A / 对照组 B）打开：

   ```
   http://127.0.0.1:8789/probe.html?group=T-cold&persona=替身ID
   ```

   - `group` ∈ `T-cold|T-warm|A-native|B-extension`（对照组省略 `persona`）；
   - 页面采集 SPEC-M4 §2 全部字段（canvas 双读间隔 ≥1200ms，
     cross_reads 走同源 Worker + iframe 独立路径），完成后自动 POST /capture；
   - POST 失败时页面红框展示完整 JSON，供手抄/复制后人工导入。

2. CreepJS：被测浏览器打开 `http://127.0.0.1:8791/`，等分析完成，
   DevTools 控制台粘贴 `creepjs_selfhost/extract_inpage.js` 全文执行，
   得到 `creepjs_export.json`（自动下载）。

## 三、录入

```bash
# creepjs_export → captures（entry=creepjs）
python3 tools/adversarial/creepjs_selfhost/import_export.py \
    --db probe.db --group T-cold --persona 替身ID --file creepjs_export.json

# FCR（实战挑战率，分入口分组不聚合）
python3 tools/adversarial/harness/record_result.py \
    --db probe.db --group T-cold --persona 替身ID \
    --site recaptcha_v3 --outcome score_bucket --score 0.7 --note "第3次"
python3 tools/adversarial/harness/record_result.py \
    --db probe.db --group A-native --site turnstile --outcome pass

# EDR（环境识别，目标 detected 全 0）
python3 tools/adversarial/harness/record_result.py \
    --db probe.db --group T-cold --persona 替身ID \
    --dimension headless --detected 0 --evidence "areyouheadless 未识别"
```

## 四、导出/报告

probe.db 即 SPEC-M4 §4 契约库（SQLite WAL，captures/clr_reports/fcr_results/
edr_results 四表）。报告由 Coder C 的 `tishen.adversarial.report` 生成：

```bash
python3 -m tishen.adversarial.report --db probe.db --out report.md
```

收集器在捕获入库时会尝试调用占位钩子 `run_rgate_if_available`
（try import `tishen.adversarial.rgate`）：T1 分支合并后自动生效并写
clr_reports；未合并时只存不评，capture 原文仍在库，可事后离线补评。

## 测试

```bash
pip install -q pytest fastapi httpx
python3 -m pytest core/tests/ -q   # 既有 130 条 + test_probe_schemas.py
```

单测全部走 fastapi.testclient 与临时库，**不 clone、不起真服端口、不依赖外网**。
