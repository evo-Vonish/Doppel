# HANDOFF —— Codex 完整接手文档

> 版本 v1.0 · 2026-08-02 · 前任：Kimi K3（主代理 Orchestrator）· 接手：Codex
> 读完本文约 40 分钟。它是你在本仓库一切行动的前提——**尤其 §五工程红线与 §六环境坑**。

---

## 一、项目是什么

**Doppel（代号 tishen，替身）**：本地优先的算法浏览器隐私系统。口号：**"替身已启动，目标无所遁形。"**

两个互为表里的子系统：
- **替身**：网站跑在预置完整身份环境的本地容器沙盒（persona.yaml 规格驱动烘焙时区/locale/字体/GPU/Chrome 指纹，跨层自洽）——网站拿到的是一套干净的 Linux 桌面分身数据，而非用户真实环境
- **无所遁形**：旁路观测（SSLKEYLOG+pcap，链路只读）+ 页面 hook 探针全量记录网页行为，三层判别引擎对追踪/指纹采集/挖矿脚本分级告警，证据链完整

**设计哲学**：不撒谎，直接造真的（不篡改 API——篡改的矛盾可被检测；从头构建真实自洽环境）。**北极星指标：CLR（自洽性露馅率）= 0**。

## 二、基线验证（接手第一动作，30 分钟）

```bash
git clone https://github.com/evo-Vonish/Doppel.git && cd Doppel
python3 -m venv .venv && . .venv/bin/activate
pip install pytest fastapi uvicorn pyyaml httpx
python -m pytest core/tests -q          # 预期 545 passed, 1 skipped
cd image/hook && node --test test/      # 预期 25 passed（node ≥18）
```
CI 状态见仓库 Actions 页（ci.yml：双栈绿勾）。**任何偏差 = 停下手头一切先对齐**（不要修代码"让它过"——先搞清环境差异）。

## 三、架构地图

```
core/tishen/
├── cli.py            # 编排 CLI：create/start/stop/suspend/resume/reset/destroy/list/events/lint/doctor/pull/evolve
├── persona.py        # persona.yaml 规格（Meta/Region/Gpu/Display/Evolution/Storage）+ 校验
├── linter.py         # 出厂门禁 V1–V10（镜像烘焙质量）
├── docker_ctl.py     # docker CLI 封装（全返回 (rc,out,err)，FileNotFoundError=无 docker）
├── state.py          # StateDB（personas 表）+ tishen_home() + 东八区 ISO 秒
├── observ/           # M3 观测流水线：events.py（Event 18 字段+16 枚举+ULID）、store.py（events.db WAL 批量纪律）、
│                     #   keylog/aligner/decrypt/daemon/query + hook_bus.py（hook 事件总线 Unix socket）
├── engine/           # 判别引擎：entity.py（E1 归因）/rules.py（E2 ABP 匹配）/behavior.py+scorer.py（E3 评分+评级闸）/
│                     #   daemon.py（在线消费，回写 alert_level/engine_tags）/payload.py（L2 载荷分析）/
│                     #   trackerdb.py + datasets/（easyprivacy/whotracksme/tracker_radar/trackerdb_src/downloader/licenses）
├── adversarial/      # M4：clr_checklist_v1.py（82 条 CLR 清单 v1.1）/rgate.py/report.py
├── resbench/         # M5：sampler/bootprobe/fidelity/report（resbench.db 六表）
├── evolution.py      # EVO：drift pack schema/gate 门禁/diff 审计器/GROUP_FIELDS 七组映射
├── evolve_seq.py     # EVO-3：演化门禁序列编排（EvolveHooks 四真机注入点）
└── api/              # 本地 API 桥：app.py（FastAPI 11 端点，仅 127.0.0.1）/adapter/schemas/settings_io
image/                # 容器镜像：Dockerfile + entrypoint/persona_bake.py（十段 BOOT_MARK 打点）+
                      #   hook/（tishen_hook.js 拦截面 + ext/ MV3 扩展 + tishen_native_host.py）
tools/adversarial/    # M4 采集：creepjs_selfhost/ + harness/（probe.html 8789/collector 8790/CreepJS 8791）
shell/                # install.sh + uninstall.sh（INS-1 一体化安装器骨架）
pipeline/             # 构建流水线脚本
```

**数据流**：页面行为 → tishen_hook.js（六类事件）→ bridge/background → native_host（补 persona/session）→ hook.sock → hook_bus → events.db ← 观测守护（pcap 解密网络事件）→ engine daemon（E1/E2 标注 → E3 评分 → decide_level 评级）→ 回写 alert_level/engine_tags → API 桥 → 前端控制台。

## 四、当前状态快照（2026-08-02）

| 领域 | 状态 | 备注 |
|---|---|---|
| M1–M3 脚手架 | ✅ 沙盒完成 | 真机容器验收挂起 |
| M4/M5 工具链 | ✅ 沙盒完成 | **真机采集未执行**（CLR/EDR/FCR、资源基线全是空表待填） |
| 判别引擎 | ✅ 全链闭合 | 含 L2 载荷分析、真实下载器、license 闸门 |
| hook 层 | ✅ 沙盒完成 | MV3 扩展真机装载未验（A8 增补） |
| 演化（EVO） | ✅ 沙盒完成 | hooks 四注入点待真机接线；drift pack 目录表是示例行 |
| 安装器（INS） | ✅ 骨架 | URL 全占位；真机 apt/dnf/curl 未验 |
| 前端 | ✅ v2 交付 | 版本卡片 2c84fcf；mock 数据驱动，真 API 联调未做 |
| **真机核验** | 🔄 **进行中（最高优先）** | 格 3 Windows 11 WSL2，见 §八-1 |
| CI | ✅ 绿 | pytest+node 双栈 |
| 产品化 P1 | ⏸️ 门禁中 | D1–D4 已拍板，等 P0–P2 真机达标 |

## 五、工程红线（违反即返工，无例外）

1. **R10 合规**：定位防御性隐私。不生成身份资料；**不内置任何绕过验证码/风控的能力**；FCR 只测量不绕过（被挑战=记录，不处置）；不提供"监控他人"的功能
2. **测量零污染**：M4 采集期间**严禁 CDP/Playwright/Puppeteer 驱动被测浏览器**（CDP 在指纹面留可检测痕迹，违背 CLR=0）；运行期 hook 走 MV3 扩展+native messaging（CDP 路线已正式否决）
3. **网络链路只读**：链路上不放任何代理/拦截/改写组件；阻断层本期恒零阻断
4. **观测层只读纪律**：events.db 对引擎只许 UPDATE `alert_level`/`engine_tags` 两列，其余字段只读
5. **数据真实**：任何字段没有真实来源就置空/省略，**不编造**；失败记实际输出不粉饰；测试夹具的恶意样本**编码落盘**（AV 误报实证，见 §六-5）
6. **告警铁律**：单个可疑 API 调用永不触发高级告警；级别 3 需 ≥3 独立信号且分 ≥80（指纹类再叠跨站 ≥3 闸门）；L2 载荷确认只作确认加权，永不单独告警
7. **license 硬约束**：核心路径只依赖非 NC 数据集（EasyPrivacy/whoTracks.me）；Tracker Radar/TrackerDB 为 NC 可选包（settings.json packages 开关），未启用时扩展列恒 NULL
8. **本地优先**：服务仅绑 127.0.0.1；零遥测；密钥/pcap 分片 age 加密、明文窗口 ≤5 分钟、随容器销毁
9. **纯标准库**（Python 侧禁引新依赖；测试依赖 pytest/fastapi/uvicorn/pyyaml/httpx 除外）
10. **git 纪律**：**严禁 `git worktree prune`**；**两次提交纪律**（实现一次 feat(x):、测试一次 test(x):）；主分支 main

## 六、环境坑大全（每条都是血泪实证）

1. **共享仓库 OSS/FUSE 挂载**（仅 Kimi 沙盒，本机无此坑）：git index 写失败 → `export GIT_INDEX_FILE=/tmp/<独立名>-idx && git read-tree HEAD` 绕行（**每次用新文件名，复用会漂移**）；对象/引用同步延迟 → "unable to read tree"/"not something we can merge" 等 10–20 秒重试；merge 后查 `git log` 确认引用真动了
2. **$HOME//tmp 周期性清理**（仅沙盒）：worktree/venv 会被抹——**尽早提交进对象库**（提交即持久）+ 收工备份到 /mnt/agents/output/backup-<分支>/（bundle+patch+源文件）
3. **shell 非持久**（仅沙盒）：每条命令新 shell，后台进程随 shell 死——长任务用持久内核（ipython Popen）；pip 依赖每新环境重装
4. **测试环境显式化纪律**（CI 三轮实证）：环境语义必须显式注入，永不依赖宿主巧合——无 docker 用 `monkeypatch`/注入点（`DOPPEL_FORCE_NO_DOCKER=1`、`DOPPEL_TARGET_USER`）；子进程测试 env 显式传 `PYTHONPATH=<仓库core/>`
5. **AV 误报**（火绒实证 2026-08-01）：Windows 真机跑 pytest 前先把项目目录加 AV 信任区（`core/tests/` 级）；恶意样本夹具一律 base64 落盘
6. **双 Python 陷阱**（仅沙盒）：/usr/local/bin/python（3.12，有 fastapi 无 pytest）vs /usr/bin/python3（3.11，反之）——用 venv 统一
7. **pip 超时**：换 `https://pypi.tuna.tsinghua.edu.cn/simple`

## 七、GitHub 工作流（沙盒→GitHub 特殊链路）

- **git 协议在沙盒被墙**（github.com smart HTTP 丢包）——推送走 **REST API 四步原子提交**（blobs→tree→commit→PATCH ref），脚本已固化：`/mnt/agents/output/push_doppel.py`（完整历史重建）与增量模式（见会话惯例：blobs 改文件+base_tree 建 tree+commit+PATCH）
- **本地↔远端 sha 不一一对应**（REST 重建时时区规范化），但 **tree sha 逐位一致**（已验证 55e045ab）——本机协作以 GitHub 为准：`git fetch origin && git reset --hard origin/main`
- **token 纪律**：PAT 永不落文件/聊天；对话出现过的凭证即销毁重发；推送用交互粘贴或 credential helper，**不写进 remote URL**
- CI 卡顿处理：runner 偶发僵尸（in_progress 不终结）——先本地复现排除真 hang，再推小提交触发替代 run

## 八、待办与排产（按优先级）

### 1. 真机核验（格 3，进行中，P0 门禁）
- 文档：`handoff 文档包`（`替身计划-真机核验Handoff-Windows.md` + `替身计划-真实环境验收手册.md`）——**先读 handoff §一格 3 增补**：弃 Docker Desktop 用 WSL2 原生 dockerd（apt install docker.io）；llvmpipe 自检先行；wslg 三件套（/dev/dxg + /usr/lib/wsl + /mnt/wslg）
- 序列：基线复现（545+25）→ P0 镜像构建 → P1 A1–A8 → P2 M2 冒烟 → P3 M3 冒烟（**tls.peet.ws JA3/JA4 零失败=一票否决项**）→ P4 M4 采集（3d）→ P5 M5 采集（1.5d）
- 产出按反馈模板带回（probe.db/resbench.db/events.db 原样不编辑）
- **AV 白名单先行**（§六-5）

### 2. 真机达标后（P1 解锁）
- INS-2 镜像三层 fallback → INS-3 更新双轨 → INS-4 发布流水线（《安装包实施方案》）
- EVO 真机接线（hooks 四注入点：rgate/harness/镜像流水线/外部抽样）→ drift pack 流水线签发（《演化实施方案》）
- 多替身调度器（D1 半自动）/persona 模板/用户分层深化（《产品化阶段规划》P1 表）

### 3. 增强件（随时可做，不阻塞）
- payload.py P0 扩充（R-E 结论：混淆工具识别/skimmer 表单窃取链/cookie→外发链，8–12 人日）
- EVO-4 金丝雀/laggard 画像（1 人日）
- 遗留裁决：cross_reads.ua_* 归组（G-ENV→G-UA？SPEC-EVO 定）；白名单组内细化
- 镜像层收尾：.dockerignore 已补；`__pycache__` 入镜像检查

## 九、文档地图（/mnt/agents/output/ 与 docs 包，34 份）

| 类别 | 文件 |
|---|---|
| 纲领 | 替身计划-项目计划文档.md（v1.3，版本历史即项目编年史） |
| 专项方案 | M1/M2/M3/M4/M5 实施方案、判别引擎实施方案、hook 层专项方案、演化实施方案、安装包实施方案、产品化阶段规划（D1–D4 已锁） |
| 工程契约 | SPEC.md、SPEC-API（v0.2）、SPEC-M2M3、SPEC-M4、SPEC-M5、SPEC-E、SPEC-E2、SPEC-E3、SPEC-E4 |
| 验收/转交 | 真实环境验收手册、真机核验Handoff-Windows（格 3 增补版）、本文 |
| 研究 | research/替身_T1–T8、替身_R[A–E]_*（rootless/分发/指纹演化/信誉养成/js-x-ray 评估） |
| 沙盒验证 | 替身计划-沙盒内验证报告.md |

**阅读顺序建议**：本文 → 项目计划文档（§一/二/三/五 + 版本历史）→ 你负责领域的专项方案+SPEC → research 对应报告。

## 十、既有工作模式（前任的协作循环，供参考）

1. 主代理出**方案文档**（What/Why/人日切分）→ 用户批准
2. 出 **SPEC**（How：schema/接口签名/文件所有权表/验收口径）
3. **coder 集群并行**（git worktree 隔离，文件零冲突）开发
4. 主代理**独立验收**：全量复跑 + 契约抽查（行为级，不只跑 coder 的自测）+ 端到端冒烟——**历史战绩：4 次打回（path 匹配 bug/协议失配/缺省边界/环境巧合），全部来自独立抽查**
5. 合并 main → 推 GitHub → CI 验证 → 计划文档版本历史

**给 Codex 的建议**：保持"写的人不自验"的双闸。测试全绿 ≠ 边界全覆盖。

## 十一、立即任务清单（接手第一周）

1. §二基线验证通过
2. 真机核验 P0–P1（镜像构建 + A1–A8），异常按 handoff §一格 3 排查
3. 把第一条实测数据（A2 渲染器字符串原文）记进反馈模板
4. 读完 §九推荐阅读顺序中的前三份
5. 遇到任何与本文档冲突的现实：以现实为准并修订文档（文档是活的）

---

*交接人注：这个仓库的每一行都有测试、每一条红线都有出处、每一个坑都标注了代价。祝顺利。—— Kimi K3，2026-08-02*
