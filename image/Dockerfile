# syntax=docker/dockerfile:1
# 替身（Tishen）平台镜像 —— 多阶段构建（M1 四层 + M2 流层）
# 分层职责：runtime（显示/音频/编码栈）→ i18n（字体/输入法）→ chrome（浏览器）
#           → tishen（烘焙入口+观测）→ stream（M2：neko v2 推流 server，SPEC-M2M3 §1.1）
# 纪律：镜像是通用「替身平台」，不写死任何 persona 具体值；persona.yaml 是容器启动参数（见 M1 方案 §2 决策 2）。

ARG UBUNTU=ubuntu:24.04

# ── L1 运行时层：显示/音频/编码栈（neko 架构范式）──────────────────────────
FROM ${UBUNTU} AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# VPN/proxy links can transiently refuse APT's pipelined connections. Keep the
# mirror portable while making every package transaction retry without HTTP
# pipelining.
ARG APT_NETWORK_OPTS="-o Acquire::Retries=5 -o Acquire::http::Pipeline-Depth=0"

# 虚拟显示器（xserver-xorg-video-dummy，分辨率由 persona_bake 运行时用 xrandr 调整）、
# pulseaudio/dbus-x11、GStreamer 全套与 x264/VP8 编码器（M2 neko 推流预留）
RUN apt-get ${APT_NETWORK_OPTS} update && apt-get ${APT_NETWORK_OPTS} install -y --no-install-recommends \
    xserver-xorg-core \
    xserver-xorg-video-dummy \
    x11-xserver-utils \
    x11-utils \
    xcvt \
    pulseaudio \
    dbus-x11 \
    libgstreamer1.0-0 \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    libx264-164 \
    libvpx9 \
    && rm -rf /var/lib/apt/lists/*

# GPU 透传准备（借鉴 kasm）：
# 1) NVIDIA 宿主库路径加入动态链接器搜索路径（宿主驱动经容器挂载进入时生效）
# 2) GLVND 的 NVIDIA EGL vendor 配置（GPU_VENDOR=nvidia 时 Chrome 走 --use-gl=egl）
# 3) mesa 驱动包（Intel/AMD 透传，GPU_VENDOR=mesa 默认路径走 --use-gl=angle --use-angle=gl）
RUN printf '/usr/lib/x86_64-linux-gnu\n/usr/lib/i386-linux-gnu\n' > /etc/ld.so.conf.d/nvidia.conf \
    && mkdir -p /usr/share/glvnd/egl_vendor.d \
    && printf '{\n    "file_format_version" : "1.0.0",\n    "ICD" : {\n        "library_path" : "libEGL_nvidia.so.0"\n    }\n}\n' \
        > /usr/share/glvnd/egl_vendor.d/10_nvidia.json \
    && apt-get ${APT_NETWORK_OPTS} update \
    && apt-get ${APT_NETWORK_OPTS} install -y --no-install-recommends \
    libglvnd0 \
    libglvnd-dev \
    libegl1 \
    libgl1 \
    mesa-vulkan-drivers \
    libgl1-mesa-dri \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

# ── L2 国际化层：字体超集 + 输入法（风险 N3）───────────────────────────────
FROM runtime AS i18n

# 字体超集全量预装，运行时由 persona_bake 按 persona.yaml 的 fonts.pack/extras
# 通过 fontconfig 模板「激活子集」而非堆装（坑位 7：装了什么字体也是可探测面）。
# fcitx5 三环境变量由 persona_bake 在 Chrome 启动前 export（坑位 4）。
RUN apt-get ${APT_NETWORK_OPTS} update && apt-get ${APT_NETWORK_OPTS} install -y --no-install-recommends \
    fonts-noto-cjk \
    fonts-wqy-microhei \
    fonts-liberation \
    fonts-dejavu \
    fontconfig \
    fcitx5 \
    fcitx5-chinese-addons \
    im-config \
    && rm -rf /var/lib/apt/lists/*

# ── L3 浏览器层：Chrome 官方 deb（R7 流水线锚点）───────────────────────────
FROM i18n AS chrome

# 构建参数化：稳定版号由更新流水线注入（默认 stable=官方 current deb）
ARG CHROME_VERSION=stable

# 从 Google 官方源安装 Chrome stable；安装后把精确版本落档到 /etc/tishen/chrome_version，
# 该文件是 evolution 基线读取点，也是容器内 linter V6 的版本锚（SPEC §5/§6）。
RUN apt-get ${APT_NETWORK_OPTS} update && apt-get ${APT_NETWORK_OPTS} install -y --no-install-recommends \
    curl \
    ca-certificates \
    wget \
    gnupg \
    && curl -fSL -o /tmp/google-chrome.deb \
    https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt-get ${APT_NETWORK_OPTS} install -y --no-install-recommends /tmp/google-chrome.deb \
    && rm -f /tmp/google-chrome.deb \
    && mkdir -p /etc/tishen \
    && google-chrome --version | awk '{print $3}' > /etc/tishen/chrome_version \
    && rm -rf /var/lib/apt/lists/*

# ── L4 替身层：烘焙入口 + 观测脚手架 ──────────────────────────────────────
FROM chrome AS tishen

# Build arguments are stage-scoped.  Redeclare the version here so the final
# image label below records the version injected by the release pipeline.
ARG CHROME_VERSION=stable

# 烘焙器运行时依赖：python3 + PyYAML（契约白名单）；
# 观测脚手架：tcpdump（环形抓包）、age（日志/keylog 加密落盘工具链，R11）；
# tshark：M3 观测链路（pcap → TLS 解密 → 事件流）需要，M2 由 Coder C 代装（SPEC-M2M3 §1.1）
RUN apt-get ${APT_NETWORK_OPTS} update && apt-get ${APT_NETWORK_OPTS} install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-yaml \
    tcpdump \
    age \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# 拷贝镜像层自带资产：入口脚本、配置模板、观测守护
COPY image/entrypoint/ /opt/tishen/entrypoint/
COPY image/config/ /opt/tishen/config/
COPY image/scripts/ /opt/tishen/scripts/

# E-IV 件一（I2）：hook 层资产预置（tishen_hook.js / ext / native host + manifest 模板），
# MV3 hook 扩展目录供 --load-extension 加载；纯增量，既有层零改动
COPY image/hook/ /opt/tishen/hook/
COPY image/hook/ext/ /opt/tishen/hook-ext/
# content_scripts 的 MAIN world 入口与扩展壳同目录；原始脚本同时保留在 hook/
# 供单元测试/资产审计，扩展目录这一份供 CRX 打包。
COPY image/hook/tishen_hook.js /opt/tishen/hook-ext/tishen_hook.js

# E-IV 件一（I2）：扩展 key 构建期一次性生成（独立缓存层，openssl 镜像已有不新装包）。
# MV3 扩展 id 由 manifest key 派生——key 固定则 id 恒定，native manifest 的
# allowed_origins 由 persona_bake 运行时从本 key 计算注入（G 遗留①/②）。
RUN chmod 755 /opt/tishen/hook/tishen_native_host.py \
    && openssl genrsa -out /opt/tishen/hook/ext-key.pem 2048 \
    && chmod 600 /opt/tishen/hook/ext-key.pem \
    && PUBKEY="$(openssl rsa -in /opt/tishen/hook/ext-key.pem -pubout -outform DER 2>/dev/null | base64 -w0)" \
    && python3 /opt/tishen/hook/inject_manifest_key.py \
        /opt/tishen/hook-ext/manifest.json "$PUBKEY"

# 拷贝并安装 tishen core 包（由 core 分支提供；--no-deps 遵守依赖白名单纪律）。
# 烘焙器在容器内复用 tishen.persona / tishen.linter 做 schema 校验与 linter 门禁复验（SPEC §6 第 1 步）。
# 兼容 PEP 668 的 Ubuntu 24.04：优先常规安装，失败时回退 --break-system-packages（容器内单用户环境，可接受）。
COPY core/ /opt/tishen/core
RUN pip3 install --no-deps /opt/tishen/core \
    || pip3 install --break-system-packages --no-deps /opt/tishen/core

RUN chmod +x /opt/tishen/entrypoint/persona-bake \
    /opt/tishen/scripts/observability-daemon.sh

# 观测目录结构（卷挂载点；M1 方案 §9）：sslkeys / pcap / events
RUN mkdir -p /persona/logs/sslkeys /persona/logs/pcap /persona/logs/events /persona/profile

# 负资产清理：清 apt 缓存（各层尾部已清）、构建痕迹
RUN rm -rf /var/cache/apt/archives /tmp/* /var/tmp/*

# 镜像标签：标题 + Chrome 精确版本（构建期从落档文件注入标签值）
LABEL org.opencontainers.image.title="tishen-persona-image" \
    tishen.chrome.version="${CHROME_VERSION}" \
    tishen.stream.enabled="false"

ENTRYPOINT ["/opt/tishen/entrypoint/persona-bake"]

# ── L5 流层：neko v2 server 二进制（M2 画面回显，SPEC-M2M3 §1.1）────────────
# 独立 stage 便于单独重建（M2 方案 §二集成要点 1：合入 neko 是「补一块二进制」，不换底座）。
# neko 只负责抓屏推流与输入回注；Chrome 生命周期仍归 persona-bake 编排。
FROM tishen AS stream

# 锁定 v2 稳定系具体 tag（v3 有 issue #598 高延迟 bug，禁入）；
# 构建前必须核实 release 页面上的真实版本号与 tar 包 SHA256 并填入下方 ARG——切片期纪律：
# NEKO_SHA256 为占位，未填则构建打印警告但不中断（便于离线/冒烟构建）；
# 进入真实验收前必须填实，否则推流二进制来源不可信（原则：供应链可校验）。
ARG NEKO_VERSION=2.8.0
ARG NEKO_SHA256=""

# 从 neko 官方 GitHub release 拉取 linux amd64 server 二进制 tar 包；
# SHA256 校验逻辑就位：填了 NEKO_SHA256 则强校验（不符即构建失败），未填则警告放行（切片期）。
RUN curl -fSL -o /tmp/neko.tar.gz \
    "https://github.com/m1k1o/neko/releases/download/v${NEKO_VERSION}/neko_${NEKO_VERSION}_linux_amd64.tar.gz" \
    && if [ -n "${NEKO_SHA256}" ]; then \
        echo "${NEKO_SHA256}  /tmp/neko.tar.gz" | sha256sum -c -; \
    else \
        echo "警告：NEKO_SHA256 未填，跳过 neko 二进制完整性校验（仅限切片期冒烟构建）" >&2; \
    fi \
    && mkdir -p /opt/neko \
    && tar -xzf /tmp/neko.tar.gz -C /opt/neko \
    && chmod +x /opt/neko/neko \
    && rm -f /tmp/neko.tar.gz

LABEL tishen.stream.enabled="true"

# neko 运行时默认（M2 方案 §二.3：本地优先，零外联）：
# 容器内 HTTP/WebSocket 监听 8080；WebRTC 走 host candidate（本机 loopback），不配 STUN/TURN。
# 口令纪律：NEKO_PASSWORD 不入镜像，运行时经环境变量注入（docker_ctl 创建替身时生成随机口令）。
ENV NEKO_BIND=:8080 \
    NEKO_ICELITE=1 \
    NEKO_NAT1TO1=127.0.0.1 \
    NEKO_EPR=59000-59100
