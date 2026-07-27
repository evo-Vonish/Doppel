// 替身（Tishen）首启五步引导（M2 方案 §五，SPEC-M2M3 §1.4）。
// 渲染进程脚本（无 Node 能力，经 window.tishen 桥接触达主进程）。
//
// 五步：检测 Docker → 检测 /dev/dri → 拉取镜像 → 建第一个替身 → 开窗口。
// 纪律：每步只一个主按钮；任一步失败可从失败步单步重试，不要求重来；
// 文案中文人话，禁止堆栈跟踪与英文原文上屏。

(function () {
  "use strict";

  // 引导步骤定义：title=步骤名，hint=一句话解释，button=主按钮文案，
  // run=执行体（抛错即视为失败，错误文案取 err.message——桥接层已保证是中文人话）
  const STEPS = [
    {
      key: "docker",
      title: "第 1 步：检查容器运行时",
      hint: "替身需要 Docker 来运行隔离的浏览环境。",
      button: "开始检测",
      async run(ctx) {
        const report = await window.tishen.runDoctor();
        const item = report.checks.find((c) => c.item.includes("docker 守护进程"));
        if (!item || !item.ok) {
          throw new Error(
            "替身需要容器运行时（Docker）才能工作。请先安装并启动 Docker；" +
            "如果你的账号没有权限，请把自己加入 docker 用户组并重新登录，装完点下方按钮重试。");
        }
        ctx.dockerOk = true;
      },
    },
    {
      key: "dri",
      title: "第 2 步：检查显卡直通",
      hint: "有显卡直通时，替身看起来更像一台真实电脑。",
      button: "开始检测",
      async run(ctx) {
        const report = await window.tishen.runDoctor();
        const item = report.checks.find((c) => c.item.includes("/dev/dri"));
        if (!item || !item.ok) {
          // R2 降级档明示义务：告知风险但用户确认后继续，不阻塞
          const accepted = window.confirm(
            "这台机器没有可用的显卡直通，替身处将使用软件渲染降级档——" +
            "网站更容易识别出这不是真实电脑。了解风险后仍要继续吗？");
          if (!accepted) throw new Error("已暂停：接入显卡后可重新检测。");
          ctx.degraded = true;
        }
        ctx.driChecked = true;
      },
    },
    {
      key: "pull",
      title: "第 3 步：下载替身平台镜像",
      hint: "首次使用需要下载替身运行环境（体积较大，请保持网络畅通）。",
      button: "开始下载",
      async run(ctx) {
        const result = await window.tishen.pullImage();
        if (!result || !result.present) {
          throw new Error("下载没有完成：请检查网络后重试；若提示磁盘不足，请清理磁盘空间后重试。");
        }
        ctx.imageReady = true;
      },
    },
    {
      key: "create",
      title: "第 4 步：准备你的第一个替身",
      hint: "正在为你准备一个干净的浏览环境。",
      button: "创建替身",
      async run(ctx) {
        const created = await window.tishen.createPersona("我的第一个替身");
        ctx.personaId = created.id;
        const started = await window.tishen.startPersona(ctx.personaId);
        ctx.embedUrl = started.embed_url;
        if (!ctx.embedUrl) throw new Error("替身已创建，但没有拿到连接信息，请在列表页重新启动它。");
      },
    },
    {
      key: "open",
      title: "第 5 步：打开替身窗口",
      hint: "一切就绪，点下面的按钮就能看到替身的画面了。",
      button: "打开窗口",
      async run(ctx) {
        if (typeof window.openPersonaView === "function") {
          window.openPersonaView(ctx.personaId, ctx.embedUrl);
        }
        window.tishen.onNotify("替身已上线", "你的第一个替身已经开始工作。");
      },
    },
  ];

  // 引导状态：stepIndex 指向当前待执行步骤（失败停在原地，可单步重试）
  const state = { stepIndex: 0, ctx: {}, busy: false };

  function render(root) {
    root.innerHTML = "";
    const title = document.createElement("h2");
    title.textContent = "欢迎使用替身";
    root.appendChild(title);

    STEPS.forEach((step, i) => {
      const row = document.createElement("div");
      row.className = "onboarding-step " +
        (i < state.stepIndex ? "step-done" : i === state.stepIndex ? "step-current" : "step-pending");
      const status = i < state.stepIndex ? "✓" : i === state.stepIndex ? "→" : "·";
      row.innerHTML = `<span class="step-status">${status}</span> ` +
        `<strong>${step.title}</strong><p class="step-hint">${step.hint}</p>`;
      root.appendChild(row);
    });

    const step = STEPS[state.stepIndex];
    if (!step) {
      const done = document.createElement("p");
      done.className = "onboarding-done";
      done.textContent = "引导完成！你可以在列表页管理替身。";
      root.appendChild(done);
      const close = document.createElement("button");
      close.textContent = "进入替身列表";
      close.onclick = () => { root.hidden = true; document.getElementById("main-view").hidden = false; };
      root.appendChild(close);
      return;
    }

    const btn = document.createElement("button");
    btn.className = "primary";
    btn.textContent = state.busy ? "请稍候……" : step.button;
    btn.disabled = state.busy;
    btn.onclick = async () => {
      state.busy = true;
      render(root);
      try {
        await step.run(state.ctx);
        state.stepIndex += 1;
        state.error = null;
      } catch (err) {
        // 失败停在当前步：错误文案上屏 + 主按钮变「重试」，不要求从头再来
        state.error = (err && err.message) ? err.message : "这一步没有成功，请重试。";
      } finally {
        state.busy = false;
        render(root);
      }
    };
    root.appendChild(btn);

    if (state.error) {
      const errBox = document.createElement("p");
      errBox.className = "onboarding-error";
      errBox.textContent = state.error;
      root.appendChild(errBox);
      btn.textContent = "重试这一步";
    }
  }

  // 启动引导：挂到 #onboarding 容器（index.html 提供）
  window.startOnboarding = function () {
    const root = document.getElementById("onboarding");
    root.hidden = false;
    render(root);
  };
})();
