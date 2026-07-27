// 替身（Tishen）M2 外壳渲染逻辑（SPEC-M2M3 §1.4，原生 DOM 无框架）。
// 全部数据经 window.tishen 桥接（→ 主进程 → tishen CLI），页面无任何直接 docker 能力。
// 模式分层：ui.mode=default|expert 条件渲染——默认模式无专家面板入口，
// 不是把专家功能硬编码进默认界面再「隐藏」（v0.3 决策：条件渲染，即时生效）。

(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);

  const state = {
    mode: "default",
    personas: [],
    currentView: "list", // list | echo
  };

  // ------------------------------------------------------------------
  // 模式分层：单一 ui.mode 驱动条件渲染，切换即时生效不需重启
  // ------------------------------------------------------------------
  async function applyMode(mode) {
    state.mode = mode;
    $("#mode-select").value = mode;
    // 专家模式才渲染面板容器（默认模式下 DOM 中不出现入口）
    $("#expert-panel").hidden = mode !== "expert";
  }

  async function initMode() {
    const mode = await window.tishen.getMode();
    await applyMode(mode);
    $("#mode-select").addEventListener("change", async (e) => {
      const next = await window.tishen.setMode(e.target.value);
      await applyMode(next);
      window.tishen.onNotify("界面模式已切换",
        next === "expert" ? "专家模式已开启。" : "已回到默认模式。");
    });
  }

  // ------------------------------------------------------------------
  // 替身列表
  // ------------------------------------------------------------------
  const STATE_LABEL = {
    creating: "准备中",
    active: "运行中",
    suspended: "已休眠",
    destroyed: "已销毁",
  };

  async function refreshList() {
    try {
      state.personas = await window.tishen.listPersonas();
    } catch (err) {
      showError(err.message);
      return;
    }
    const tbody = $("#persona-tbody");
    tbody.innerHTML = "";
    $("#list-empty").hidden = state.personas.length > 0;
    for (const p of state.personas) {
      tbody.appendChild(renderRow(p));
    }
  }

  function renderRow(p) {
    const tr = document.createElement("tr");
    const label = STATE_LABEL[p.state] || p.state;
    tr.innerHTML = `<td>${escapeHtml(p.name)}</td><td>${escapeHtml(label)}</td>`;
    const ops = document.createElement("td");

    if (p.state === "active") {
      ops.appendChild(makeButton("打开窗口", async () => {
        try {
          const url = await window.tishen.getEmbedUrl(p.id);
          openPersonaView(p.id, url, p.name);
        } catch (err) { showError(err.message); }
      }));
      ops.appendChild(makeButton("休眠", async () => {
        await guard(async () => {
          await window.tishen.stopPersona(p.id);
          window.tishen.onNotify("替身已休眠", `「${p.name}」已休眠，随时可唤醒。`);
          await refreshList();
        });
      }));
    } else if (p.state === "suspended" || p.state === "creating") {
      ops.appendChild(makeButton("唤醒", async () => {
        await guard(async () => {
          const started = await window.tishen.startPersona(p.id);
          window.tishen.onNotify("替身已上线", `「${p.name}」已开始工作。`);
          await refreshList();
          if (started.embed_url) openPersonaView(p.id, started.embed_url, p.name);
        });
      }));
    }

    // 信誉清零：二次确认，文案明示「信誉清零」（原则 5 与 N4 的落地）
    ops.appendChild(makeButton("重置", async () => {
      const confirmed = window.confirm(
        `确定要重置「${p.name}」吗？\n\n` +
        "此操作将删除登录态、Cookie、浏览历史等全部信誉资产——信誉清零，" +
        "替身将以全新身份重新出发。此操作不可撤销。");
      if (!confirmed) return;
      await guard(async () => {
        await window.tishen.resetPersona(p.id, p.name);
        window.tishen.onNotify("替身已重置", `「${p.name}」信誉已清零，将以全新身份出发。`);
        await refreshList();
      });
    }));

    // 焚毁：二次确认，文案明示「容器与档案全部焚毁」
    ops.appendChild(makeButton("销毁", async () => {
      const confirmed = window.confirm(
        `确定要销毁「${p.name}」吗？\n\n` +
        "此操作不可撤销：替身的容器与档案将全部焚毁，无法再找回。");
      if (!confirmed) return;
      await guard(async () => {
        await window.tishen.destroyPersona(p.id);
        window.tishen.onNotify("替身已销毁", `「${p.name}」的容器与档案已全部焚毁。`);
        await refreshList();
      });
    }, true));

    tr.appendChild(ops);
    return tr;
  }

  // ------------------------------------------------------------------
  // 回显区：<webview> 嵌 embed_url（webviewTag 开；断线提示重连）
  // ------------------------------------------------------------------
  function openPersonaView(id, embedUrl, name) {
    state.currentView = "echo";
    $("#persona-list-view").hidden = true;
    $("#echo-view").hidden = false;
    $("#echo-title").textContent = name ? `「${name}」的画面` : "";

    const container = $("#echo-container");
    container.innerHTML = "";
    const webview = document.createElement("webview");
    webview.src = embedUrl;
    webview.style.width = "100%";
    webview.style.height = "640px";
    // 断线重连提示（M2-5）：加载失败上屏中文提示 + 重试按钮，不给英文错误页
    webview.addEventListener("did-fail-load", () => {
      container.innerHTML = "";
      const tip = document.createElement("p");
      tip.className = "echo-error";
      tip.textContent = "画面连接中断了。";
      const retry = makeButton("重新连接", () => openPersonaView(id, embedUrl, name));
      container.appendChild(tip);
      container.appendChild(retry);
    });
    container.appendChild(webview);
  }
  // 供 onboarding.js 第 5 步调用
  window.openPersonaView = openPersonaView;

  // ------------------------------------------------------------------
  // 专家模式：doctor 输出查看（面板数据 M3 接入，M2 只有占位与自检）
  // ------------------------------------------------------------------
  function initExpert() {
    $("#btn-doctor").addEventListener("click", async () => {
      await guard(async () => {
        const report = await window.tishen.runDoctor();
        const out = $("#doctor-output");
        out.hidden = false;
        out.textContent = report.checks
          .map((c) => `${c.ok ? "[OK]" : "[FAIL]"} ${c.item}` +
               (c.detail ? `（${c.detail}）` : "") + (c.ok || !c.fix ? "" : `\n    建议：${c.fix}`))
          .join("\n");
      });
    });
  }

  // ------------------------------------------------------------------
  // 新建替身（只填名称，地区默认 auto）
  // ------------------------------------------------------------------
  function initCreate() {
    $("#btn-create").addEventListener("click", async () => {
      const name = window.prompt("给新替身起个名字：", "我的替身");
      if (name === null) return;
      await guard(async () => {
        const created = await window.tishen.createPersona(name.trim() || "我的替身");
        window.tishen.onNotify("替身已创建", `「${created.name}」准备好了，点「唤醒」开始使用。`);
        await refreshList();
      });
    });
    $("#btn-refresh").addEventListener("click", refreshList);
    $("#btn-back").addEventListener("click", () => {
      state.currentView = "list";
      $("#echo-view").hidden = true;
      $("#echo-container").innerHTML = "";
      $("#persona-list-view").hidden = false;
      refreshList();
    });
  }

  // ------------------------------------------------------------------
  // 工具
  // ------------------------------------------------------------------
  function makeButton(text, onClick, danger) {
    const btn = document.createElement("button");
    btn.textContent = text;
    if (danger) btn.className = "danger";
    btn.addEventListener("click", onClick);
    return btn;
  }

  async function guard(fn) {
    try {
      await fn();
    } catch (err) {
      showError((err && err.message) ? err.message : "操作没有成功，请重试。");
    }
  }

  function showError(msg) {
    window.tishen.onNotify("替身：操作未成功", msg);
    alert(msg);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // ------------------------------------------------------------------
  // 入口：模式 → 列表 → 首启引导（没有替身时自动进入五步引导）
  // ------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", async () => {
    await initMode();
    initCreate();
    initExpert();
    await refreshList();
    if (state.personas.length === 0) {
      $("#main-view").hidden = true;
      window.startOnboarding();
    }
  });
})();
