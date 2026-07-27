// 替身（Tishen）M2 外壳主进程（SPEC-M2M3 §1.4 / M2 方案 §三）。
//
// 纪律：
// - 一切 docker 操作经 tishen CLI（--json），本进程严禁直接调 docker（M2 方案 §三）；
// - 渲染进程 contextIsolation 开、nodeIntegration 关、webviewTag 开（R-M2-5 安全面）；
// - ui.mode（default|expert）本地持久化，单一配置项驱动条件渲染（v0.3 决策落地）。

const { app, BrowserWindow, ipcMain, Tray, Menu, Notification, nativeImage } = require("electron");
const { execFile } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

// tishen CLI 入口：可用环境变量 TISHEN_CLI 覆盖（开发期指向 pipx/venv 里的 tishen）
const TISHEN_CLI = process.env.TISHEN_CLI || "tishen";

// ---------------------------------------------------------------------------
// tishen CLI 调用封装（child_process；全部命令走 --json 的走 JSON，无 JSON 契约
// 的 stop/destroy 走文本并以退出码判成败——CLI 侧无 --json 语义变化的命令）
// ---------------------------------------------------------------------------

// 执行 CLI 并解析 stdout 最后一行 JSON；失败抛出中文可读错误（不抛堆栈上屏）。
function runCliJson(args) {
  return new Promise((resolve, reject) => {
    execFile(TISHEN_CLI, [...args, "--json"], { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(humanizeCliError(stderr, err)));
        return;
      }
      const lastLine = stdout.trim().split("\n").filter(Boolean).pop() || "";
      try {
        resolve(JSON.parse(lastLine));
      } catch (e) {
        reject(new Error("替身后台返回了无法识别的内容，请升级外壳或 CLI 版本。"));
      }
    });
  });
}

// 执行无 --json 契约的 CLI（stop/destroy/reset），以退出码判成败。
// options.input 用于向交互式确认（reset 须输入替身名）喂 stdin。
function runCliText(args, input) {
  return new Promise((resolve, reject) => {
    const child = execFile(TISHEN_CLI, args, { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(humanizeCliError(stderr, err)));
        return;
      }
      resolve(stdout.trim());
    });
    if (input) child.stdin.end(input);
  });
}

// 把 CLI 的 stderr 提炼成一句中文人话（首启引导纪律：禁止堆栈与英文原文直接上屏）。
function humanizeCliError(stderr, err) {
  const lines = (stderr || "").split("\n")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("错误：") || s.startsWith("警告：") || s.startsWith("提示："));
  if (lines.length) return lines.join("；");
  if (err && err.code === "ENOENT") {
    return "未找到 tishen 命令：请确认替身命令行工具已安装（可设 TISHEN_CLI 环境变量指定路径）。";
  }
  return "替身后台执行失败，请查看日志或运行 tishen doctor 自检。";
}

// ---------------------------------------------------------------------------
// ui.mode 持久化（userData/settings.json；v0.3：单一配置项驱动条件渲染）
// ---------------------------------------------------------------------------

function settingsPath() {
  return path.join(app.getPath("userData"), "settings.json");
}

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsPath(), "utf-8"));
  } catch {
    return {};
  }
}

function getMode() {
  const mode = readSettings()["ui.mode"];
  return mode === "expert" ? "expert" : "default";
}

function setMode(mode) {
  if (mode !== "default" && mode !== "expert") {
    throw new Error("界面模式只能是 default 或 expert。");
  }
  const settings = readSettings();
  settings["ui.mode"] = mode;
  fs.mkdirSync(path.dirname(settingsPath()), { recursive: true });
  fs.writeFileSync(settingsPath(), JSON.stringify(settings, null, 2), "utf-8");
  return mode;
}

// ---------------------------------------------------------------------------
// 窗口与托盘
// ---------------------------------------------------------------------------

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    title: "替身",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,   // 安全基线：渲染进程与 Node 隔离
      nodeIntegration: false,   // 安全基线：页面无 Node 能力
      webviewTag: true,         // 回显区以 <webview> 嵌 neko embed_url（M2 方案 §三）
    },
  });
  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
  mainWindow.on("closed", () => { mainWindow = null; });
}

function createTray() {
  // 占位图标：切片期用空 nativeImage，产品化阶段替换为正式托盘图标资产
  const tray = new Tray(nativeImage.createEmpty());
  tray.setToolTip("替身");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "打开替身", click: () => { if (mainWindow) mainWindow.show(); else createWindow(); } },
    { type: "separator" },
    { label: "退出", click: () => app.quit() },
  ]));
}

// ---------------------------------------------------------------------------
// IPC：preload contextBridge 的桥接实现（全部经 tishen CLI，无一直接 docker）
// ---------------------------------------------------------------------------

function registerIpc() {
  // 替身列表：tishen list --json → 替身数组
  ipcMain.handle("persona:list", () => runCliJson(["list"]));

  // 新建替身：tishen create --region auto --name 名 --json → {id,...}
  ipcMain.handle("persona:create", (_e, name) => {
    const args = ["create", "--region", "auto"];
    if (name) args.push("--name", String(name));
    return runCliJson(args);
  });

  // 启动替身：tishen start <id> --json → {id,state,host_port,embed_url,password}
  ipcMain.handle("persona:start", (_e, id) => runCliJson(["start", String(id)]));

  // 停止（休眠归并）：tishen stop <id>（文本契约，退出码判成败）
  ipcMain.handle("persona:stop", (_e, id) => runCliText(["stop", String(id)]));

  // 信誉清零：外壳 UI 已二次确认；CLI 侧交互确认须输入替身名，经 stdin 喂入
  ipcMain.handle("persona:reset", (_e, id, personaName) =>
    runCliText(["reset", String(id)], String(personaName) + "\n"));

  // 焚毁：tishen destroy <id>
  ipcMain.handle("persona:destroy", (_e, id) => runCliText(["destroy", String(id)]));

  // 取回显地址：优先用状态库已有连接信息拼 embed_url（未启动的替身先提示启动）
  ipcMain.handle("persona:embedUrl", async (_e, id) => {
    const list = await runCliJson(["list"]);
    const rec = Array.isArray(list) ? list.find((r) => r.id === id) : null;
    if (!rec) throw new Error("找不到这个替身，请刷新列表。");
    if (!rec.host_port || !rec.neko_password) {
      throw new Error("该替身还没有连接信息，请先启动它。");
    }
    return `http://127.0.0.1:${rec.host_port}/?embed=1&usr=admin&pwd=${rec.neko_password}`;
  });

  // 自检：tishen doctor --json → {failed, checks[]}（首启引导与专家模式共用）
  ipcMain.handle("doctor:run", () => runCliJson(["doctor"]));

  // 拉取镜像：tishen pull --json（首启引导第 3 步；已存在则幂等跳过）
  ipcMain.handle("image:pull", () => runCliJson(["pull"]));

  // 模式管理
  ipcMain.handle("mode:get", () => getMode());
  ipcMain.handle("mode:set", (_e, mode) => setMode(mode));

  // 宿主原生通知（B5：替身状态/风险事件弹系统通知；文案由渲染侧给自然语言一句）
  ipcMain.on("notify", (_e, payload) => {
    const { title, body } = payload || {};
    if (!title) return;
    new Notification({ title: String(title), body: String(body || "") }).show();
  });
}

// ---------------------------------------------------------------------------

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  createTray();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  // 非 macOS 惯例：全关即退出（macOS 驻留托盘）
  if (process.platform !== "darwin") app.quit();
});
