// 替身（Tishen）外壳 preload（SPEC-M2M3 §1.4）。
// contextBridge 暴露最小白名单 API；渲染进程无 Node 能力（contextIsolation 开）。
// 桥接面与 M2 方案 §三「与 tishen CLI 的调用关系」一一对应。

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("tishen", {
  // 替身生命周期（全部经主进程 → tishen CLI，无一直接 docker）
  listPersonas: () => ipcRenderer.invoke("persona:list"),
  createPersona: (name) => ipcRenderer.invoke("persona:create", name),
  startPersona: (id) => ipcRenderer.invoke("persona:start", id),
  stopPersona: (id) => ipcRenderer.invoke("persona:stop", id),
  resetPersona: (id, personaName) => ipcRenderer.invoke("persona:reset", id, personaName),
  destroyPersona: (id) => ipcRenderer.invoke("persona:destroy", id),
  getEmbedUrl: (id) => ipcRenderer.invoke("persona:embedUrl", id),

  // 首启引导与自检
  runDoctor: () => ipcRenderer.invoke("doctor:run"),
  pullImage: () => ipcRenderer.invoke("image:pull"),

  // 模式管理（ui.mode = default | expert）
  getMode: () => ipcRenderer.invoke("mode:get"),
  setMode: (mode) => ipcRenderer.invoke("mode:set", mode),

  // 宿主原生通知（B5；title/body 均须为自然语言一句，默认模式不含技术细节）
  onNotify: (title, body) => ipcRenderer.send("notify", { title, body }),
});
