/*
 * 替身 Tishen M4 · CreepJS 结果提取脚本（SPEC-M4 §4 creepjs_export）
 *
 * 用法：
 *   1. bash setup.sh && bash serve.sh（自托管 CreepJS 于 127.0.0.1:8791）；
 *   2. 被测浏览器打开 http://127.0.0.1:8791/ 等待分析完成（勿用 CDP 驱动）；
 *   3. 打开 DevTools 控制台，整段粘贴本脚本执行；
 *   4. 控制台输出 + 自动下载的 creepjs_export.json 即 §4 契约形状，
 *      用 import_export.py 写入 probe.db。
 *
 * 说明：CreepJS 无稳定公开 JS API，本脚本按页面 DOM/文本做最大努力提取；
 *       提不到的字段一律 null/空数组（契约允许），不编造。
 */
(async function extractCreepjsExport() {
  "use strict";

  // creepjs_commit：同源 commit.txt（setup.sh 会复制进 repo/）；失败则 null
  async function readCommit() {
    try {
      const r = await fetch("commit.txt", { cache: "no-store" });
      if (!r.ok) return null;
      const t = (await r.text()).trim();
      return /^[0-9a-f]{40}$/i.test(t) ? t : null;
    } catch (e) { return null; }
  }

  const bodyText = (document.body && document.body.innerText) || "";

  // trust score：页面头部形如 "trust score: 87%"（最大努力正则）
  let trustScore = null;
  const mTrust = bodyText.match(/trust score[^\d%]*(\d+(?:\.\d+)?)\s*%/i);
  if (mTrust) trustScore = parseFloat(mTrust[1]);

  // lies：CreepJS lies 区块列出的谎言项（DOM 类名含 lie 的元素逐条取文本）
  const lies = [];
  document.querySelectorAll("[class*='lie']").forEach(function (el) {
    const t = (el.innerText || "").trim();
    if (!t || t.length > 500) return;
    // 形如 "name: detail" 拆字段；拆不出则整段进 detail
    const idx = t.indexOf(":");
    if (idx > 0 && idx < 80) {
      lies.push({ name: t.slice(0, idx).trim(), detail: t.slice(idx + 1).trim() });
    } else {
      lies.push({ name: t.slice(0, 80), detail: t });
    }
  });
  // 去重（同名只留首条）
  const seen = new Set();
  const liesDedup = lies.filter(function (l) {
    if (seen.has(l.name)) return false;
    seen.add(l.name);
    return true;
  });

  // resistance：CreepJS 对指纹抗性模式的识别（文本扫描已知抗性关键词）
  const RESISTANCE_PATTERNS = [
    "privacy.resistFingerprinting", "CanvasBlocker", "Trace", "Chameleon",
    "ScriptSafe", "Firefox", "Brave", "Tor Browser", "resistFingerprinting",
    "canvas noise", "randomized", "spoofed"
  ];
  const resistanceFound = RESISTANCE_PATTERNS.filter(function (p) {
    return bodyText.toLowerCase().indexOf(p.toLowerCase()) !== -1;
  });
  // 页面若有显式 resistance 区块，整段文本归入 raw_summary
  let resistanceSection = null;
  document.querySelectorAll("[class*='resistance'], [id*='resistance']")
    .forEach(function (el) {
      const t = (el.innerText || "").trim();
      if (t && !resistanceSection) resistanceSection = t.slice(0, 2000);
    });
  const resistance = {
    detected: resistanceFound.length > 0 || !!resistanceSection,
    patterns: resistanceFound
  };

  // fp_hash：CreepJS 页头展示的指纹哈希（类名含 hash 的元素首个）
  let fpHash = null;
  document.querySelectorAll("[class*='hash']").forEach(function (el) {
    const t = (el.innerText || "").trim();
    if (!fpHash && /^[0-9a-f]{16,64}$/i.test(t)) fpHash = t;
  });

  // raw_summary：原始页面摘要（截断），供人工复核
  const rawSummary = {
    title: document.title || null,
    url: location.href,
    collected_at: new Date().toISOString(),
    trust_score_text: mTrust ? mTrust[0] : null,
    resistance_section: resistanceSection,
    body_text_head: bodyText.slice(0, 4000)
  };

  const out = {
    source: "creepjs-selfhost",
    creepjs_commit: await readCommit(),
    trust_score: trustScore,
    lies: liesDedup,
    resistance: resistance,
    fp_hash: fpHash,
    raw_summary: rawSummary
  };

  const json = JSON.stringify(out, null, 2);
  console.log("creepjs_export 提取结果：\n" + json);

  // 自动下载一份，便于导入 probe.db（ import_export.py --file ）
  try {
    const blob = new Blob([json], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "creepjs_export.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  } catch (e) {
    console.warn("自动下载失败，请手抄上方 JSON。", e);
  }
  return out;
})();
