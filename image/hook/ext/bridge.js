/*
 * bridge.js —— ISOLATED world 桥（SPEC-E3 §3.2）
 * window message → 来源校验（event.source===window、data.v===1）→ chrome.runtime.sendMessage
 * 仅转发 type=event|payload_sample，其余静默丢弃。
 */
(function () {
  'use strict';
  try {
    window.addEventListener('message', function (event) {
      try {
        if (event.source !== window) return;                 // 伪造来源拒绝
        var data = event.data;
        if (!data || data.v !== 1) return;                   // 协议版本校验
        if (data.type !== 'event' && data.type !== 'payload_sample') return;
        if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;
        chrome.runtime.sendMessage(data, function () {
          // 吞掉 lastError（background 未就绪时静默，不向页面抛错）
          void chrome.runtime.lastError;
        });
      } catch (e) { /* 静默 */ }
    });
  } catch (e) { /* 静默 */ }
})();
