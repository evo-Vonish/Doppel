/*
 * background.js —— MV3 service worker（SPEC-E3 §3.2）
 * onMessage → native port（connectNative("tishen_native_host")）postMessage 转发；
 * ruleset 读取 chrome.storage.local（本期恒空），收到规则回执 {type:"ack"} 经 port 回传；
 * native 断开指数退避重连（1s/2s/4s … 封顶 30s）。
 */
(function () {
  'use strict';

  var HOST_NAME = 'tishen_native_host';
  var port = null;
  var backoffMs = 1000;
  var BACKOFF_MAX = 30000;
  var queue = [];            // 断线期间缓冲（上限防膨胀，观测不拖页面）
  var QUEUE_MAX = 1000;

  function connect() {
    try {
      port = chrome.runtime.connectNative(HOST_NAME);
      backoffMs = 1000; // 连接成功即重置退避
      port.onMessage.addListener(function (msg) {
        // native host 回执（{ok:true}/规则回执）——本期仅作通道实证，不回传页面
        try { void msg; } catch (e) { /* 静默 */ }
      });
      port.onDisconnect.addListener(function () {
        void chrome.runtime.lastError;
        port = null;
        scheduleReconnect();
      });
      //  flush 缓冲
      while (queue.length && port) {
        try { port.postMessage(queue.shift()); } catch (e) { break; }
      }
    } catch (e) {
      port = null;
      scheduleReconnect();
    }
  }

  function scheduleReconnect() {
    var delay = backoffMs;
    backoffMs = Math.min(backoffMs * 2, BACKOFF_MAX); // 1/2/4/8/16/30 封顶
    setTimeout(connect, delay);
  }

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    try {
      if (!msg || msg.v !== 1) return false;
      if (msg.type !== 'event' && msg.type !== 'payload_sample') return false;
      if (port) {
        try { port.postMessage(msg); } catch (e) { enqueue(msg); }
      } else {
        enqueue(msg);
      }
      if (sendResponse) {
        try { sendResponse({ type: 'ack' }); } catch (e) { /* 静默 */ }
      }
    } catch (e) { /* 静默 */ }
    return false;
  });

  function enqueue(msg) {
    if (queue.length >= QUEUE_MAX) queue.shift(); // 降级：丢弃最旧
    queue.push(msg);
  }

  // ruleset：本期恒空，仅读取以实证通道语义；收到规则回执 {type:"ack"}
  try {
    chrome.storage.local.get(['tishen_ruleset'], function (items) {
      void chrome.runtime.lastError;
      try {
        var ruleset = (items && items.tishen_ruleset) || [];
        void ruleset; // 本期无规则应用逻辑
      } catch (e) { /* 静默 */ }
    });
  } catch (e) { /* 静默 */ }

  connect();
})();
