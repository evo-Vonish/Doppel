'use strict';
/* bridge.js 来源校验测试（SPEC-E3 §3.3）：伪造 source 拒绝、v!==1 拒绝、合法转发 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

function loadBridge() {
  const code = fs.readFileSync(path.join(__dirname, '..', 'ext', 'bridge.js'), 'utf8');
  const handlers = [];
  const sent = [];
  const win = {
    addEventListener(type, fn) { if (type === 'message') handlers.push(fn); },
  };
  const chromeMock = {
    runtime: {
      lastError: null,
      sendMessage(data, cb) { sent.push(data); if (cb) cb(); },
    },
  };
  // eslint-disable-next-line no-new-func
  const run = new Function('window', 'chrome', code);
  run(win, chromeMock);
  assert.equal(handlers.length, 1);
  return { handler: handlers[0], sent, win };
}

function msg(over) {
  return Object.assign({
    v: 1, type: 'event',
    event: { event_type: 'api_call', summary: 'canvas.toDataURL x', ts: Date.now() },
  }, over || {});
}

test('bridge：合法消息（source===window 且 v===1）转发 sendMessage', () => {
  const { handler, sent, win } = loadBridge();
  handler({ source: win, data: msg() });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'event');
});

test('bridge：伪造 source（!==window）拒绝', () => {
  const { handler, sent } = loadBridge();
  handler({ source: { fake: true }, data: msg() });
  assert.equal(sent.length, 0);
});

test('bridge：v!==1 拒绝；未知 type 拒绝；payload_sample 放行', () => {
  const { handler, sent, win } = loadBridge();
  handler({ source: win, data: msg({ v: 2 }) });
  handler({ source: win, data: msg({ type: 'eval_me' }) });
  handler({ source: win, data: null });
  assert.equal(sent.length, 0);
  handler({ source: win, data: { v: 1, type: 'payload_sample', sha256: 'ab', kind: 'wasm', size: 1, head_b64: '', source_url: null, ts: 1 } });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'payload_sample');
});
