'use strict';
/* wasm_load / worker_spawn / storage_write / visibility_probe 测试（SPEC-E3 §3.3） */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { factory, buildEnv, flushAsync, eventsOf } = require('./helpers.js');

test('wasm_load：instantiate(bytes) 触发事件 size+sha256，构造不阻塞', async () => {
  const env = buildEnv();
  const hook = factory(env);
  const bytes = new Uint8Array(2048).map((_, i) => i % 256);
  const p = env.WebAssembly.instantiate(bytes, {});
  assert.ok(p instanceof Promise); // 立即返回原 Promise（哈希异步不阻塞）
  await p;
  await flushAsync();
  const evs = eventsOf(hook, (e) => e.event_type === 'wasm_load');
  assert.equal(evs.length, 1);
  assert.equal(evs[0].summary.split(' ')[0], 'WebAssembly.instantiate'); // 首 token=API 名
  assert.equal(evs[0].size, 2048);
  assert.match(evs[0].sha256, /^[0-9a-f]{64}$/);
});

test('wasm_load → payload_sample：kind=wasm 且 head_b64 ≤64KB', async () => {
  const env = buildEnv();
  const hook = factory(env);
  const big = new Uint8Array(100 * 1024).map((_, i) => i % 251); // 100KB > 64KB
  await env.WebAssembly.compile(big);
  await flushAsync();
  const samples = hook.posted.filter((m) => m.type === 'payload_sample');
  assert.equal(samples.length, 1);
  const s = samples[0];
  assert.equal(s.v, 1);
  assert.equal(s.kind, 'wasm');
  assert.equal(s.size, 100 * 1024);
  assert.match(s.sha256, /^[0-9a-f]{64}$/);
  const decoded = Buffer.from(s.head_b64, 'base64');
  assert.ok(decoded.length <= 64 * 1024, `head ${decoded.length}B 应 ≤64KB`);
  assert.equal(decoded.length, 64 * 1024); // 截断到 64KB
  assert.deepEqual([...decoded.subarray(0, 16)], [...big.subarray(0, 16)]); // 前 16B 一致
});

test('worker_spawn：Worker 构造触发事件且构造返回不阻塞', async () => {
  const env = buildEnv();
  const hook = factory(env);
  const w = new env.Worker('https://example.com/w.js');
  assert.ok(w instanceof Object);
  assert.equal(w.url, 'https://example.com/w.js'); // 构造行为不动
  const evs = eventsOf(hook, (e) => e.event_type === 'worker_spawn');
  assert.equal(evs.length, 1);
  assert.equal(evs[0].script_url, 'https://example.com/w.js');
});

test('worker_spawn：blob URL 异步 sha256 → payload_sample kind=js，不阻塞构造', async () => {
  const src = new TextEncoder().encode('self.onmessage=()=>{}');
  const env = buildEnv({
    fetch: (u) => Promise.resolve({ arrayBuffer: () => Promise.resolve(src.buffer.slice(0)) }),
  });
  const hook = factory(env);
  const w = new env.Worker('blob:https://example.com/abc'); // 构造立即返回
  assert.equal(w.url, 'blob:https://example.com/abc');
  await flushAsync();
  const samples = hook.posted.filter((m) => m.type === 'payload_sample');
  assert.equal(samples.length, 1);
  assert.equal(samples[0].kind, 'js');
  assert.equal(samples[0].source_url, 'blob:https://example.com/abc');
  assert.equal(samples[0].size, src.length);
  assert.match(samples[0].sha256, /^[0-9a-f]{64}$/);
});

test('storage_write：localStorage.setItem 只记键名+值长度+熵，值本体不采集', () => {
  const env = buildEnv();
  const hook = factory(env);
  const ls = new env.Storage();
  const secret = 's3cr3t-token-ABCDEFGH';
  ls.setItem('session', secret);
  assert.equal(ls.getItem('session'), secret); // 原行为不动
  const evs = eventsOf(hook, (e) => e.event_type === 'storage_write');
  assert.equal(evs.length, 1);
  const ev = evs[0];
  assert.equal(ev.summary.split(' ')[0], 'localStorage.setItem');
  assert.equal(ev.key, 'session');
  assert.equal(ev.value_len, secret.length);
  assert.ok(ev.entropy === 'low' || ev.entropy === 'high');
  assert.ok(!JSON.stringify(ev).includes(secret), '值本体泄露！');
});

test('storage_write：document.cookie setter 同上不落值', () => {
  const env = buildEnv();
  const hook = factory(env);
  env.document.cookie = 'uid=xyz123; Secure';
  assert.ok(env.document.cookie.includes('uid=xyz123')); // 原 setter 生效
  const evs = eventsOf(hook, (e) => e.event_type === 'storage_write');
  assert.equal(evs.length, 1);
  assert.equal(evs[0].summary.split(' ')[0], 'document.cookie');
  assert.equal(evs[0].key, 'uid');
  assert.equal(evs[0].value_len, 'xyz123; Secure'.length);
  assert.ok(!JSON.stringify(evs[0]).includes('xyz123'));
});

test('storage_write：熵分级 low/high', () => {
  const env = buildEnv();
  const hook = factory(env);
  const ls = new env.Storage();
  ls.setItem('a', 'aaaaaaaaaaaaaaaa'); // 低熵
  ls.setItem('b', 'aX9$mK2#pQ7&zR4!'); // 高熵
  const evs = eventsOf(hook, (e) => e.event_type === 'storage_write');
  assert.equal(evs[0].entropy, 'low');
  assert.equal(evs[1].entropy, 'high');
});

test('visibility_probe：hidden/visible + 前后 5s 密度快照', () => {
  const env = buildEnv({ captureTimeouts: true });
  const hook = factory(env);
  new env.HTMLCanvasElement().toDataURL(); // 先造 1 个事件进密度窗
  env.document.visibilityState = 'hidden';
  env.document.dispatch('visibilitychange');
  let evs = eventsOf(hook, (e) => e.event_type === 'visibility_probe');
  assert.equal(evs.length, 1);
  assert.equal(evs[0].summary.split(' ')[0], 'visibilitychange');
  assert.equal(evs[0].state, 'hidden');
  assert.ok(evs[0].pre_5s >= 1);
  assert.equal(evs[0].post_5s, null);
  // 触发 5s 后快照回调
  assert.equal(env._timeouts.length, 1);
  assert.equal(env._timeouts[0].ms, 5000);
  env._timeouts[0].cb();
  evs = eventsOf(hook, (e) => e.event_type === 'visibility_probe');
  assert.equal(evs.length, 2);
  assert.ok(typeof evs[1].post_5s === 'number');
});
