'use strict';
/* tishen_hook.js 核心铁律测试（SPEC-E3 §3.3，node --test 零依赖） */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { factory, buildEnv, flushAsync, eventsOf } = require('./helpers.js');

test('api_call 事件格式：summary 首 token=API 名、actor_script 非空、ts 毫秒', () => {
  const env = buildEnv();
  const hook = factory(env);
  new env.HTMLCanvasElement().toDataURL();
  const evs = eventsOf(hook, (e) => e.event_type === 'api_call');
  assert.equal(evs.length, 1);
  const ev = evs[0];
  assert.equal(ev.summary.split(' ')[0], 'canvas.toDataURL'); // 首 token=API 名（铁）
  assert.ok(ev.actor_script && ev.actor_script !== '' && ev.actor_script !== 'unknown');
  assert.ok(Number.isInteger(ev.ts) && ev.ts > 1e12); // Unix 毫秒
  assert.equal(ev.page_url, 'https://example.com/page');
  assert.equal(ev.frame, 'top');
  assert.equal(ev.sampled, false);
  assert.equal(ev.injected_late, false);
  assert.equal(ev.target_host, null);
});

test('postMessage 通道：{v:1,type:"event",event} 且 origin=location.origin', () => {
  const env = buildEnv();
  const hook = factory(env);
  new env.HTMLCanvasElement().toDataURL();
  assert.equal(env.window.messages.length, 1);
  const { msg, origin } = env.window.messages[0];
  assert.equal(msg.v, 1);
  assert.equal(msg.type, 'event');
  assert.ok(msg.event);
  assert.equal(origin, 'https://example.com');
});

test('观测不干预：原函数返回值一字不动', () => {
  const env = buildEnv();
  factory(env);
  const c = new env.HTMLCanvasElement();
  assert.equal(c.toDataURL(), 'data:image/png;base64,MOCK');
});

test('观测不干预：this 绑定不动', () => {
  const env = buildEnv();
  factory(env);
  const ctx = new env.CanvasRenderingContext2D();
  const r = ctx.getImageData(1, 2, 3, 4);
  assert.equal(r.self, ctx);
  assert.deepEqual([r.x, r.y, r.w, r.h], [1, 2, 3, 4]);
});

test('观测不干预：异常透传（原样抛出，不吞页面异常）', () => {
  const env = buildEnv();
  factory(env);
  const gl = new env.WebGLRenderingContext();
  assert.throws(() => gl.getParameter('THROW'), /gl boom/);
  assert.equal(gl.getParameter('OK'), 'gl-param');
});

test('隐蔽：toString 伪装为 native code（包装函数与 Function.prototype 双路径）', () => {
  const env = buildEnv();
  factory(env);
  const fn = env.HTMLCanvasElement.prototype.toDataURL;
  assert.equal(fn.toString(), 'function toDataURL() { [native code] }');
  assert.equal(Function.prototype.toString.call(fn), 'function toDataURL() { [native code] }');
});

test('隐蔽：Error.stack 清洗 hook 帧（actor_script 不含 tishen_hook）', () => {
  const env = buildEnv();
  const hook = factory(env);
  new env.HTMLCanvasElement().toDataURL();
  const ev = eventsOf(hook)[0];
  assert.ok(!String(ev.actor_script).includes('tishen_hook'));
  assert.ok(!ev.summary.includes('tishen_hook'));
});

test('降级：单 API >100 次/秒 → 1/10 采样且 sampled=true', () => {
  const env = buildEnv();
  const hook = factory(env);
  const c = new env.HTMLCanvasElement();
  for (let i = 0; i < 250; i++) c.toDataURL(); // 灌 250 次/秒
  const evs = eventsOf(hook, (e) => e.summary.startsWith('canvas.toDataURL'));
  assert.ok(evs.length >= 25, `事件数 ${evs.length} 应 ≥25`);
  assert.ok(evs.length <= 130, `事件数 ${evs.length} 应 ≤130（100 全量 + 超窗 1/10）`);
  const sampled = evs.filter((e) => e.sampled === true);
  assert.ok(sampled.length >= 1, '超限部分必须 sampled=true');
  assert.equal(sampled.length, evs.length - 100); // 前 100 全量，其余全为采样事件
});

test('降级：document.readyState!=="loading" → 全部事件 injected_late=true', () => {
  const env = buildEnv({ readyState: 'complete' });
  const hook = factory(env);
  new env.HTMLCanvasElement().toDataURL();
  void env.navigator.hardwareConcurrency;
  const evs = eventsOf(hook);
  assert.ok(evs.length >= 2);
  for (const ev of evs) assert.equal(ev.injected_late, true);
});

test('静默：postMessage 抛错时内部异常吞掉，原函数仍正常返回', () => {
  const env = buildEnv();
  const hook = factory(env);
  env.window.postMessage = () => { throw new Error('bus down'); };
  const c = new env.HTMLCanvasElement();
  assert.equal(c.toDataURL(), 'data:image/png;base64,MOCK'); // 不向页面抛错
});

test('navigator getter 拦截：hardwareConcurrency/plugins/languages 读触发 api_call', () => {
  const env = buildEnv();
  const hook = factory(env);
  assert.equal(env.navigator.hardwareConcurrency, 8); // 原值不动
  void env.navigator.plugins;
  const evs = eventsOf(hook);
  const apis = evs.map((e) => e.summary.split(' ')[0]);
  assert.ok(apis.includes('navigator.hardwareConcurrency'));
  assert.ok(apis.includes('navigator.plugins'));
});

test('screen getter 拦截：width/height/colorDepth', () => {
  const env = buildEnv();
  const hook = factory(env);
  assert.equal(env.screen.width, 1920);
  assert.equal(env.screen.colorDepth, 24);
  const apis = eventsOf(hook).map((e) => e.summary.split(' ')[0]);
  assert.ok(apis.includes('screen.width'));
  assert.ok(apis.includes('screen.colorDepth'));
});

test('WebGL/Audio/fonts 拦截面（FP_APIS 对齐）', () => {
  const env = buildEnv();
  const hook = factory(env);
  const gl = new env.WebGLRenderingContext();
  gl.getSupportedExtensions();
  gl.getExtension('x');
  gl.getShaderPrecisionFormat();
  gl.readPixels();
  const ac = new env.AudioContext();
  ac.createAnalyser();
  ac.createDynamicsCompressor();
  ac.createOscillator();
  new env.AnalyserNode().getFloatFrequencyData(new Float32Array(4));
  const fs = new env.FontFaceSet();
  fs.check('12px x');
  const apis = new Set(eventsOf(hook).map((e) => e.summary.split(' ')[0]));
  for (const a of ['webgl.getSupportedExtensions', 'webgl.getExtension', 'webgl.getShaderPrecisionFormat',
    'webgl.readPixels', 'audio.createAnalyser', 'audio.createDynamicsCompressor', 'audio.createOscillator',
    'audio.getFloatFrequencyData', 'fonts.check']) {
    assert.ok(apis.has(a), `缺 ${a}`);
  }
});
