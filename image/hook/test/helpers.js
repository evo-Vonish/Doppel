'use strict';
/* node --test 零依赖 mock 环境（SPEC-E3 §3.3） */
const path = require('path');

global.__tishenHookNoAuto = true; // 禁止自动安装，测试手工注入 mock 环境
require(path.join(__dirname, '..', 'tishen_hook.js'));
const factory = globalThis.__tishenHookFactory;
if (typeof factory !== 'function') throw new Error('tishen_hook.js 未暴露 __tishenHookFactory');

function makeNavigator() {
  const nav = {};
  Object.defineProperty(nav, 'plugins', { get: () => ['p1', 'p2'], configurable: true, enumerable: true });
  Object.defineProperty(nav, 'hardwareConcurrency', { get: () => 8, configurable: true, enumerable: true });
  Object.defineProperty(nav, 'deviceMemory', { get: () => 16, configurable: true, enumerable: true });
  Object.defineProperty(nav, 'languages', { get: () => ['zh-CN'], configurable: true, enumerable: true });
  Object.defineProperty(nav, 'userAgent', { get: () => 'MockUA/1.0', configurable: true, enumerable: true });
  Object.defineProperty(nav, 'platform', { get: () => 'Linux x86_64', configurable: true, enumerable: true });
  return nav;
}

function makeScreen() {
  const scr = {};
  Object.defineProperty(scr, 'width', { get: () => 1920, configurable: true, enumerable: true });
  Object.defineProperty(scr, 'height', { get: () => 1080, configurable: true, enumerable: true });
  Object.defineProperty(scr, 'colorDepth', { get: () => 24, configurable: true, enumerable: true });
  return scr;
}

class MockStorage {
  constructor() { this._m = new Map(); }
  setItem(k, v) { this._m.set(String(k), String(v)); }
  getItem(k) { return this._m.has(String(k)) ? this._m.get(String(k)) : null; }
}

function makeDocument(readyState) {
  const listeners = {};
  const doc = {
    readyState: readyState || 'loading',
    visibilityState: 'visible',
    hidden: false,
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    dispatch(type) { (listeners[type] || []).forEach((fn) => fn()); },
  };
  let cookieJar = '';
  Object.defineProperty(doc, 'cookie', {
    get() { return cookieJar; },
    set(v) { cookieJar += (cookieJar ? '; ' : '') + v; },
    configurable: true, enumerable: true,
  });
  return doc;
}

function buildEnv(opts) {
  opts = opts || {};
  const windowObj = {
    messages: [],
    postMessage(msg, origin) { this.messages.push({ msg, origin }); },
  };
  windowObj.top = windowObj;

  class MockWorker {
    constructor(url, opts) { this.url = String(url); this.opts = opts; }
    postMessage() {}
    terminate() {}
  }

  const wasmBytesSeen = [];
  const WebAssemblyMock = {
    Module: class Module {},
    instantiate(bytes, imports) { wasmBytesSeen.push(bytes); return Promise.resolve({ instance: {}, module: {} }); },
    compile(bytes) { return Promise.resolve(new WebAssemblyMock.Module()); },
    instantiateStreaming(resp, imports) { return Promise.resolve({ instance: {}, module: {} }); },
    compileStreaming(resp) { return Promise.resolve(new WebAssemblyMock.Module()); },
  };

  const timeouts = [];
  const env = {
    window: windowObj,
    document: makeDocument(opts.readyState),
    navigator: makeNavigator(),
    screen: makeScreen(),
    location: { href: 'https://example.com/page', origin: 'https://example.com' },
    Function,
    HTMLCanvasElement: class HTMLCanvasElement {
      toDataURL(type) { return 'data:image/png;base64,MOCK'; }
      toBlob(cb) { cb && cb(null); }
    },
    CanvasRenderingContext2D: class CanvasRenderingContext2D {
      getImageData(x, y, w, h) { return { self: this, x, y, w, h, data: [] }; }
      measureText(t) { return { width: String(t).length * 6 }; }
    },
    WebGLRenderingContext: class WebGLRenderingContext {
      getParameter(p) { if (p === 'THROW') throw new Error('gl boom'); return 'gl-param'; }
      getSupportedExtensions() { return ['EXT_a']; }
      getExtension(n) { return { name: n }; }
      getShaderPrecisionFormat() { return { precision: 23 }; }
      readPixels() { return undefined; }
    },
    AudioContext: class AudioContext {
      createAnalyser() { return { kind: 'analyser' }; }
      createDynamicsCompressor() { return { kind: 'compressor' }; }
      createOscillator() { return { kind: 'osc' }; }
    },
    AnalyserNode: class AnalyserNode { getFloatFrequencyData(arr) { return undefined; } },
    FontFaceSet: class FontFaceSet {
      check() { return true; }
      load() { return Promise.resolve([]); }
    },
    Worker: MockWorker,
    SharedWorker: MockWorker,
    WebAssembly: WebAssemblyMock,
    Storage: MockStorage,
    crypto: globalThis.crypto,
    btoa: globalThis.btoa ? globalThis.btoa.bind(globalThis) : undefined,
    fetch: opts.fetch,
    setTimeout: opts.captureTimeouts
      ? (cb, ms) => { timeouts.push({ cb, ms }); return timeouts.length; }
      : setTimeout,
  };
  env._timeouts = timeouts;
  env._wasmBytesSeen = wasmBytesSeen;
  windowObj.Worker = MockWorker;
  windowObj.SharedWorker = MockWorker;
  return env;
}

function flushAsync(times) {
  let p = Promise.resolve();
  for (let i = 0; i < (times || 6); i++) p = p.then(() => new Promise((r) => setImmediate(r)));
  return p;
}

function eventsOf(hook, pred) {
  return hook.posted.filter((m) => m && m.type === 'event').map((m) => m.event).filter(pred || (() => true));
}

module.exports = { factory, buildEnv, flushAsync, eventsOf };
