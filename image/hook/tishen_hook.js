/*
 * tishen_hook.js —— 替身 Tishen E-III JS hook 层（MAIN world，零依赖原生 JS）
 *
 * 拦截表与 core/tishen/engine/behavior.py FP_APIS 同源对齐
 * （对齐版本：main HEAD=dc71e56，FP_APIS frozenset，行为引擎文件头注释锁定）。
 * 覆盖：canvas toDataURL/getImageData/toBlob/measureText、
 * WebGL getParameter/getSupportedExtensions/getExtension/getShaderPrecisionFormat/readPixels、
 * AudioContext createAnalyser/getFloatFrequencyData/createDynamicsCompressor/createOscillator/
 * offline.startRendering、FontFace fonts.check/load、
 * navigator plugins/hardwareConcurrency/deviceMemory/languages/userAgent/platform、
 * screen width/height/colorDepth。
 *
 * 铁律（SPEC-E3 §3.1）：
 *  1. 观测不干预：包装只旁路记录，原函数返回值/this/异常一字不动
 *  2. 隐蔽：toString 伪装为 native code；Error.stack 清洗 hook 帧
 *  3. 静默：任何内部异常 catch 后吞掉，绝不向页面抛错
 *  4. 数据最小化：storage_write 只记键名+值长度+熵分级，值本体不采集
 *  5. 降级不拖页面：单 API >100 次/秒 → 1/10 采样且 sampled=true；
 *     document.readyState !== 'loading' → 全部事件 injected_late=true
 *
 * 发送：window.postMessage({v:1,type:"event",event:{…}}, location.origin)
 * summary 首 token = API 名（behavior.py 消费口径，铁）。
 */
(function (global) {
  'use strict';

  var HOOK_MARK = 'tishen_hook'; // Error.stack 清洗用 hook 帧标记
  var PROTO_VERSION = 1;

  /**
   * 工厂：注入环境（window/document/navigator/screen/…），返回控制句柄。
   * 页面 MAIN world 自动以真实全局环境调用；node 测试以 mock 环境调用。
   */
  function createTishenHook(env) {
    var posted = [];           // 已发消息旁路记录（测试可观察）
    var eventClock = [];       // visibility 密度快照用事件时间环
    var samplerState = {};     // 单 API 滑动窗口采样状态
    var disposed = false;

    var LATE = (function () {
      try { return env.document && env.document.readyState !== 'loading'; }
      catch (e) { return false; }
    })();

    function now() { return Date.now(); }

    function safe(fn) { // 静默铁律：内部异常吞掉
      try { return fn(); } catch (e) { return undefined; }
    }

    // ---- Error.stack 解析：清洗 hook 帧，取首个外部帧为 actor_script ----
    function parseStack() {
      return safe(function () {
        var prevLimit = Error.stackTraceLimit;
        var stack;
        try { Error.stackTraceLimit = 50; stack = String(new Error().stack || ''); }
        finally { Error.stackTraceLimit = prevLimit; }
        var lines = stack.split('\n');
        var external = [];
        for (var i = 0; i < lines.length; i++) {
          var line = lines[i];
          if (line.indexOf(HOOK_MARK) !== -1) continue;      // 清洗 hook 帧
          if (line.indexOf('Error') === 0 && line.length < 8) continue;
          if (line.indexOf('node:') !== -1) continue;        // node 内部帧（测试环境）
          var m = line.match(/(https?:\/\/[^\s)]+|blob:[^\s)]+|file:\/\/[^\s)]+)/);
          if (!m) m = line.match(/(\/[A-Za-z0-9_\-./@+]+\.[a-zA-Z0-9]+)(?::\d+:\d+)?/); // 绝对路径帧（node 等）
          if (m) external.push(m[1].replace(/:\d+:\d+$/, ''));
        }
        return external;
      }) || [];
    }

    function actorInfo() {
      var frames = parseStack();
      return {
        actor_script: frames.length ? frames[0] : 'unknown',
        frames_tail: frames.length ? (' [' + frames.slice(0, 3).join(' <- ') + ']') : ''
      };
    }

    // ---- 采样：单 API 滑动 1s 窗口 >100 次 → 超出部分 1/10 保留 ----
    function keep(api) {
      var t = now();
      var st = samplerState[api] || (samplerState[api] = { start: t, count: 0, seq: 0 });
      if (t - st.start >= 1000) { st.start = t; st.count = 0; st.seq = 0; }
      st.count++;
      if (st.count <= 100) return { emit: true, sampled: false };
      st.seq++;
      return { emit: (st.seq % 10 === 0), sampled: true };
    }

    function post(msg) {
      safe(function () {
        posted.push(msg);
        env.window.postMessage(msg, (env.location && env.location.origin) || '*');
      });
    }

    function baseEvent(api, desc, extra) {
      var ai = actorInfo();
      var event = {
        summary: api + ' ' + (desc || '') + ai.frames_tail, // 首 token=API 名（铁）
        ts: now(),
        page_url: String((env.location && env.location.href) || ''),
        frame: (env.window && env.window.top === env.window) ? 'top' : 'iframe',
        actor_script: ai.actor_script,
        target_host: (extra && extra.target_host) || null,
        sampled: false,
        injected_late: LATE
      };
      if (extra) for (var k in extra) if (event[k] === undefined) event[k] = extra[k];
      return event;
    }

    function emitApiCall(api, desc, extra) {
      var gate = keep(api);
      var t = now();
      eventClock.push(t);
      if (!gate.emit) return;
      safe(function () {
        var event = baseEvent(api, desc || 'called', extra);
        event.event_type = 'api_call';
        event.sampled = gate.sampled;
        post({ v: PROTO_VERSION, type: 'event', event: event });
      });
    }

    function emitRaw(eventType, api, desc, extra) {
      eventClock.push(now());
      safe(function () {
        var event = baseEvent(api, desc, extra);
        event.event_type = eventType;
        post({ v: PROTO_VERSION, type: 'event', event: event });
      });
    }

    // ---- toString 伪装：function <name>() { [native code] } ----
    var nativeToString = env.Function.prototype.toString;
    var disguised = []; // {fn, name}
    function nativeStr(name) { return 'function ' + name + '() { [native code] }'; }
    function disguise(fn, name) {
      disguised.push({ fn: fn, name: name });
      safe(function () {
        Object.defineProperty(fn, 'toString', {
          value: function () { return nativeStr(name); },
          configurable: true, writable: true
        });
      });
      return fn;
    }
    safe(function () {
      var patched = function toString() {
        for (var i = 0; i < disguised.length; i++) {
          if (this === disguised[i].fn) return nativeStr(disguised[i].name);
        }
        return nativeToString.call(this);
      };
      Object.defineProperty(patched, 'toString', {
        value: function () { return nativeStr('toString'); },
        configurable: true, writable: true
      });
      env.Function.prototype.toString = patched;
    });

    // ---- 方法包装：先记录再原样调用（观测不干预，异常透传） ----
    function wrapMethod(obj, name, api, describe) {
      safe(function () {
        if (!obj || typeof obj[name] !== 'function') return;
        var orig = obj[name];
        var wrapped = function () {
          var args = arguments;
          var self = this;
          safe(function () { emitApiCall(api, describe ? describe(args, self) : 'called'); });
          return orig.apply(self, args); // 返回值/this/异常一字不动
        };
        disguise(wrapped, name);
        safe(function () { Object.defineProperty(wrapped, 'name', { value: name, configurable: true }); });
        obj[name] = wrapped;
      });
    }

    // ---- 属性 getter 包装 ----
    function wrapGetter(obj, name, api) {
      safe(function () {
        if (!obj) return;
        var owner = obj, desc;
        while (owner && !desc) {
          desc = Object.getOwnPropertyDescriptor(owner, name);
          if (!desc) owner = Object.getPrototypeOf(owner);
        }
        if (!desc || typeof desc.get !== 'function') return;
        if (desc.configurable === false) return;
        var origGet = desc.get;
        var newGet = function () {
          var v = origGet.call(this);
          safe(function () { emitApiCall(api, 'read'); });
          return v;
        };
        disguise(newGet, 'get ' + name);
        Object.defineProperty(owner, name, {
          get: newGet, set: desc.set, configurable: true, enumerable: desc.enumerable
        });
      });
    }

    // ---- 熵分级（storage_write，值本体不采集） ----
    function entropyClass(value) {
      var s = String(value == null ? '' : value);
      if (!s.length) return 'low';
      var freq = {};
      for (var i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
      var h = 0;
      for (var c in freq) {
        var p = freq[c] / s.length;
        h -= p * Math.log2(p);
      }
      return h >= 4.0 ? 'high' : 'low';
    }

    function bytesToB64(bytes, limit) {
      var n = Math.min(bytes.length, limit == null ? bytes.length : limit);
      var bin = '';
      var CHUNK = 0x8000;
      for (var i = 0; i < n; i += CHUNK) {
        var sub = bytes.subarray(i, Math.min(i + CHUNK, n));
        for (var j = 0; j < sub.length; j++) bin += String.fromCharCode(sub[j]);
      }
      if (env.btoa) return env.btoa(bin);
      if (typeof Buffer !== 'undefined') return Buffer.from(bin, 'binary').toString('base64');
      return '';
    }

    function sha256Hex(bytes, cb) {
      safe(function () {
        var subtle = env.crypto && env.crypto.subtle;
        if (!subtle || !subtle.digest) { cb(null); return; }
        Promise.resolve(subtle.digest('SHA-256', bytes)).then(function (digest) {
          var arr = new Uint8Array(digest);
          var hex = '';
          for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2);
          cb(hex);
        }, function () { cb(null); });
      });
    }

    function toUint8(data, cb) {
      safe(function () {
        if (data == null) { cb(null); return; }
        if (data instanceof Uint8Array) { cb(data); return; }
        if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) { cb(new Uint8Array(data)); return; }
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(data)) { cb(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)); return; }
        if (env.Blob && data instanceof env.Blob && data.arrayBuffer) {
          data.arrayBuffer().then(function (ab) { cb(new Uint8Array(ab)); }, function () { cb(null); });
          return;
        }
        cb(null);
      });
    }

    // ---- 拦截安装 ----
    function install() {
      safe(function () {
        var nav = env.navigator;
        var scr = env.screen;
        var doc = env.document;

        // canvas（FP_APIS: canvas.*）
        if (env.HTMLCanvasElement && env.HTMLCanvasElement.prototype) {
          wrapMethod(env.HTMLCanvasElement.prototype, 'toDataURL', 'canvas.toDataURL');
          wrapMethod(env.HTMLCanvasElement.prototype, 'toBlob', 'canvas.toBlob');
        }
        if (env.CanvasRenderingContext2D && env.CanvasRenderingContext2D.prototype) {
          wrapMethod(env.CanvasRenderingContext2D.prototype, 'getImageData', 'canvas.getImageData');
          wrapMethod(env.CanvasRenderingContext2D.prototype, 'measureText', 'canvas.measureText');
        }
        // WebGL（FP_APIS: webgl.*）
        ['WebGLRenderingContext', 'WebGL2RenderingContext'].forEach(function (cls) {
          var proto = env[cls] && env[cls].prototype;
          if (!proto) return;
          wrapMethod(proto, 'getParameter', 'webgl.getParameter');
          wrapMethod(proto, 'getSupportedExtensions', 'webgl.getSupportedExtensions');
          wrapMethod(proto, 'getExtension', 'webgl.getExtension');
          wrapMethod(proto, 'getShaderPrecisionFormat', 'webgl.getShaderPrecisionFormat');
          wrapMethod(proto, 'readPixels', 'webgl.readPixels');
        });
        // Audio（SPEC §3.1 + FP_APIS audio.*）
        ['AudioContext', 'OfflineAudioContext', 'webkitAudioContext'].forEach(function (cls) {
          var proto = env[cls] && env[cls].prototype;
          if (!proto) return;
          wrapMethod(proto, 'createAnalyser', 'audio.createAnalyser');
          wrapMethod(proto, 'createDynamicsCompressor', 'audio.createDynamicsCompressor');
          wrapMethod(proto, 'createOscillator', 'audio.createOscillator');
        });
        if (env.OfflineAudioContext && env.OfflineAudioContext.prototype) {
          wrapMethod(env.OfflineAudioContext.prototype, 'startRendering', 'audio.offline.startRendering');
        }
        if (env.AnalyserNode && env.AnalyserNode.prototype) {
          wrapMethod(env.AnalyserNode.prototype, 'getFloatFrequencyData', 'audio.getFloatFrequencyData');
        }
        // fonts（FP_APIS fonts.*）
        if (env.FontFaceSet && env.FontFaceSet.prototype) {
          wrapMethod(env.FontFaceSet.prototype, 'check', 'fonts.check');
          wrapMethod(env.FontFaceSet.prototype, 'load', 'fonts.load');
        }
        // navigator / screen（FP_APIS navigator.*、screen.* + SPEC §3.1）
        if (nav) {
          wrapGetter(nav, 'plugins', 'navigator.plugins');
          wrapGetter(nav, 'hardwareConcurrency', 'navigator.hardwareConcurrency');
          wrapGetter(nav, 'deviceMemory', 'navigator.deviceMemory');
          wrapGetter(nav, 'languages', 'navigator.languages');
          wrapGetter(nav, 'userAgent', 'navigator.userAgent');
          wrapGetter(nav, 'platform', 'navigator.platform');
        }
        if (scr) {
          wrapGetter(scr, 'width', 'screen.width');
          wrapGetter(scr, 'height', 'screen.height');
          wrapGetter(scr, 'colorDepth', 'screen.colorDepth');
        }

        installWorkers();
        installWasm();
        installStorage(doc);
        installVisibility(doc);
      });
    }

    // Worker / SharedWorker → worker_spawn（blob URL sha256 异步不阻塞）
    function installWorkers() {
      ['Worker', 'SharedWorker'].forEach(function (cls) {
        safe(function () {
          var Orig = env[cls];
          if (typeof Orig !== 'function') return;
          var Wrapped = function (url, opts) {
            safe(function () {
              var u = String(url);
              emitRaw('worker_spawn', cls, u, { script_url: u });
              if (u.indexOf('blob:') === 0 && typeof env.fetch === 'function') {
                Promise.resolve(env.fetch(u)).then(function (r) { return r.arrayBuffer(); })
                  .then(function (ab) {
                    var bytes = new Uint8Array(ab);
                    sha256Hex(bytes, function (hex) {
                      post({
                        v: PROTO_VERSION, type: 'payload_sample',
                        sha256: hex, kind: 'js', size: bytes.length,
                        head_b64: bytesToB64(bytes, 64 * 1024),
                        source_url: u, ts: now()
                      });
                    });
                  }, function () {});
              }
            });
            return new Orig(url, opts); // 不干预构造
          };
          Wrapped.prototype = Orig.prototype;
          disguise(Wrapped, cls);
          env[cls] = Wrapped;
          if (env.window) safe(function () { env.window[cls] = Wrapped; });
        });
      });
    }

    // WebAssembly.instantiate*/compile* → wasm_load + payload_sample（前 64KB base64）
    function installWasm() {
      safe(function () {
        var WA = env.WebAssembly;
        if (!WA) return;
        function wasmObserve(apiName, data) {
          toUint8(data, function (bytes) {
            if (!bytes) { emitRaw('wasm_load', 'WebAssembly.' + apiName, 'bytes unavailable'); return; }
            sha256Hex(bytes, function (hex) {
              emitRaw('wasm_load', 'WebAssembly.' + apiName,
                'size=' + bytes.length + ' sha256=' + (hex || 'n/a'),
                { size: bytes.length, sha256: hex });
              post({
                v: PROTO_VERSION, type: 'payload_sample',
                sha256: hex, kind: 'wasm', size: bytes.length,
                head_b64: bytesToB64(bytes, 64 * 1024),
                source_url: null, ts: now()
              });
            });
          });
        }
        ['instantiate', 'instantiateStreaming', 'compile', 'compileStreaming'].forEach(function (name) {
          safe(function () {
            var orig = WA[name];
            if (typeof orig !== 'function') return;
            WA[name] = disguise(function () {
              var args = arguments;
              safe(function () {
                var src = args[0];
                if (name === 'instantiate' && src instanceof WA.Module) return;
                if (name.indexOf('Streaming') !== -1) {
                  // Response promise：克隆后旁路观察，不消费原流
                  Promise.resolve(src).then(function (resp) {
                    if (resp && typeof resp.clone === 'function') {
                      return resp.clone().arrayBuffer().then(function (ab) { wasmObserve(name, ab); });
                    }
                    wasmObserve(name, resp);
                  }, function () {});
                } else {
                  wasmObserve(name, src);
                }
              });
              return orig.apply(this, args); // 立即返回，哈希异步不阻塞
            }, name);
          });
        });
      });
    }

    // localStorage.setItem + document.cookie setter → storage_write（不落值）
    function installStorage(doc) {
      safe(function () {
        var LS = env.Storage && env.Storage.prototype;
        if (!LS || typeof LS.setItem !== 'function') return;
        var orig = LS.setItem.__tishen_orig || LS.setItem;
        var wrapped = function () {
          var args = arguments;
          var self = this;
          safe(function () {
            var key = String(args[0]);
            var val = args[1] == null ? '' : String(args[1]);
            emitRaw('storage_write', 'localStorage.setItem',
              'key=' + key + ' len=' + val.length,
              { key: key, value_len: val.length, entropy: entropyClass(val) });
          });
          return orig.apply(self, args);
        };
        disguise(wrapped, 'setItem');
        Object.defineProperty(wrapped, '__tishen_orig', { value: orig, configurable: true });
        LS.setItem = wrapped;
      });
      safe(function () {
        if (!doc) return;
        var target = null, setter = null, getter = null;
        var p = doc;
        while (p) {
          var d = Object.getOwnPropertyDescriptor(p, 'cookie');
          if (d && d.set) { target = p; setter = d.set; getter = d.get; break; }
          p = Object.getPrototypeOf(p);
        }
        if (!target || !setter || (Object.getOwnPropertyDescriptor(target, 'cookie') || {}).configurable === false) return;
        Object.defineProperty(target, 'cookie', {
          get: getter,
          set: disguise(function (v) {
            safe(function () {
              var kv = String(v);
              var eq = kv.indexOf('=');
              var key = eq === -1 ? kv : kv.slice(0, eq);
              var val = eq === -1 ? '' : kv.slice(eq + 1);
              emitRaw('storage_write', 'document.cookie',
                'key=' + key + ' len=' + val.length,
                { key: key, value_len: val.length, entropy: entropyClass(val) });
            });
            return setter.call(this, v);
          }, 'set cookie'),
          configurable: true, enumerable: true
        });
      });
    }

    // visibilitychange → visibility_probe（前后 5s 事件密度快照）
    function installVisibility(doc) {
      safe(function () {
        if (!doc || typeof doc.addEventListener !== 'function') return;
        doc.addEventListener('visibilitychange', function () {
          safe(function () {
            var t = now();
            var state = doc.visibilityState || (doc.hidden ? 'hidden' : 'visible');
            var pre = 0;
            for (var i = 0; i < eventClock.length; i++) {
              if (t - eventClock[i] <= 5000) pre++;
            }
            emitRaw('visibility_probe', 'visibilitychange', state + ' pre_5s=' + pre,
              { state: state, pre_5s: pre, post_5s: null });
            var sched = env.setTimeout;
            if (sched) {
              sched(function () {
                safe(function () {
                  if (disposed) return;
                  var t2 = now(), post5 = 0;
                  for (var j = 0; j < eventClock.length; j++) {
                    if (eventClock[j] > t && t2 - eventClock[j] <= 5000) post5++;
                  }
                  emitRaw('visibility_probe', 'visibilitychange', state + ' post_5s=' + post5,
                    { state: state, pre_5s: pre, post_5s: post5 });
                });
              }, 5000);
            }
          });
        });
      });
    }

    install();

    return {
      posted: posted,
      dispose: function () { disposed = true; },
      _internals: {
        emitApiCall: emitApiCall, emitRaw: emitRaw,
        entropyClass: entropyClass, keep: keep, parseStack: parseStack
      }
    };
  }

  // 工厂暴露（node 测试用）；页面环境自动安装
  global.__tishenHookFactory = createTishenHook;
  if (global.window && global.document && !global.__tishenHookNoAuto) {
    try {
      createTishenHook({
        window: global.window, document: global.document, navigator: global.navigator,
        screen: global.screen, location: global.location, Function: global.Function,
        HTMLCanvasElement: global.HTMLCanvasElement,
        CanvasRenderingContext2D: global.CanvasRenderingContext2D,
        WebGLRenderingContext: global.WebGLRenderingContext,
        WebGL2RenderingContext: global.WebGL2RenderingContext,
        AudioContext: global.AudioContext, OfflineAudioContext: global.OfflineAudioContext,
        webkitAudioContext: global.webkitAudioContext, AnalyserNode: global.AnalyserNode,
        FontFaceSet: global.FontFaceSet, Worker: global.Worker, SharedWorker: global.SharedWorker,
        WebAssembly: global.WebAssembly, Storage: global.Storage, Document: global.Document,
        Blob: global.Blob, crypto: global.crypto,
        fetch: global.fetch ? global.fetch.bind(global) : undefined,
        btoa: global.btoa ? global.btoa.bind(global) : undefined,
        setTimeout: typeof global.setTimeout === 'function' ? global.setTimeout.bind(global) : undefined
      });
    } catch (e) { /* 静默 */ }
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
