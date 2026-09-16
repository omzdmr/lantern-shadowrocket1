/*
 Lantern Free -> Shadowrocket TLS material extractor v16
 LOCAL ONLY. Fetches Lantern Free SDK config on-device and exposes TLS resume
 material only in the synthetic local response. Do not publish/copy the L16
 bundle to GitHub, logs, issues, or chat.
*/
(function () {
  "use strict";

  var FEED_HOST = "connect.rom.miui.com";
  var CONFIG_URL = "https://df.iantem.io/api/v1/config";
  var LANTERN = {
    flashlightVersion: "7.6.179",
    clientVersion: "9999.99.99",
    userId: "381696446",
    proToken: "K1qttSsZruN",
    deviceId: "a34113",
    platform: "android",
    locale: "",
    timezone: "Asia/Shanghai"
  };

  function utf8Encode(str) {
    if (typeof TextEncoder !== "undefined") {
      return Array.prototype.slice.call(new TextEncoder().encode(String(str)));
    }
    str = String(str);
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
    return out;
  }

  function utf8Decode(arr) {
    if (typeof TextDecoder !== "undefined") {
      try { return new TextDecoder("utf-8").decode(new Uint8Array(arr)); } catch (_) {}
    }
    var s = "";
    for (var i = 0; i < arr.length;) {
      var c = arr[i++];
      if (c < 0x80) s += String.fromCharCode(c);
      else if ((c & 0xe0) === 0xc0) {
        var c2 = arr[i++];
        s += String.fromCharCode(((c & 0x1f) << 6) | (c2 & 0x3f));
      } else {
        var c2e = arr[i++], c3e = arr[i++];
        s += String.fromCharCode(((c & 0x0f) << 12) | ((c2e & 0x3f) << 6) | (c3e & 0x3f));
      }
    }
    return s;
  }

  function concat() {
    var out = [];
    for (var i = 0; i < arguments.length; i++) {
      var a = arguments[i] || [];
      for (var j = 0; j < a.length; j++) out.push(a[j] & 255);
    }
    return out;
  }

  function encVarint(n) {
    var out = [];
    n = Number(n);
    while (n > 127) {
      out.push((n & 0x7f) | 0x80);
      n = Math.floor(n / 128);
    }
    out.push(n & 0x7f);
    return out;
  }
  function key(fieldNo, wireType) { return encVarint(fieldNo * 8 + wireType); }
  function fieldBytes(fieldNo, bytes) { return concat(key(fieldNo, 2), encVarint(bytes.length), bytes); }
  function fieldString(fieldNo, value) {
    if (value === undefined || value === null || value === "") return [];
    return fieldBytes(fieldNo, utf8Encode(String(value)));
  }
  function fieldMessage(fieldNo, bytes) { return fieldBytes(fieldNo, bytes); }

  var ZERO_GO_TIME_SECONDS_VARINT = [0x80,0x92,0xb8,0xc3,0x98,0xfe,0xff,0xff,0xff,0x01];
  function buildConfigRequest() {
    var clientInfo = concat(
      fieldString(1, LANTERN.flashlightVersion),
      fieldString(2, LANTERN.clientVersion),
      fieldString(3, LANTERN.userId),
      fieldString(4, LANTERN.proToken)
    );
    var timestamp = concat(key(1, 0), ZERO_GO_TIME_SECONDS_VARINT);
    var proxy = fieldMessage(2, timestamp);
    return concat(fieldMessage(1, clientInfo), fieldMessage(2, proxy));
  }

  function toArrayBuffer(bytes) { return new Uint8Array(bytes).buffer; }
  function normalizeBinary(data, response) {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (typeof Uint8Array !== "undefined" && data instanceof Uint8Array) return data;
    if (response && response.bodyBytes instanceof ArrayBuffer) return new Uint8Array(response.bodyBytes);
    if (response && response.bodyBytes instanceof Uint8Array) return response.bodyBytes;
    if (response && response.body instanceof ArrayBuffer) return new Uint8Array(response.body);
    if (response && response.body instanceof Uint8Array) return response.body;
    if (typeof data === "string") {
      var a = new Uint8Array(data.length);
      for (var i = 0; i < data.length; i++) a[i] = data.charCodeAt(i) & 255;
      return a;
    }
    throw new Error("Binary protobuf response not available");
  }

  function Reader(input) { this.b = input instanceof Uint8Array ? input : new Uint8Array(input); this.p = 0; }
  Reader.prototype.eof = function () { return this.p >= this.b.length; };
  Reader.prototype.varint = function () {
    var n = 0, mul = 1, count = 0;
    while (this.p < this.b.length) {
      var x = this.b[this.p++];
      n += (x & 0x7f) * mul;
      if ((x & 0x80) === 0) return n;
      mul *= 128;
      if (++count > 9) throw new Error("varint too long");
    }
    throw new Error("truncated varint");
  };
  Reader.prototype.bytes = function () {
    var len = this.varint();
    if (len < 0 || this.p + len > this.b.length) throw new Error("bad length");
    var x = this.b.slice(this.p, this.p + len);
    this.p += len;
    return x;
  };
  Reader.prototype.skip = function (wire) {
    if (wire === 0) { this.varint(); return; }
    if (wire === 1) { this.p += 8; return; }
    if (wire === 2) { var n = this.varint(); this.p += n; return; }
    if (wire === 5) { this.p += 4; return; }
    throw new Error("unsupported protobuf wire type " + wire);
  };
  function readFields(bytes, fn) {
    var r = new Reader(bytes);
    while (!r.eof()) {
      var k = r.varint(), no = Math.floor(k / 8), wire = k & 7;
      if (!fn(r, no, wire)) r.skip(wire);
      if (r.p > r.b.length) throw new Error("protobuf overrun");
    }
  }
  function readString(r, wire) {
    if (wire !== 2) throw new Error("expected string");
    return utf8Decode(r.bytes());
  }

  function parseTLSSessionState(bytes) {
    var o = { ticket: [], version: 0, cipherSuite: 0, masterSecret: [], serializedState: [] };
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) { o.ticket = Array.prototype.slice.call(r.bytes()); return true; }
      if (no === 2 && wire === 0) { o.version = r.varint(); return true; }
      if (no === 3 && wire === 0) { o.cipherSuite = r.varint(); return true; }
      if (no === 4 && wire === 2) { o.masterSecret = Array.prototype.slice.call(r.bytes()); return true; }
      if (no === 5 && wire === 2) { o.serializedState = Array.prototype.slice.call(r.bytes()); return true; }
      return false;
    });
    return o;
  }

  function parseTLS(bytes) {
    var o = { type: "tls", sessionState: null, tlsFrag: "", sni: "" };
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) { o.sessionState = parseTLSSessionState(r.bytes()); return true; }
      if (no === 2) { o.tlsFrag = readString(r, wire); return true; }
      if (no === 3) { o.sni = readString(r, wire); return true; }
      return false;
    });
    return o;
  }

  function parseProxy(bytes) {
    var p = { addr:"", port:0, name:"", authToken:"", transport:null };
    readFields(bytes, function (r, no, wire) {
      if (no === 1) { p.addr = readString(r, wire); return true; }
      if (no === 4) { p.name = readString(r, wire); return true; }
      if (no === 5 && wire === 0) { p.port = r.varint(); return true; }
      if (no === 11) { p.authToken = readString(r, wire); return true; }
      if (no === 20 && wire === 2) { p.transport = parseTLS(r.bytes()); return true; }
      return false;
    });
    return p;
  }

  function parseProxyContainer(bytes) {
    var out = [];
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) { out.push(parseProxy(r.bytes())); return true; }
      return false;
    });
    return out;
  }

  function parseConfigResponse(bytes) {
    var out = { country:"", proxies:[] };
    readFields(bytes, function (r, no, wire) {
      if (no === 2) { out.country = readString(r, wire); return true; }
      if (no === 4 && wire === 2) { out.proxies = parseProxyContainer(r.bytes()); return true; }
      return false;
    });
    return out;
  }

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64(bytes) {
    bytes = bytes || [];
    var out = "", i;
    for (i = 0; i < bytes.length; i += 3) {
      var a = bytes[i], b = i + 1 < bytes.length ? bytes[i + 1] : 0, c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      var n = (a << 16) | (b << 8) | c;
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] +
             (i + 1 < bytes.length ? B64[(n >> 6) & 63] : "=") +
             (i + 2 < bytes.length ? B64[n & 63] : "=");
    }
    return out;
  }
  function b64s(s) { return b64(utf8Encode(String(s || ""))); }
  function hx(n) {
    var h = Number(n || 0).toString(16);
    while (h.length < 4) h = "0" + h;
    return "0x" + h;
  }

  function buildMaterial(cfg) {
    var tls = [];
    (cfg.proxies || []).forEach(function (p) {
      if (!p.transport || p.transport.type !== "tls" || !p.transport.sessionState) return;
      var ss = p.transport.sessionState;
      var bundle = [
        "L16",
        p.addr || "",
        String(p.port || 0),
        String(ss.version || 0),
        String(ss.cipherSuite || 0),
        b64s(p.transport.sni || ""),
        b64(ss.ticket || []),
        b64(ss.masterSecret || []),
        b64s(p.authToken || ""),
        b64s(p.transport.tlsFrag || ""),
        b64(ss.serializedState || [])
      ].join("|");
      tls.push({
        name: p.name || "",
        addr: p.addr || "",
        port: p.port || 0,
        sni: p.transport.sni || "",
        tlsFrag: p.transport.tlsFrag || "",
        tlsVersion: hx(ss.version),
        cipherSuite: hx(ss.cipherSuite),
        sessionTicketLen: (ss.ticket || []).length,
        masterSecretLen: (ss.masterSecret || []).length,
        serializedStateLen: (ss.serializedState || []).length,
        authTokenLen: String(p.authToken || "").length,
        bundle: bundle
      });
    });
    return {
      warning: "SECRET: L16 bundle'i ChatGPT/GitHub/loglara gonderme. Yalnizca Shadowrocket Parola alanina yapistir.",
      safeToShare: "Sadece name/addr/port/sni/tlsFrag/tlsVersion/cipherSuite ve *Len alanlarini paylasabilirsin.",
      fetchedAt: new Date().toISOString(),
      country: cfg.country || "",
      tlsCount: tls.length,
      tls: tls
    };
  }

  function htmlEscape(s) {
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;");
  }
  function page(text, ok) {
    var accent = ok ? "#30d158" : "#ff453a";
    return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
      "<title>Lantern TLS Material v16</title><style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#111;color:#eee;padding:18px}" +
      ".box{max-width:900px;margin:auto;background:#1c1c1e;border-radius:16px;padding:18px}h1{color:"+accent+";font-size:22px}" +
      "pre{white-space:pre-wrap;word-break:break-all;background:#000;padding:12px;border-radius:12px}</style></head><body><div class=\"box\">" +
      "<h1>Lantern TLS Material v16 - LOCAL ONLY</h1><pre>" + htmlEscape(text) + "</pre></div></body></html>";
  }
  function done(status, text, ok) {
    $done({ response: { status: status, headers: {"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}, body: page(text, ok) } });
  }
  function fail(msg) { done(502, "ERROR\n" + String(msg), false); }

  function randomLowercase(n) {
    var chars = "abcdefghijklmnopqrstuvwxyz", out = "";
    for (var i = 0; i < n; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
  }

  function fetchMaterial() {
    var reqBytes = buildConfigRequest();
    var opts = {
      url: CONFIG_URL,
      method: "POST",
      timeout: 20,
      headers: {
        "Content-Type":"application/x-protobuf",
        "Accept":"application/x-protobuf",
        "Cache-Control":"no-cache",
        "X-Lantern-Version":LANTERN.flashlightVersion,
        "X-Lantern-App-Version":LANTERN.clientVersion,
        "X-Lantern-App":"",
        "X-Lantern-Device-Id":LANTERN.deviceId,
        "X-Lantern-Platform":LANTERN.platform,
        "X-Lantern-Pro-Token":LANTERN.proToken,
        "X-Lantern-User-Id":LANTERN.userId,
        "X-Lantern-Locale":LANTERN.locale,
        "X-Lantern-Time-Zone":LANTERN.timezone,
        "X-Lantern-Supported-Data-Caps":"monthly, weekly, daily",
        "X-Lantern-Rand":randomLowercase(64),
        "X-Surge-Proxy":"DIRECT"
      },
      "binary-mode":true,
      body:toArrayBuffer(reqBytes)
    };
    $httpClient.post(opts, function (error, response, data) {
      if (error) return fail(error);
      var code = Number((response && (response.statusCode || response.status)) || 0);
      if (code !== 200) return fail("Lantern API HTTP " + code);
      try {
        var cfg = parseConfigResponse(normalizeBinary(data, response));
        var out = buildMaterial(cfg);
        if (!out.tlsCount) return fail("TLS proxy/session material bulunamadi");
        done(200, JSON.stringify(out, null, 2), true);
      } catch (e) {
        fail("decode: " + (e && e.message ? e.message : String(e)));
      }
    });
  }

  var url = (typeof $request !== "undefined" && $request.url) ? $request.url : "";
  if (url.indexOf("https://" + FEED_HOST + "/lantern-material-v16") === 0) return fetchMaterial();
  return $done({});
})();
