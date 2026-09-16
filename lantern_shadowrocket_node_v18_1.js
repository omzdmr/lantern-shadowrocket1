/* Lantern Free -> Shadowrocket real Lua node JSON generator v18.1
 * Uses the proven v17 Lantern request/parser shape, but tolerates malformed or
 * unsupported proxy entries so one non-TLS transport cannot kill the whole feed.
 */
(function () {
  "use strict";

  var HOST = "connect.rom.miui.com";
  var SINGLE_PATH = "/lantern-node-v18-1.json";
  var ALL_PATH = "/lantern-nodes-v18-1.json";
  var CONFIG_URL = "https://df.iantem.io/api/v1/config";
  var LUA_PATH = "lantern_tls_resume_smux_v16_2.lua";

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
    if (typeof TextEncoder !== "undefined") return Array.prototype.slice.call(new TextEncoder().encode(String(str)));
    str = String(str); var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
    return out;
  }
  function utf8Decode(arr) {
    if (typeof TextDecoder !== "undefined") { try { return new TextDecoder("utf-8").decode(new Uint8Array(arr)); } catch (_) {} }
    var s = "";
    for (var i = 0; i < arr.length;) {
      var c = arr[i++];
      if (c < 0x80) s += String.fromCharCode(c);
      else if ((c & 0xe0) === 0xc0) { var c2 = arr[i++]; s += String.fromCharCode(((c & 0x1f) << 6) | (c2 & 0x3f)); }
      else { var c2e = arr[i++], c3e = arr[i++]; s += String.fromCharCode(((c & 0x0f) << 12) | ((c2e & 0x3f) << 6) | (c3e & 0x3f)); }
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
    var out = []; n = Number(n);
    while (n > 127) { out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
    out.push(n & 0x7f); return out;
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
    var x = this.b.slice(this.p, this.p + len); this.p += len; return x;
  };
  Reader.prototype.skip = function (wire) {
    if (wire === 0) { this.varint(); return true; }
    if (wire === 1) { this.p += 8; return true; }
    if (wire === 2) { this.p += this.varint(); return true; }
    if (wire === 5) { this.p += 4; return true; }
    return false;
  };
  function readFields(bytes, fn) {
    var r = new Reader(bytes);
    while (!r.eof()) {
      var k;
      try { k = r.varint(); } catch (_) { break; }
      var no = Math.floor(k / 8), wire = k & 7;
      if (wire !== 0 && wire !== 1 && wire !== 2 && wire !== 5) break;
      var handled = false;
      try { handled = !!fn(r, no, wire); } catch (_) { break; }
      if (!handled && !r.skip(wire)) break;
      if (r.p > r.b.length) break;
    }
  }
  function readString(r, wire) { if (wire !== 2) throw new Error("expected string"); return utf8Decode(r.bytes()); }

  function parseTLSSessionState(bytes) {
    var o = { ticket: [], version: 0, cipherSuite: 0, masterSecret: [] };
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) { o.ticket = Array.prototype.slice.call(r.bytes()); return true; }
      if (no === 2 && wire === 0) { o.version = r.varint(); return true; }
      if (no === 3 && wire === 0) { o.cipherSuite = r.varint(); return true; }
      if (no === 4 && wire === 2) { o.masterSecret = Array.prototype.slice.call(r.bytes()); return true; }
      return false;
    });
    return o;
  }
  function parseTLS(bytes) {
    var o = { sessionState: null, tlsFrag: "", sni: "" };
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) { o.sessionState = parseTLSSessionState(r.bytes()); return true; }
      if (no === 2 && wire === 2) { o.tlsFrag = readString(r, wire); return true; }
      if (no === 3 && wire === 2) { o.sni = readString(r, wire); return true; }
      return false;
    });
    return o;
  }
  function parseProxy(bytes) {
    var p = { addr:"", port:0, name:"", authToken:"", transport:null };
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) { p.addr = readString(r, wire); return true; }
      if (no === 4 && wire === 2) { p.name = readString(r, wire); return true; }
      if (no === 5 && wire === 0) { p.port = r.varint(); return true; }
      if (no === 11 && wire === 2) { p.authToken = readString(r, wire); return true; }
      if (no === 20 && wire === 2) { p.transport = parseTLS(r.bytes()); return true; }
      return false;
    });
    return p;
  }
  function parseProxyContainer(bytes) {
    var out = [];
    readFields(bytes, function (r, no, wire) {
      if (no === 1 && wire === 2) {
        var raw = r.bytes();
        try {
          var p = parseProxy(raw);
          if (p.addr || p.port || p.transport) out.push(p);
        } catch (_) {}
        return true;
      }
      return false;
    });
    return out;
  }
  function parseConfigResponse(bytes) {
    var out = { country:"", proxies:[] };
    readFields(bytes, function (r, no, wire) {
      if (no === 2 && wire === 2) { out.country = readString(r, wire); return true; }
      if (no === 4 && wire === 2) { out.proxies = parseProxyContainer(r.bytes()); return true; }
      return false;
    });
    return out;
  }

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64(bytes) {
    bytes = bytes || []; var out = "";
    for (var i = 0; i < bytes.length; i += 3) {
      var a = bytes[i], b = i + 1 < bytes.length ? bytes[i + 1] : 0, c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      var n = (a << 16) | (b << 8) | c;
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] +
        (i + 1 < bytes.length ? B64[(n >> 6) & 63] : "=") +
        (i + 2 < bytes.length ? B64[n & 63] : "=");
    }
    return out;
  }
  function randomLowercase(n) { var chars="abcdefghijklmnopqrstuvwxyz", out=""; for (var i=0;i<n;i++) out += chars.charAt(Math.floor(Math.random()*chars.length)); return out; }

  function compatibleNodes(cfg) {
    var out = [];
    (cfg.proxies || []).forEach(function (p) {
      var t = p.transport, s = t && t.sessionState;
      if (!t || !s) return;
      if (Number(s.version) !== 0x0303 || Number(s.cipherSuite) !== 0xc02b) return;
      if (!p.addr || !p.port || !t.sni) return;
      if ((s.ticket || []).length === 0 || (s.masterSecret || []).length !== 48) return;
      if (String(p.authToken || "").length !== 64) return;
      out.push({
        addr:String(p.addr), port:String(p.port), sni:String(t.sni), tlsFrag:String(t.tlsFrag || ""),
        ticket:b64(s.ticket), master:b64(s.masterSecret), auth:String(p.authToken)
      });
    });
    out.sort(function (a,b) { return (a.tlsFrag ? 1 : 0) - (b.tlsFrag ? 1 : 0); });
    return out;
  }

  function stableUuid(index) {
    var tail = String(9000 + index);
    return "A18E3C6D-27A2-4D2B-94B7-8C1E7A5F" + tail;
  }
  function nodeJson(n, index) {
    var now = Date.now() / 1000;
    return {
      host:n.addr,
      path:LUA_PATH,
      type:"Lua",
      user:n.sni + "|" + n.ticket,
      plugin:"none",
      method:"aes-256-cfb",
      udp:0,
      allowInsecure:1,
      port:n.port,
      obfs:"none",
      proto:"none",
      password:n.master + n.auth,
      title:"Lantern Auto v18.1 " + n.sni,
      uuid:stableUuid(index),
      created:now,
      updated:now,
      weight:Math.floor(now)
    };
  }

  function respondJson(obj, filename) {
    $done({response:{status:200,headers:{
      "Content-Type":"application/json; charset=utf-8",
      "Content-Disposition":"attachment; filename=\"" + filename + "\"",
      "Cache-Control":"no-store, no-cache, must-revalidate",
      "Pragma":"no-cache"
    },body:JSON.stringify(obj,null,2)}});
  }
  function fail(msg) {
    $done({response:{status:502,headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store"},body:"Lantern v18.1 ERROR\n" + String(msg)}});
  }

  function fetchAndBuild(all) {
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
        var nodes = compatibleNodes(cfg);
        if (!nodes.length) return fail("uyumlu TLS 1.2/c02b node bulunamadi; parsedProxies=" + (cfg.proxies || []).length + " country=" + (cfg.country || ""));
        if (all) return respondJson(nodes.map(function(n,i){return nodeJson(n,i+1);}), "Lantern-All-v18-1.json");
        return respondJson(nodeJson(nodes[0],1), "Lantern-Auto-v18-1.json");
      } catch (e) {
        return fail("decode/build: " + (e && e.message ? e.message : String(e)));
      }
    });
  }

  var url = (typeof $request !== "undefined" && $request.url) ? $request.url : "";
  if (url.indexOf("http://" + HOST + SINGLE_PATH) === 0) return fetchAndBuild(false);
  if (url.indexOf("http://" + HOST + ALL_PATH) === 0) return fetchAndBuild(true);
  return $done({});
})();