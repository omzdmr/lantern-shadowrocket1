/*
 Lantern Free -> Shadowrocket dynamic config generator v17

 Runs inside Shadowrocket. It fetches fresh Lantern Free TLS resume material
 on-device and returns a Shadowrocket .conf. Fresh session secrets are never
 stored in this repository.
*/
(function () {
  "use strict";

  var FEED_HOST = "connect.rom.miui.com";
  var FEED_PATH = "/lantern-dynamic-v17.conf";
  var CONFIG_URL = "https://df.iantem.io/api/v1/config";
  var LUA_PATH = "lantern_tls_resume_smux_v16_2.lua";
  var SCRIPT_URL = "https://cdn.jsdelivr.net/gh/omzdmr/lantern-shadowrocket1@main/lantern_shadowrocket_dynamic_v17.js";

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

  function randomLowercase(n) {
    var chars = "abcdefghijklmnopqrstuvwxyz", out = "";
    for (var i = 0; i < n; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
  }

  function safeName(s, n) {
    s = String(s || "").replace(/[\r\n,=]/g, "-").replace(/^\s+|\s+$/g, "");
    if (!s) s = "TLS-" + n;
    if (s.length > 40) s = s.slice(0, 40);
    return "Lantern-" + n + "-" + s;
  }

  function collectNodes(cfg) {
    var out = [];
    (cfg.proxies || []).forEach(function (p) {
      var t = p.transport, ss = t && t.sessionState;
      if (!t || t.type !== "tls" || !ss) return;
      if (Number(ss.version) !== 0x0303 || Number(ss.cipherSuite) !== 0xc02b) return;
      if (!p.addr || !p.port || !t.sni) return;
      if ((ss.ticket || []).length === 0 || (ss.masterSecret || []).length !== 48) return;
      if (String(p.authToken || "").length !== 64) return;
      out.push({
        name: safeName(p.name, out.length + 1),
        addr: String(p.addr),
        port: Number(p.port),
        sni: String(t.sni),
        tlsFrag: String(t.tlsFrag || ""),
        ticket: b64(ss.ticket),
        master: b64(ss.masterSecret),
        auth: String(p.authToken)
      });
    });
    return out;
  }

  function oneLine(s) { return String(s == null ? "" : s).replace(/[\r\n]/g, ""); }

  function buildConf(cfg) {
    var nodes = collectNodes(cfg);
    if (!nodes.length) throw new Error("compatible TLS 1.2/c02b proxy bulunamadi");

    var L = [];
    L.push("# Lantern Dynamic v17");
    L.push("# Generated on-device: " + new Date().toISOString());
    L.push("# Country: " + oneLine(cfg.country || ""));
    L.push("");
    L.push("[General]");
    L.push("ipv6 = false");
    L.push("prefer-ipv6 = false");
    L.push("dns-server = https://223.5.5.5/dns-query, https://doh.pub/dns-query");
    L.push("dns-direct-system = true");
    L.push("hijack-dns = 8.8.8.8:53, 8.8.4.4:53, 1.1.1.1:53");
    L.push("block-quic = all-proxy");
    L.push("udp-policy-not-supported-behaviour = REJECT");
    L.push("");
    L.push("[Proxy]");

    nodes.forEach(function (n) {
      var user = n.sni + "|" + n.ticket;
      var password = n.master + n.auth;
      L.push(n.name + " = lua," + n.addr + "," + n.port +
        ",user=" + user +
        ",password=" + password +
        ",method=aes-256-cfb" +
        ",path=" + LUA_PATH +
        ",allowInsecure=1" +
        ",udp=0" +
        ",plugin=none");
    });

    var names = nodes.map(function (n) { return n.name; });
    L.push("");
    L.push("[Proxy Group]");
    L.push("Lantern-Dynamic = random," + names.join(",") + ",url=http://example.com,interval=60,timeout=5");
    L.push("");
    L.push("[Rule]");
    L.push("DOMAIN," + FEED_HOST + ",DIRECT");
    L.push("DOMAIN,df.iantem.io,DIRECT");
    L.push("FINAL,Lantern-Dynamic");
    L.push("");
    L.push("[Script]");
    L.push("Lantern Dynamic v17 = type=http-request,pattern=^http:\\/\\/connect\\.rom\\.miui\\.com\\/lantern-dynamic-v17\\.conf(?:\\?.*)?$,requires-body=false,timeout=30,engine=jsc,script-path=" + SCRIPT_URL + ",enable=true");
    L.push("");
    L.push("# tlsFrag metadata (current v16.2 backend does not require it on the two tested nodes)");
    nodes.forEach(function (n) { L.push("# " + n.name + " tlsFrag=" + oneLine(n.tlsFrag)); });
    return L.join("\n") + "\n";
  }

  function done(status, body, contentType) {
    $done({ response: {
      status: status,
      headers: {
        "Content-Type": contentType || "text/plain; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache"
      },
      body: body
    }});
  }
  function fail(msg) { done(502, "# Lantern Dynamic v17 ERROR\n# " + String(msg) + "\n"); }

  function fetchDynamicConf() {
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
        done(200, buildConf(cfg), "text/plain; charset=utf-8");
      } catch (e) {
        fail("decode/build: " + (e && e.message ? e.message : String(e)));
      }
    });
  }

  var url = (typeof $request !== "undefined" && $request.url) ? $request.url : "";
  if (url.indexOf("http://" + FEED_HOST + FEED_PATH) === 0) return fetchDynamicConf();
  return $done({});
})();
