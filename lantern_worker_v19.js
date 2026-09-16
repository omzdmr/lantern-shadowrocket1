export default {
  async fetch(request) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/health") {
        return json({ ok: true, service: "lantern-worker-v19" });
      }
      const nodes = await fetchLanternNodes();
      if (url.pathname === "/node.json") {
        return json(toShadowrocketNode(nodes[0], 1), "Lantern-Auto-v19.json");
      }
      if (url.pathname === "/nodes.json" || url.pathname === "/") {
        return json(nodes.map((n, i) => toShadowrocketNode(n, i + 1)), "Lantern-All-v19.json");
      }
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return new Response("Lantern Worker v19 ERROR\n" + (e && e.message ? e.message : String(e)), {
        status: 502,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }
      });
    }
  }
};

const CONFIG_URL = "https://df.iantem.io/api/v1/config";
const LUA_PATH = "lantern_tls_resume_smux_v16_2.lua";
const L = {
  flashlightVersion: "7.6.179",
  clientVersion: "9999.99.99",
  userId: "381696446",
  proToken: "K1qttSsZruN",
  deviceId: "a34113",
  platform: "android",
  locale: "",
  timezone: "Asia/Shanghai"
};

async function fetchLanternNodes() {
  const body = new Uint8Array(requestBody());
  const res = await fetch(CONFIG_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-protobuf",
      "accept": "application/x-protobuf",
      "cache-control": "no-cache",
      "x-lantern-version": L.flashlightVersion,
      "x-lantern-app-version": L.clientVersion,
      "x-lantern-app": "",
      "x-lantern-device-id": L.deviceId,
      "x-lantern-platform": L.platform,
      "x-lantern-pro-token": L.proToken,
      "x-lantern-user-id": L.userId,
      "x-lantern-locale": L.locale,
      "x-lantern-time-zone": L.timezone,
      "x-lantern-supported-data-caps": "monthly, weekly, daily",
      "x-lantern-rand": rand(64)
    },
    body
  });
  if (!res.ok) throw new Error("Lantern API HTTP " + res.status);
  const raw = new Uint8Array(await res.arrayBuffer());
  const nodes = scan(raw);
  if (!nodes.length) throw new Error("uyumlu TLS 1.2/c02b node bulunamadi");
  return nodes;
}

function json(obj, filename) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  };
  if (filename) headers["content-disposition"] = `attachment; filename="${filename}"`;
  return new Response(JSON.stringify(obj, null, 2), { status: 200, headers });
}

function utf8Encode(s) { return Array.from(new TextEncoder().encode(String(s))); }
function utf8Decode(a) { return new TextDecoder("utf-8").decode(a instanceof Uint8Array ? a : new Uint8Array(a)); }
function cat(...args) { const o=[]; for (const a of args) for (const v of (a || [])) o.push(v & 255); return o; }
function vint(n) { const o=[]; n=Number(n); while (n>127) { o.push((n&127)|128); n=Math.floor(n/128); } o.push(n&127); return o; }
function key(n,w){ return vint(n*8+w); }
function fbytes(n,b){ return cat(key(n,2),vint(b.length),b); }
function fstr(n,s){ return s ? fbytes(n,utf8Encode(s)) : []; }
const ZERO=[0x80,0x92,0xb8,0xc3,0x98,0xfe,0xff,0xff,0xff,0x01];
function requestBody(){
  const ci=cat(fstr(1,L.flashlightVersion),fstr(2,L.clientVersion),fstr(3,L.userId),fstr(4,L.proToken));
  const ts=cat(key(1,0),ZERO);
  const px=fbytes(2,ts);
  return cat(fbytes(1,ci),fbytes(2,px));
}

function readVar(b,p){
  let n=0,m=1,c=0;
  while(p<b.length){
    const x=b[p++]; n+=(x&127)*m;
    if((x&128)===0) return {v:n,p};
    m*=128;
    if(++c>9) throw new Error("varint");
  }
  throw new Error("truncated");
}

function fields(bytes){
  const out=[]; let p=0;
  while(p<bytes.length){
    const k=readVar(bytes,p); p=k.p;
    const no=Math.floor(k.v/8), w=k.v&7;
    if(no<=0 || (w!==0&&w!==1&&w!==2&&w!==5)) throw new Error("wire");
    if(w===0){ const q=readVar(bytes,p); p=q.p; out.push({n:no,w,v:q.v}); }
    else if(w===1){ if(p+8>bytes.length) throw new Error("fixed64"); out.push({n:no,w,b:bytes.slice(p,p+8)}); p+=8; }
    else if(w===5){ if(p+4>bytes.length) throw new Error("fixed32"); out.push({n:no,w,b:bytes.slice(p,p+4)}); p+=4; }
    else { const z=readVar(bytes,p); p=z.p; if(z.v<0||p+z.v>bytes.length) throw new Error("len"); out.push({n:no,w,b:bytes.slice(p,p+z.v)}); p+=z.v; }
  }
  return out;
}
function one(fs,n,w){ return fs.find(x => x.n===n && (w===undefined || x.w===w)) || null; }
function all(fs,n,w){ return fs.filter(x => x.n===n && (w===undefined || x.w===w)); }
function ascii(b){ try { return utf8Decode(b); } catch { return ""; } }
function looksHost(s){ return !!s && s.length<256 && /^[A-Za-z0-9._:-]+$/.test(s); }

function parseTLS(raw){
  try {
    const f=fields(raw), sf=one(f,1,2), frag=one(f,2,2), sniF=one(f,3,2);
    if(!sf||!sniF) return null;
    const sfs=fields(sf.b), ticket=one(sfs,1,2), ver=one(sfs,2,0), cipher=one(sfs,3,0), master=one(sfs,4,2);
    const sni=ascii(sniF.b);
    if(!ticket||!ver||!cipher||!master||!looksHost(sni)) return null;
    if(Number(ver.v)!==0x0303 || Number(cipher.v)!==0xc02b || master.b.length!==48 || ticket.b.length===0) return null;
    return { ticket:Array.from(ticket.b), master:Array.from(master.b), sni, tlsFrag:frag?ascii(frag.b):"" };
  } catch { return null; }
}

function maybeProxy(fs){
  const addrF=one(fs,1,2), portF=one(fs,5,0), authF=one(fs,11,2);
  if(!addrF||!portF||!authF) return null;
  const addr=ascii(addrF.b), auth=ascii(authF.b);
  if(!looksHost(addr)||auth.length!==64) return null;
  for (const tr of all(fs,20,2)) {
    const t=parseTLS(tr.b);
    if(t) return { addr, port:Number(portF.v), auth, sni:t.sni, ticket:t.ticket, master:t.master, tlsFrag:t.tlsFrag };
  }
  return null;
}

function scan(root){
  const found=[], seen=new Set();
  function walk(raw,depth){
    if(depth>7||!raw||raw.length<2) return;
    let fs; try { fs=fields(raw); } catch { return; }
    const p=maybeProxy(fs);
    if(p){ const id=`${p.addr}:${p.port}|${p.sni}|${p.auth}`; if(!seen.has(id)){ seen.add(id); found.push(p); } }
    for(const f of fs){ if(f.w===2 && f.b && f.b.length>=2 && f.b.length<=200000) walk(f.b,depth+1); }
  }
  walk(root,0);
  found.sort((a,b)=>(a.tlsFrag?1:0)-(b.tlsFrag?1:0));
  return found;
}

function b64(bytes){
  let s=""; for(const b of bytes) s+=String.fromCharCode(b);
  return btoa(s);
}
function stableUUID(n){
  const s=`${n.addr}:${n.port}|${n.sni}`;
  let h1=2166136261>>>0, h2=2246822519>>>0;
  for(let i=0;i<s.length;i++){ h1=Math.imul(h1^s.charCodeAt(i),16777619)>>>0; h2=Math.imul(h2^s.charCodeAt(i),3266489917)>>>0; }
  const hex=(h1.toString(16).padStart(8,"0")+h2.toString(16).padStart(8,"0")+h1.toString(16).padStart(8,"0")+h2.toString(16).padStart(8,"0")).slice(0,32);
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`.toUpperCase();
}
function toShadowrocketNode(n,i){
  const now=Date.now()/1000;
  return {
    host:n.addr,
    path:LUA_PATH,
    type:"Lua",
    user:n.sni+"|"+b64(n.ticket),
    plugin:"none",
    method:"aes-256-cfb",
    udp:0,
    allowInsecure:1,
    port:String(n.port),
    obfs:"none",
    proto:"none",
    password:b64(n.master)+n.auth,
    title:`Lantern Auto v19 ${n.sni}`,
    uuid:stableUUID(n),
    created:now,
    updated:now,
    weight:Math.floor(now),
    tlsFrag:n.tlsFrag || ""
  };
}
function rand(n){ const c="abcdefghijklmnopqrstuvwxyz", a=[]; for(let i=0;i<n;i++) a.push(c[Math.floor(Math.random()*c.length)]); return a.join(""); }
