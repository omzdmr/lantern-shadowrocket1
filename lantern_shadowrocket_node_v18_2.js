/* Lantern Free -> Shadowrocket real Lua node JSON generator v18.2
 * Recursively scans protobuf messages for valid Lantern TLS proxy records.
 */
(function () {
  "use strict";

  var HOST = "connect.rom.miui.com";
  var SINGLE_PATH = "/lantern-node-v18-2.json";
  var ALL_PATH = "/lantern-nodes-v18-2.json";
  var CONFIG_URL = "https://df.iantem.io/api/v1/config";
  var LUA_PATH = "lantern_tls_resume_smux_v16_2.lua";
  var L = {
    flashlightVersion:"7.6.179", clientVersion:"9999.99.99", userId:"381696446",
    proToken:"K1qttSsZruN", deviceId:"a34113", platform:"android", locale:"", timezone:"Asia/Shanghai"
  };

  function utf8Encode(s) {
    s=String(s); var o=[];
    if (typeof TextEncoder!=="undefined") return Array.prototype.slice.call(new TextEncoder().encode(s));
    for (var i=0;i<s.length;i++) { var c=s.charCodeAt(i); if(c<128)o.push(c); else if(c<2048)o.push(192|(c>>6),128|(c&63)); else o.push(224|(c>>12),128|((c>>6)&63),128|(c&63)); }
    return o;
  }
  function utf8Decode(a) {
    if (typeof TextDecoder!=="undefined") { try{return new TextDecoder("utf-8").decode(new Uint8Array(a));}catch(_){} }
    var s=""; for(var i=0;i<a.length;){var c=a[i++]; if(c<128)s+=String.fromCharCode(c); else if((c&224)===192){var c2=a[i++];s+=String.fromCharCode(((c&31)<<6)|(c2&63));} else {var b=a[i++],d=a[i++];s+=String.fromCharCode(((c&15)<<12)|((b&63)<<6)|(d&63));}} return s;
  }
  function cat(){var o=[];for(var i=0;i<arguments.length;i++){var a=arguments[i]||[];for(var j=0;j<a.length;j++)o.push(a[j]&255);}return o;}
  function vint(n){var o=[];n=Number(n);while(n>127){o.push((n&127)|128);n=Math.floor(n/128);}o.push(n&127);return o;}
  function key(n,w){return vint(n*8+w);} function fbytes(n,b){return cat(key(n,2),vint(b.length),b);} function fstr(n,s){return s?fbytes(n,utf8Encode(s)):[];}
  var ZERO=[0x80,0x92,0xb8,0xc3,0x98,0xfe,0xff,0xff,0xff,0x01];
  function requestBody(){var ci=cat(fstr(1,L.flashlightVersion),fstr(2,L.clientVersion),fstr(3,L.userId),fstr(4,L.proToken));var ts=cat(key(1,0),ZERO);var px=fbytes(2,ts);return cat(fbytes(1,ci),fbytes(2,px));}
  function normalize(data,res){
    if(data instanceof ArrayBuffer)return new Uint8Array(data);
    if(typeof Uint8Array!=="undefined"&&data instanceof Uint8Array)return data;
    if(res&&res.bodyBytes instanceof ArrayBuffer)return new Uint8Array(res.bodyBytes);
    if(res&&res.bodyBytes instanceof Uint8Array)return res.bodyBytes;
    if(res&&res.body instanceof ArrayBuffer)return new Uint8Array(res.body);
    if(res&&res.body instanceof Uint8Array)return res.body;
    if(typeof data==="string"){var a=new Uint8Array(data.length);for(var i=0;i<data.length;i++)a[i]=data.charCodeAt(i)&255;return a;}
    throw new Error("binary protobuf response yok");
  }
  function readVar(b,p){var n=0,m=1,c=0;while(p<b.length){var x=b[p++];n+=(x&127)*m;if((x&128)===0)return {v:n,p:p};m*=128;if(++c>9)throw new Error("varint");}throw new Error("truncated");}
  function fields(bytes){
    var out=[],p=0;
    while(p<bytes.length){var k=readVar(bytes,p);p=k.p;var no=Math.floor(k.v/8),w=k.v&7;if(no<=0||(w!==0&&w!==1&&w!==2&&w!==5))throw new Error("wire");
      if(w===0){var q=readVar(bytes,p);p=q.p;out.push({n:no,w:w,v:q.v});}
      else if(w===1){if(p+8>bytes.length)throw new Error("fixed64");out.push({n:no,w:w,b:bytes.slice(p,p+8)});p+=8;}
      else if(w===5){if(p+4>bytes.length)throw new Error("fixed32");out.push({n:no,w:w,b:bytes.slice(p,p+4)});p+=4;}
      else {var z=readVar(bytes,p);p=z.p;if(z.v<0||p+z.v>bytes.length)throw new Error("len");out.push({n:no,w:w,b:bytes.slice(p,p+z.v)});p+=z.v;}
    }
    return out;
  }
  function one(fs,n,w){for(var i=0;i<fs.length;i++)if(fs[i].n===n&&(w===undefined||fs[i].w===w))return fs[i];return null;}
  function all(fs,n,w){var o=[];for(var i=0;i<fs.length;i++)if(fs[i].n===n&&(w===undefined||fs[i].w===w))o.push(fs[i]);return o;}
  function ascii(b){try{return utf8Decode(b);}catch(_){return "";}}
  function looksHost(s){return !!s&&s.length<256&&/^[A-Za-z0-9._:-]+$/.test(s);}

  function parseTLS(raw){
    try{
      var f=fields(raw),sf=one(f,1,2),frag=one(f,2,2),sniF=one(f,3,2);if(!sf||!sniF)return null;
      var sfs=fields(sf.b),ticket=one(sfs,1,2),ver=one(sfs,2,0),cipher=one(sfs,3,0),master=one(sfs,4,2);
      var sni=ascii(sniF.b); if(!ticket||!ver||!cipher||!master||!looksHost(sni))return null;
      if(Number(ver.v)!==0x0303||Number(cipher.v)!==0xc02b||master.b.length!==48||ticket.b.length===0)return null;
      return {ticket:Array.prototype.slice.call(ticket.b),master:Array.prototype.slice.call(master.b),sni:sni,tlsFrag:frag?ascii(frag.b):""};
    }catch(_){return null;}
  }
  function maybeProxy(fs){
    var addrF=one(fs,1,2),portF=one(fs,5,0),authF=one(fs,11,2); if(!addrF||!portF||!authF)return null;
    var addr=ascii(addrF.b),auth=ascii(authF.b); if(!looksHost(addr)||auth.length!==64)return null;
    var transports=all(fs,20,2); for(var i=0;i<transports.length;i++){var t=parseTLS(transports[i].b);if(t)return {addr:addr,port:Number(portF.v),auth:auth,sni:t.sni,ticket:t.ticket,master:t.master,tlsFrag:t.tlsFrag};}
    return null;
  }
  function scan(root){
    var found=[],seen={};
    function walk(raw,depth){if(depth>7||!raw||raw.length<2)return;var fs;try{fs=fields(raw);}catch(_){return;}
      var p=maybeProxy(fs); if(p){var id=p.addr+":"+p.port+"|"+p.sni+"|"+p.auth;if(!seen[id]){seen[id]=1;found.push(p);}}
      for(var i=0;i<fs.length;i++)if(fs[i].w===2&&fs[i].b&&fs[i].b.length>=2&&fs[i].b.length<=200000)walk(fs[i].b,depth+1);
    }
    walk(root,0);found.sort(function(a,b){return (a.tlsFrag?1:0)-(b.tlsFrag?1:0);});return found;
  }

  var B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64(bytes){var out="";for(var i=0;i<bytes.length;i+=3){var a=bytes[i],b=i+1<bytes.length?bytes[i+1]:0,c=i+2<bytes.length?bytes[i+2]:0,n=(a<<16)|(b<<8)|c;out+=B64[(n>>18)&63]+B64[(n>>12)&63]+(i+1<bytes.length?B64[(n>>6)&63]:"=")+(i+2<bytes.length?B64[n&63]:"=");}return out;}
  function uuid(i){var x=String(9100+i);return "B18E3C6D-27A2-4D2B-94B7-8C1E7A5F"+x;}
  function node(n,i){var now=Date.now()/1000;return {host:n.addr,path:LUA_PATH,type:"Lua",user:n.sni+"|"+b64(n.ticket),plugin:"none",method:"aes-256-cfb",udp:0,allowInsecure:1,port:String(n.port),obfs:"none",proto:"none",password:b64(n.master)+n.auth,title:"Lantern Auto v18.2 "+n.sni,uuid:uuid(i),created:now,updated:now,weight:Math.floor(now)};}
  function respond(obj,name){$done({response:{status:200,headers:{"Content-Type":"application/json; charset=utf-8","Content-Disposition":"attachment; filename=\""+name+"\"","Cache-Control":"no-store"},body:JSON.stringify(obj,null,2)}});}
  function fail(x){$done({response:{status:502,headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store"},body:"Lantern v18.2 ERROR\n"+String(x)}});}
  function rand(n){var c="abcdefghijklmnopqrstuvwxyz",s="";for(var i=0;i<n;i++)s+=c.charAt(Math.floor(Math.random()*c.length));return s;}
  function run(allNodes){
    var rb=requestBody(),opts={url:CONFIG_URL,method:"POST",timeout:20,"binary-mode":true,body:new Uint8Array(rb).buffer,headers:{
      "Content-Type":"application/x-protobuf","Accept":"application/x-protobuf","Cache-Control":"no-cache",
      "X-Lantern-Version":L.flashlightVersion,"X-Lantern-App-Version":L.clientVersion,"X-Lantern-App":"","X-Lantern-Device-Id":L.deviceId,
      "X-Lantern-Platform":L.platform,"X-Lantern-Pro-Token":L.proToken,"X-Lantern-User-Id":L.userId,"X-Lantern-Locale":L.locale,
      "X-Lantern-Time-Zone":L.timezone,"X-Lantern-Supported-Data-Caps":"monthly, weekly, daily","X-Lantern-Rand":rand(64),"X-Surge-Proxy":"DIRECT"}};
    $httpClient.post(opts,function(err,res,data){if(err)return fail(err);var code=Number((res&&(res.statusCode||res.status))||0);if(code!==200)return fail("Lantern API HTTP "+code);try{var ns=scan(normalize(data,res));if(!ns.length)return fail("raw scan TLS node bulamadi");if(allNodes)return respond(ns.map(function(n,i){return node(n,i+1);}),"Lantern-All-v18-2.json");return respond(node(ns[0],1),"Lantern-Auto-v18-2.json");}catch(e){return fail(e&&e.message?e.message:String(e));}});
  }

  var u=(typeof $request!=="undefined"&&$request.url)?$request.url:"";
  if(u.indexOf("http://"+HOST+SINGLE_PATH)===0)return run(false);
  if(u.indexOf("http://"+HOST+ALL_PATH)===0)return run(true);
  return $done({});
})();