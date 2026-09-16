/* Lantern v16 safe legacy TLS-session probe for Shadowrocket.
 * Requests Flashlight 7.6.150 and reports ONLY non-secret metadata.
 * No auth token, ticket, master-secret, certificate, or serialized session bytes are printed or persisted.
 */
(function () {
  "use strict";

  var FEED_HOST = "connect.rom.miui.com";
  var CONFIG_URL = "https://df.iantem.io/api/v1/config";
  var VERSION = "7.6.150";
  var CLIENT_VERSION = "9999.99.99";
  var USER_ID = "381696446";
  var PRO_TOKEN = "K1qttSsZruN";
  var DEVICE_ID = "a34113";

  function utf8(s) {
    s = String(s || "");
    if (typeof TextEncoder !== "undefined") return Array.prototype.slice.call(new TextEncoder().encode(s));
    var o=[];
    for(var i=0;i<s.length;i++){
      var c=s.charCodeAt(i);
      if(c<128)o.push(c);
      else if(c<2048)o.push(192|(c>>6),128|(c&63));
      else o.push(224|(c>>12),128|((c>>6)&63),128|(c&63));
    }
    return o;
  }

  function utf8dec(a) {
    if (typeof TextDecoder !== "undefined") {
      try { return new TextDecoder("utf-8").decode(new Uint8Array(a)); } catch (_) {}
    }
    var s="";
    for(var i=0;i<a.length;){
      var c=a[i++];
      if(c<128)s+=String.fromCharCode(c);
      else if((c&224)===192){var c2=a[i++];s+=String.fromCharCode(((c&31)<<6)|(c2&63));}
      else {var c2e=a[i++],c3=a[i++];s+=String.fromCharCode(((c&15)<<12)|((c2e&63)<<6)|(c3&63));}
    }
    return s;
  }

  function cat(){var o=[];for(var i=0;i<arguments.length;i++){var a=arguments[i];for(var j=0;j<a.length;j++)o.push(a[j]&255);}return o;}
  function vi(n){var o=[];n=Number(n);while(n>127){o.push((n&127)|128);n=Math.floor(n/128);}o.push(n&127);return o;}
  function key(n,w){return vi(n*8+w);}
  function fb(n,b){return cat(key(n,2),vi(b.length),b);}
  function fs(n,s){return s ? fb(n,utf8(s)) : [];}
  function fm(n,b){return fb(n,b);}

  var ZERO_GO_TIME=[0x80,0x92,0xb8,0xc3,0x98,0xfe,0xff,0xff,0xff,0x01];
  function requestBytes(){
    var ci=cat(fs(1,VERSION),fs(2,CLIENT_VERSION),fs(3,USER_ID),fs(4,PRO_TOKEN));
    var ts=cat(key(1,0),ZERO_GO_TIME);
    var pr=fm(2,ts);
    return cat(fm(1,ci),fm(2,pr));
  }

  function ab(bytes){return new Uint8Array(bytes).buffer;}
  function binary(data,response){
    if(data instanceof ArrayBuffer)return new Uint8Array(data);
    if(typeof Uint8Array!=="undefined"&&data instanceof Uint8Array)return data;
    if(response&&response.bodyBytes instanceof ArrayBuffer)return new Uint8Array(response.bodyBytes);
    if(response&&response.bodyBytes instanceof Uint8Array)return response.bodyBytes;
    if(response&&response.body instanceof ArrayBuffer)return new Uint8Array(response.body);
    if(response&&response.body instanceof Uint8Array)return response.body;
    if(typeof data==="string"){var a=new Uint8Array(data.length);for(var i=0;i<data.length;i++)a[i]=data.charCodeAt(i)&255;return a;}
    throw new Error("binary response unavailable");
  }

  function R(b){this.b=b instanceof Uint8Array?b:new Uint8Array(b);this.p=0;}
  R.prototype.eof=function(){return this.p>=this.b.length;};
  R.prototype.v=function(){var n=0,m=1,c=0;while(this.p<this.b.length){var x=this.b[this.p++];n+=(x&127)*m;if(!(x&128))return n;m*=128;if(++c>9)throw new Error("varint");}throw new Error("truncated");};
  R.prototype.bytes=function(){var n=this.v();if(this.p+n>this.b.length)throw new Error("length");var x=this.b.slice(this.p,this.p+n);this.p+=n;return x;};
  R.prototype.skip=function(w){if(w===0){this.v();return;}if(w===1){this.p+=8;return;}if(w===2){this.p+=this.v();return;}if(w===5){this.p+=4;return;}throw new Error("wire "+w);};
  function fields(b,fn){var r=new R(b);while(!r.eof()){var k=r.v(),n=Math.floor(k/8),w=k&7;if(!fn(r,n,w))r.skip(w);if(r.p>r.b.length)throw new Error("overrun");}}
  function str(r,w){if(w!==2)throw new Error("string");return utf8dec(r.bytes());}

  function session(b){
    var o={ticketLen:0,version:0,cipherSuite:0,masterSecretLen:0,serializedStateLen:0};
    fields(b,function(r,n,w){
      if(n===1&&w===2){o.ticketLen=r.bytes().length;return true;}
      if(n===2&&w===0){o.version=r.v();return true;}
      if(n===3&&w===0){o.cipherSuite=r.v();return true;}
      if(n===4&&w===2){o.masterSecretLen=r.bytes().length;return true;}
      if(n===5&&w===2){o.serializedStateLen=r.bytes().length;return true;}
      return false;
    });
    return o;
  }

  function tls(b){
    var o={type:"tls",sni:"",tlsFrag:"",session:null};
    fields(b,function(r,n,w){
      if(n===1&&w===2){o.session=session(r.bytes());return true;}
      if(n===2){o.tlsFrag=str(r,w);return true;}
      if(n===3){o.sni=str(r,w);return true;}
      return false;
    });
    return o;
  }

  function proxy(b){
    var p={addr:"",port:0,name:"",hasAuthToken:false,transport:null};
    fields(b,function(r,n,w){
      if(n===1){p.addr=str(r,w);return true;}
      if(n===4){p.name=str(r,w);return true;}
      if(n===5&&w===0){p.port=r.v();return true;}
      if(n===10&&w===2){r.bytes();return true;}
      if(n===11){str(r,w);p.hasAuthToken=true;return true;}
      if(n===20&&w===2){p.transport=tls(r.bytes());return true;}
      return false;
    });
    return p;
  }

  function parse(raw){
    var out={country:"",proxies:[]};
    fields(raw,function(r,n,w){
      if(n===2){out.country=str(r,w);return true;}
      if(n===4&&w===2){
        var container=r.bytes();
        fields(container,function(rr,nn,ww){if(nn===1&&ww===2){out.proxies.push(proxy(rr.bytes()));return true;}return false;});
        return true;
      }
      return false;
    });
    return out;
  }

  function hx(n){var h=Number(n||0).toString(16);while(h.length<4)h="0"+h;return "0x"+h;}
  function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
  function html(title,text,ok){var c=ok?"#22c55e":"#ef4444";return "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><style>body{font-family:-apple-system;background:#111;color:#eee;padding:20px}.b{max-width:850px;margin:auto;background:#1c1c1e;padding:18px;border-radius:16px}h1{color:"+c+"}pre{white-space:pre-wrap;word-break:break-word;background:#000;padding:14px;border-radius:12px}</style></head><body><div class=\"b\"><h1>"+esc(title)+"</h1><pre>"+esc(text)+"</pre></div></body></html>";}
  function done(status,title,text,ok){$done({response:{status:status,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"},body:html(title,text,ok)}});}

  function run(){
    var rb=requestBytes();
    var opt={url:CONFIG_URL,method:"POST",timeout:20,headers:{
      "Content-Type":"application/x-protobuf","Accept":"application/x-protobuf","Cache-Control":"no-cache",
      "X-Lantern-Version":VERSION,"X-Lantern-App-Version":CLIENT_VERSION,"X-Lantern-App":"",
      "X-Lantern-Device-Id":DEVICE_ID,"X-Lantern-Platform":"android","X-Lantern-Pro-Token":PRO_TOKEN,
      "X-Lantern-User-Id":USER_ID,"X-Lantern-Locale":"","X-Lantern-Time-Zone":"Asia/Shanghai",
      "X-Lantern-Supported-Data-Caps":"monthly, weekly, daily","X-Surge-Proxy":"DIRECT"
    },"binary-mode":true,body:ab(rb)};

    $httpClient.post(opt,function(error,response,data){
      if(error)return done(502,"Lantern v16 Probe Error",String(error),false);
      var code=Number(response&&(response.statusCode||response.status)||0);
      if(code!==200)return done(502,"Lantern v16 Probe Error","HTTP "+code,false);
      try{
        var cfg=parse(binary(data,response));
        var rows=[];
        cfg.proxies.forEach(function(p){
          if(!p.transport||p.transport.type!=="tls")return;
          var s=p.transport.session||{};
          rows.push({
            name:p.name,addr:p.addr,port:p.port,sni:p.transport.sni,tlsFrag:p.transport.tlsFrag,
            tlsVersion:s.version?hx(s.version):"",cipherSuite:s.cipherSuite?hx(s.cipherSuite):"",
            sessionTicketLen:s.ticketLen||0,masterSecretLen:s.masterSecretLen||0,
            serializedStateLen:s.serializedStateLen||0,hasAuthToken:!!p.hasAuthToken,
            legacyUsable:!!((s.ticketLen||0)>0&&(s.masterSecretLen||0)>0&&s.version&&s.cipherSuite)
          });
        });
        var usable=rows.filter(function(x){return x.legacyUsable;}).length;
        var out={note:"SAFE SUMMARY ONLY. No auth token, ticket, master-secret, certificate or serialized session bytes are included.",requestedFlashlightVersion:VERSION,country:cfg.country,tlsCount:rows.length,legacyUsableCount:usable,tls:rows};
        return done(200,"Lantern v16 Legacy Session Probe",JSON.stringify(out,null,2),usable>0);
      }catch(e){return done(502,"Lantern v16 Probe Error","decode: "+(e&&e.message?e.message:String(e)),false);}
    });
  }

  var url=(typeof $request!=="undefined"&&$request.url)?$request.url:"";
  if(url.indexOf("https://"+FEED_HOST+"/lantern-v16-check")===0)return run();
  return $done({});
})();
