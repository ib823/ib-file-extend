(() => {
  const te = new TextEncoder(), td = new TextDecoder();
  const VERSION = 1;
  const APP_ID = `app://ironbox-v1@${location.origin}`;
  const MAX_TOKEN_LEN = 2 * 1024 * 1024;
  const ITER = 350_000;
  const MAILTO_BODY_LIMIT = 60000;
  const TOKEN_WRAP_COL = 120;
  const ENABLE_GZIP_BEFORE_ENCRYPT = true;

  const $ = (id) => document.getElementById(id);
  const stateEl = $("state"), savePassEl = $("savePass"), tokenOutEl = $("tokenOut");
  const loadPassEl = $("loadPass"), tokenInEl = $("tokenIn");
  const statusEl = $("status"), renderEl = $("render");
  const btnSave = $("btnSave"), btnEmail = $("btnEmail"), btnCopy = $("btnCopy");
  const btnLoad = $("btnLoad"), btnQR = $("btnQR"), btnDownloadIB = $("btnDownloadIB");
  const qrOverlay = $("qrOverlay"), qrClose = $("qrClose"), qrCanvas = $("qrCanvas");

  function setStatus(s) { statusEl.textContent = s; }
  const b64u = {
    enc: (buf) => {
      const bin = String.fromCharCode(...new Uint8Array(buf));
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    },
    dec: (s) => {
      if (!/^[A-Za-z0-9._-]+$/.test(s)) throw new Error("Invalid characters in token");
      s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
      const bin = atob(s); const u8 = new Uint8Array(bin.length);
      for (let i=0;i<bin.length;i++) u8[i] = bin.charCodeAt(i);
      return u8.buffer;
    }
  };

  function wrapText(s, col = TOKEN_WRAP_COL) { return s.replace(new RegExp(`(.{1,${col}})`, "g"), "$1\n"); }
  function normalizeTokenInput(s) {
    const n = s.normalize("NFKC").replace(/\s+/g, "");
    if (n.length > MAX_TOKEN_LEN) throw new Error("Token too large");
    return n;
  }

  function downloadFile(filename, text, mime="application/x-ironbox") {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }
  function openMailto({ to="", subject, body }) {
    location.href = `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  function validateState(obj) {
    if (typeof obj !== "object" || obj === null) throw new Error("State must be object");
    if ("title" in obj && typeof obj.title !== "string") throw new Error("title must be string");
    if ("items" in obj) {
      if (!Array.isArray(obj.items) || obj.items.length > 5000) throw new Error("items invalid");
      for (const it of obj.items) {
        if (typeof it !== "object" || it === null) throw new Error("item invalid");
        if (typeof it.txt !== "string" || it.txt.length > 2000) throw new Error("txt invalid");
        if (typeof it.done !== "boolean") throw new Error("done invalid");
      }
    }
    const forbidden = ["__proto__", "constructor", "prototype"];
    const stack = [obj];
    while (stack.length) {
      const cur = stack.pop();
      for (const k of Object.keys(cur)) {
        if (forbidden.includes(k)) throw new Error(`Forbidden key: ${k}`);
        if (typeof cur[k] === "object" && cur[k] !== null) stack.push(cur[k]);
      }
    }
  }

  async function deriveKeyPBKDF2(passphrase, salt, iter=ITER) {
    const km = await crypto.subtle.importKey("raw", te.encode(passphrase), { name: "PBKDF2" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
      km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }
  function concatBuf(a, b) {
    const ua = new Uint8Array(a), ub = new Uint8Array(b);
    const out = new Uint8Array(ua.length + ub.length);
    out.set(ua, 0); out.set(ub, ua.length);
    return out.buffer;
  }

  async function maybeGzipUtf8(utf8Bytes) {
    if (!ENABLE_GZIP_BEFORE_ENCRYPT) return utf8Bytes;
    if (typeof CompressionStream !== "function") return utf8Bytes;
    try {
      const cs = new CompressionStream("gzip");
      const stream = new Blob([utf8Bytes]).stream().pipeThrough(cs);
      const gz = await new Response(stream).arrayBuffer();
      return new Uint8Array(gz);
    } catch { return utf8Bytes; }
  }

  async function encryptState(stateJson, passphrase) {
    let obj; try { obj = JSON.parse(stateJson); } catch { throw new Error("State JSON invalid"); }
    validateState(obj);

    const utf8 = new TextEncoder().encode(JSON.stringify(obj));
    const toEncrypt = await maybeGzipUtf8(utf8);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyPBKDF2(passphrase, salt);
    const header = {
      v: VERSION,
      kdf: "pbkdf2-sha256",
      iter: ITER,
      salt_b64u: b64u.enc(salt.buffer),
      aad: APP_ID,
      created: Math.floor(Date.now()/1000),
      enc: "AES-256-GCM",
      pre: (toEncrypt !== utf8) ? "gzip" : "none"
    };
    const aadBytes = new TextEncoder().encode(JSON.stringify(header));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadBytes }, key, toEncrypt);
    const token = ["ARC1", b64u.enc(aadBytes), b64u.enc(concatBuf(iv.buffer, ct))].join(".");
    if (token.length > MAX_TOKEN_LEN) throw new Error("Token too large (try smaller document)");
    return token;
  }

  async function decryptToken(token, passphrase) {
    const parts = normalizeTokenInput(token).split(".");
    if (parts.length !== 3 || parts[0] !== "ARC1") throw new Error("Bad token format");
    const header = JSON.parse(td.decode(b64u.dec(parts[1])));
    if (header.v !== VERSION) throw new Error("Unsupported token version");
    if (header.kdf !== "pbkdf2-sha256") throw new Error("Unsupported KDF");
    if (header.aad !== APP_ID) throw new Error("Wrong app");
    const all = new Uint8Array(b64u.dec(parts[2]));
    if (all.byteLength < 12 + 16) throw new Error("Cipher too short");
    const iv = all.slice(0, 12), ct = all.slice(12);
    const key = await deriveKeyPBKDF2(passphrase, new Uint8Array(b64u.dec(header.salt_b64u)), header.iter);
    const aadBytes = new TextEncoder().encode(JSON.stringify(header));
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aadBytes }, key, ct);
    } catch { throw new Error("Decrypt failed (wrong passphrase or corrupted token)"); }
    let bytes = new Uint8Array(plain);
    if (header.pre === "gzip") {
      if (typeof DecompressionStream !== "function") throw new Error("Token is gzip-compressed but browser lacks DecompressionStream");
      const ds = new DecompressionStream("gzip");
      const stream = new Blob([bytes]).stream().pipeThrough(ds);
      const ungz = await new Response(stream).arrayBuffer();
      bytes = new Uint8Array(ungz);
    }
    const obj = JSON.parse(new TextDecoder().decode(bytes));
    validateState(obj);
    return obj;
  }

  // Email flow with size fallback to .ib file
  btnSave.onclick = async () => {
    try {
      const pass = savePassEl.value;
      if (!pass || pass.length < 12) throw new Error("Use a passphrase ≥ 12 characters");
      const token = await encryptState(stateEl.value, pass);
      tokenOutEl.value = wrapText(token);
      btnEmail.disabled = false; btnCopy.disabled = false; btnQR.disabled = false; btnDownloadIB.disabled = false;
      setStatus("token generated");
    } catch (e) { setStatus("save error: " + e.message); }
  };

  btnCopy.onclick = async () => {
    if (!tokenOutEl.value) return;
    await navigator.clipboard.writeText(tokenOutEl.value);
    setStatus("token copied to clipboard");
  };

  btnEmail.onclick = () => {
    const token = tokenOutEl.value.replace(/\s+/g, "");
    if (!token) return;
    const subject = "IronBox (.ib) Token";
    const inlineBody = [
      "Here is your encrypted IronBox token (keep the passphrase safe):",
      "",
      wrapText(token),
      "",
      "How to open:",
      "1) Open the app",
      "2) Paste token into Resume",
      "3) Enter the shared passphrase"
    ].join("\n");
    if (inlineBody.length <= MAILTO_BODY_LIMIT) {
      openMailto({ subject, body: inlineBody });
      setStatus("opening email client with inline token");
      return;
    }
    // fallback: create .ib file locally and instruct to attach
    downloadFile("state.ib", token + "\n");
    const shortBody = [
      "Token is large, attached as file: state.ib",
      "",
      "How to open:",
      "1) Open the app",
      "2) Open state.ib and copy its contents into the Resume box",
      "3) Enter the shared passphrase"
    ].join("\n");
    openMailto({ subject: "IronBox (.ib) Token (see attached file)", body: shortBody });
    setStatus("token too large; downloaded state.ib and opened email draft");
  };

  btnDownloadIB.onclick = () => {
    const token = tokenOutEl.value.replace(/\s+/g, "");
    if (!token) return;
    downloadFile("state.ib", token + "\n");
    setStatus("downloaded state.ib");
  };

  btnLoad.onclick = async () => {
    try {
      const pass = loadPassEl.value;
      const token = tokenInEl.value;
      const obj = await decryptToken(token, pass);
      renderEl.textContent = JSON.stringify(obj, null, 2);
      stateEl.value = JSON.stringify(obj, null, 2);
      setStatus("state loaded");
    } catch (e) { setStatus("load error: " + e.message); }
  };

  // ---------- QR code (compact encoder; ECC-M, versions 1..20) ----------
  const QRUtil = (() => {
    const EXP = new Array(256), LOG = new Array(256);
    for (let i=0;i<8;i++) EXP[i]=1<<i;
    for (let i=8;i<256;i++) EXP[i]=EXP[i-4]^EXP[i-5]^EXP[i-6]^EXP[i-8];
    for (let i=0;i<255;i++) LOG[EXP[i]]=i;
    const gexp=n=>(n<0?gexp(n+255):n>=256?gexp(n-255):EXP[n]);
    const glog=n=>{ if(n<1) throw Error("glog"); return LOG[n]; };
    function Poly(nums,shift){let o=0;while(o<nums.length&&nums[o]===0)o++;this.num=new Array(nums.length-o+(shift||0));for(let i=0;i<nums.length-o;i++)this.num[i]=nums[i+o];}
    Poly.prototype.get=function(i){return this.num[i];};
    Poly.prototype.getLength=function(){return this.num.length;};
    Poly.prototype.multiply=function(e){const n=new Array(this.getLength()+e.getLength()-1).fill(0);for(let i=0;i<this.getLength();i++)for(let j=0;j<e.getLength();j++)n[i+j]^=gexp(glog(this.get(i))+glog(e.get(j)));return new Poly(n,0);};
    Poly.prototype.mod=function(e){ if(this.getLength()-e.getLength()<0) return this; const r=glog(this.get(0))-glog(e.get(0)); const n=this.num.slice(); for(let i=0;i<e.getLength();i++) n[i]^=gexp(glog(e.get(i))+r); return new Poly(n,0).mod(e); };
    const RS_M = {
      1:[[1,16]],2:[[1,28]],3:[[1,44]],4:[[2,32]],5:[[2,43]],6:[[4,27]],7:[[4,31]],8:[[2,38],[2,39]],
      9:[[3,36],[2,37]],10:[[4,43],[1,44]],11:[[1,58],[3,59]],12:[[6,42],[2,43]],13:[[8,33],[1,34]],
      14:[[4,42],[5,43]],15:[[5,36],[5,37]],16:[[7,36],[3,37]],17:[[10,46],[1,47]],18:[[9,43],[4,44]],
      19:[[3,44],[11,45]],20:[[3,41],[13,42]]
    };
    const TOTAL = [0,26,44,70,100,134,172,196,242,292,346,404,466,532,581,655,733,815,901,991,1085];
    function rsBlocks(ver){const spec=RS_M[ver]; if(!spec)return null; const out=[]; for(const [n,k] of spec) for(let i=0;i<n;i++) out.push({dataCount:k}); return out;}
    function BitBuf(){this.buf=[];this.len=0;}
    BitBuf.prototype.put=function(num,len){for(let i=0;i<len;i++)this.putBit(((num>>>(len-i-1))&1)===1);};
    BitBuf.prototype.putBit=function(bit){const idx=Math.floor(this.len/8); if(this.buf.length<=idx)this.buf.push(0); if(bit)this.buf[idx]|=0x80>>>(this.len%8); this.len++;};
    const PAD0=0xEC,PAD1=0x11;
    function createData(ver,data){
      const bb=new BitBuf(); const mode=0x4; bb.put(mode,4);
      const lenBits=ver<10?8:16; bb.put(data.length,lenBits);
      for(let i=0;i<data.length;i++) bb.put(data[i],8);
      const blocks=rsBlocks(ver); const total=blocks.reduce((a,b)=>a+b.dataCount,0);
      if (bb.len + 4 <= total*8) bb.put(0,4);
      while (bb.len % 8 !== 0) bb.putBit(false);
      while (bb.buf.length < total) bb.buf.push(bb.buf.length % 2 ? PAD1 : PAD0);
      return bb.buf;
    }
    function createBytes(ver,dataBytes){
      const blocks=rsBlocks(ver); if(!blocks) throw Error("no ver");
      const totalCodewords=TOTAL[ver];
      const totalData=blocks.reduce((a,b)=>a+b.dataCount,0);
      const ecTotal=totalCodewords-totalData;
      const cache={};
      const poly=(ec)=>{ if(cache[ec]) return cache[ec]; let p=new Poly([1],0); for(let i=0;i<ec;i++) p=p.multiply(new Poly([1,gexp(i)],0)); cache[ec]=p; return p; };
      const out=[]; let off=0; const ecEach=ecTotal/blocks.length;
      const blks=[];
      for(const b of blocks){
        const dc=b.dataCount; const d=dataBytes.slice(off,off+dc); off+=dc;
        const mod=new Poly(d,0).mod(poly(ecEach));
        const eccLen=ecEach, ecc=new Array(eccLen).fill(0);
        const diff=eccLen - mod.getLength();
        for(let i=0;i<eccLen;i++) ecc[i]=(i<diff)?0:mod.get(i-diff);
        blks.push({data:d,ecc});
      }
      const dcMax=Math.max(...blks.map(b=>b.data.length));
      const ecMax=Math.max(...blks.map(b=>b.ecc.length));
      for(let i=0;i<dcMax;i++) for(const b of blks) if(i<b.data.length) out.push(b.data[i]);
      for(let i=0;i<ecMax;i++) for(const b of blks) if(i<b.ecc.length) out.push(b.ecc[i]);
      return out;
    }
    function Matrix(ver){
      this.size=ver*4+17; this.m=Array.from({length:this.size},()=>Array(this.size).fill(null));
    }
    Matrix.prototype.isEmpty=function(r,c){return this.m[r][c]===null;};
    Matrix.prototype.set=function(r,c,v){this.m[r][c]=v;};
    function finder(m,r,c){
      const p=[[1,1,1,1,1,1,1],[1,0,0,0,0,0,1],[1,0,1,1,1,0,1],[1,0,1,1,1,0,1],[1,0,1,1,1,0,1],[1,0,0,0,0,0,1],[1,1,1,1,1,1,1]];
      for(let i=0;i<7;i++) for(let j=0;j<7;j++) m.set(r+i,c+j,p[i][j]);
    }
    function timing(m){
      for(let i=8;i<m.size-8;i++){
        const v = i%2===0?1:0;
        if(m.isEmpty(6,i)) m.set(6,i,v);
        if(m.isEmpty(i,6)) m.set(i,6,v);
      }
    }
    function alignPos(ver){
      if(ver===1) return [];
      const cnt=Math.floor(ver/7)+2, size=ver*4+17;
      const step=Math.ceil((size-13)/(cnt*2-2))*2;
      const res=[6]; for(let p=0;p<cnt-1;p++) res.push(size-7-p*step);
      return res;
    }
    function alignment(m,ver){
      const pos=alignPos(ver);
      for(let i=0;i<pos.length;i++) for(let j=0;j<pos.length;j++){
        const r=pos[i], c=pos[j]; if(m.m[r][c]!==null) continue;
        for(let y=-2;y<=2;y++) for(let x=-2;x<=2;x++){
          m.set(r+y,c+x, Math.max(Math.abs(x),Math.abs(y))!==1?1:0);
        }
      }
    }
    function reserveFormat(m){
      for(let i=0;i<9;i++){ if(i!==6) m.set(i,8,0); if(i!==6) m.set(8,i,0); }
      for(let i=0;i<8;i++){ m.set(m.size-1-i,8,0); m.set(8,m.size-1-i,0); }
      m.set(8,8,0);
    }
    function build(ver, data){
      const m=new Matrix(ver);
      finder(m,0,0); finder(m,0,m.size-7); finder(m,m.size-7,0);
      for(let i=0;i<8;i++){
        if(m.isEmpty(i,7)) m.set(i,7,0);
        if(m.isEmpty(7,i)) m.set(7,i,0);
        if(m.isEmpty(m.size-8+i,7)) m.set(m.size-8+i,7,0);
        if(m.isEmpty(7,m.size-8+i)) m.set(7,m.size-8+i,0);
        if(m.isEmpty(i,m.size-8)) m.set(i,m.size-8,0);
        if(m.isEmpty(m.size-8,i)) m.set(m.size-8,i,0);
      }
      timing(m); alignment(m,ver); reserveFormat(m);
      let dirUp=true, row=m.size-1, col=m.size-1, bitIndex=0;
      const totalBits=data.length*8;
      const getBit=(i)=>((data[Math.floor(i/8)]>>>(7-(i%8)))&1)===1;
      while(col>0){
        if(col===6) col--;
        for(let i=0;i<m.size;i++){
          const r=dirUp?(row - i):i;
          for(let cOff=0;cOff<2;cOff++){
            const c=col-cOff;
            if(m.isEmpty(r,c) && bitIndex<totalBits) m.set(r,c, getBit(bitIndex++)?1:0);
          }
        }
        col-=2; dirUp=!dirUp; row=dirUp?m.size-1:0;
      }
      // mask 0
      for(let r=0;r<m.size;r++) for(let c=0;c<m.size;c++){
        if(m.m[r][c]===0||m.m[r][c]===1){ if((r+c)%2===0) m.m[r][c]^=1; }
      }
      // format for ECC=M, mask=0 (precomputed)
      const FORMAT = 0b111011111000100;
      for (let i = 0; i < 15; i++) {
        const v = ((FORMAT >>> i) & 1);
        if (i < 6) m.set(i, 8, v);
        else if (i < 8) m.set(i + 1, 8, v);
        else m.set(m.size - 15 + i, 8, v);
        if (i < 8) m.set(8, m.size - 1 - i, v);
        else if (i < 9) m.set(8, 15 - i, v);
        else m.set(8, 14 - i, v);
      }
      return m;
    }
    function encode(text){
      const data=new TextEncoder().encode(text);
      for(let ver=1; ver<=20; ver++){
        const blocks=rsBlocks(ver);
        if(!blocks) continue;
        const total=blocks.reduce((a,b)=>a+b.dataCount,0);
        try{
          const dataBytes=createData(ver,data);
          if(dataBytes.length>total) continue;
          const finalBytes=createBytes(ver,dataBytes);
          return build(ver, finalBytes);
        }catch{ continue; }
      }
      throw new Error("Token too large for QR (ECC-M, v≤20). Use Email or .ib file.");
    }
    return { encode };
  })();

  async function showTokenQR(token) {
    const mat = QRUtil.encode(token);
    const size = mat.size;
    const scale = Math.floor(qrCanvas.width / (size + 8));
    const margin = 4;
    const ctx = qrCanvas.getContext("2d");
    ctx.fillStyle = "#fff"; ctx.fillRect(0,0,qrCanvas.width,qrCanvas.height);
    ctx.fillStyle = "#000";
    for(let r=0;r<size;r++) for(let c=0;c<size;c++){
      if (mat.m[r][c]) ctx.fillRect((c+margin)*scale,(r+margin)*scale,scale,scale);
    }
  }
  btnQR.onclick = async () => {
    try {
      const token = tokenOutEl.value.replace(/\s+/g, "");
      if (!token) return;
      await showTokenQR(token);
      qrOverlay.hidden = false;
      setStatus("QR generated");
    } catch (e) { setStatus("qr error: " + e.message + " (use Email or .ib file)"); }
  };
  qrClose.onclick = () => (qrOverlay.hidden = true);
  qrOverlay.addEventListener("click", (e) => { if (e.target === qrOverlay) qrOverlay.hidden = true; });
})();
