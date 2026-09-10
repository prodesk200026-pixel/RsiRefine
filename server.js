import express from "express";
import cors from "cors";
import WebSocket, { WebSocketServer } from "ws";
import { authenticator } from "otplib";

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({limit:"2mb"}));
app.use((_req,res,next)=>{res.set("Cache-Control","no-store");next()});

const PORT=Number(process.env.PORT||10000);
const CLIENT_ID=(process.env.DHAN_CLIENT_ID||"").trim();
const PIN=(process.env.DHAN_PIN||"").trim();
const TOTP_SECRET=(process.env.DHAN_TOTP_SECRET||"").replace(/\s+/g,"").toUpperCase();
const STATIC_TOKEN=(process.env.DHAN_ACCESS_TOKEN||"").trim();
const DEFAULT_INDEX=(process.env.DEFAULT_INDEX||"NIFTY").toUpperCase();

const INDEXES={
  NIFTY:{securityId:"13",segment:"IDX_I",optionSegment:"NSE_FNO"},
  BANKNIFTY:{securityId:"25",segment:"IDX_I",optionSegment:"NSE_FNO"},
  FINNIFTY:{securityId:"27",segment:"IDX_I",optionSegment:"NSE_FNO"},
  MIDCPNIFTY:{securityId:"442",segment:"IDX_I",optionSegment:"NSE_FNO"},
  SENSEX:{securityId:"51",segment:"IDX_I",optionSegment:"BSE_FNO"}
};
const SEGMENT_CODE={IDX_I:0,NSE_EQ:1,NSE_FNO:2,NSE_CURRENCY:3,BSE_EQ:4,MCX_COMM:5,BSE_CURRENCY:7,BSE_FNO:8};

const state={
  version:"Bharati-Universal-Dhan-2.0-L20",
  indexKey:INDEXES[DEFAULT_INDEX]?DEFAULT_INDEX:"NIFTY",
  expiry:null, expiries:[], spot:null,
  dhanConnected:false, depthConnected:false, marketStatus:"UNKNOWN",
  lastTick:null,
  ticks:[], chain:{rows:[],updatedAt:null,spot:null}, analytics:{},
  depth:{}, historyCache:{}, subscriptions:[],
  server:{ticks:0,packets:0,depthPackets:0,reconnects:0},
  capabilities:{
    rest:["/api/health","/api/status","/api/feed-status","/api/config","/api/state","/api/ticks","/api/option-chain","/api/analytics","/api/depth","/api/history","/api/instruments"],
    websocket:"/ws", l20:true, depthLevels:20, bidAsk:true
  }
};

let tokenCache = { token: null, expiresAt: 0 };
let tokenGenerationPromise = null;
let tokenRetryAfter = 0;
let authState = {
  mode: STATIC_TOKEN ? "STATIC_TOKEN" : "TOTP",
  status: STATIC_TOKEN ? "READY" : "WAITING",
  lastSuccessAt: null,
  lastError: null,
  retryAfter: null
};

// Runtime objects. Keep these in one place so a failed instrument refresh or
// socket reconnect can never crash the HTTP server.
const instrumentMap = new Map();
let instrumentsLoadedAt = 0;
const clients = new Set();
let liveWS = null;
let depthWS = null;
let liveReconnectTimer = null;
let depthReconnectTimer = null;
let liveWatchdogTimer = null;
let depthWatchdogTimer = null;
const feedDiagnostics = {
  live: { status: "DISCONNECTED", lastOpenAt: null, lastMessageAt: null, lastError: null, closeCode: null, closeReason: null, reconnects: 0, packets: 0 },
  depth: { status: "DISCONNECTED", lastOpenAt: null, lastMessageAt: null, lastError: null, closeCode: null, closeReason: null, reconnects: 0, packets: 0 }
};

function key(segment, securityId){ return `${String(segment)}:${String(securityId)}`; }
function safeNum(v){ const n=Number(v); return Number.isFinite(n) ? n : null; }
function markFeed(kind, patch){ Object.assign(feedDiagnostics[kind], patch); }
function feedSnapshot(){ return JSON.parse(JSON.stringify(feedDiagnostics)); }

function now(){return new Date().toISOString();}

function authErrorMessage(j, text = "") {
  return String(j?.errorMessage || j?.message || j?.remarks || j?.error || text || "Dhan authentication failed");
}

async function generateDhanTokenOnce() {
  if (STATIC_TOKEN) {
    authState = { ...authState, mode: "STATIC_TOKEN", status: "READY", lastError: null, retryAfter: null };
    return STATIC_TOKEN;
  }
  if (!CLIENT_ID || !PIN || !TOTP_SECRET) {
    authState = { ...authState, status: "CONFIG_ERROR", lastError: "Set DHAN_CLIENT_ID, DHAN_PIN and DHAN_TOTP_SECRET" };
    throw new Error(authState.lastError);
  }

  const current = Date.now();
  if (current < tokenRetryAfter) {
    const wait = Math.ceil((tokenRetryAfter - current) / 1000);
    authState = { ...authState, status: "RATE_LIMIT_COOLDOWN", retryAfter: new Date(tokenRetryAfter).toISOString() };
    throw new Error(`Dhan token generation cooldown active; retry in ${wait}s`);
  }

  if (tokenGenerationPromise) return tokenGenerationPromise;

  tokenGenerationPromise = (async () => {
    authState = { ...authState, status: "GENERATING", lastError: null, retryAfter: null };

    const totp = authenticator.generate(TOTP_SECRET);
    const u = `https://auth.dhan.co/app/generateAccessToken?dhanClientId=${encodeURIComponent(CLIENT_ID)}&pin=${encodeURIComponent(PIN)}&totp=${encodeURIComponent(totp)}`;

    const r = await fetch(u, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      }
    });

    const text = await r.text();
    let j = {};
    try { j = JSON.parse(text); } catch {}

    const token = j.accessToken || j.access_token || j.token || j.accesstoken;
    if (!r.ok || !token) {
      const msg = authErrorMessage(j, text.slice(0, 300));

      // Dhan explicitly rate-limits token generation to once every 2 minutes.
      // Never hammer the auth endpoint with parallel/repeating retries.
      if (/once every 2 minutes|2 minutes|too frequently|rate limit/i.test(msg) || r.status === 429) {
        tokenRetryAfter = Date.now() + 120_000;
      }

      authState = {
        ...authState,
        status: `FAILED_${r.status}`,
        lastError: msg,
        retryAfter: tokenRetryAfter ? new Date(tokenRetryAfter).toISOString() : null
      };
      throw new Error(`Dhan auth failed ${r.status}: ${msg}`);
    }

    const expiry = j.expiryTime ? new Date(j.expiryTime).getTime() : Date.now() + 23 * 3600_000;
    tokenCache = {
      token: String(token),
      // Refresh 5 minutes before actual expiry, but never sooner than 2 minutes.
      expiresAt: Math.max(Date.now() + 120_000, expiry)
    };
    tokenRetryAfter = 0;
    authState = {
      ...authState,
      status: "AUTHENTICATED",
      lastSuccessAt: new Date().toISOString(),
      lastError: null,
      retryAfter: null
    };
    return tokenCache.token;
  })();

  try {
    return await tokenGenerationPromise;
  } finally {
    tokenGenerationPromise = null;
  }
}

async function getToken() {
  if (STATIC_TOKEN) return generateDhanTokenOnce();

  const current = Date.now();
  if (tokenCache.token && current < tokenCache.expiresAt - 5 * 60_000) {
    return tokenCache.token;
  }

  return generateDhanTokenOnce();
}

async function dhanPost(path,body){
  const token=await getToken();
  if(!token)throw new Error("Dhan credentials are not configured");
  const r=await fetch(`https://api.dhan.co/v2${path}`,{
    method:"POST",
    headers:{"Content-Type":"application/json","Accept":"application/json","access-token":token,"client-id":CLIENT_ID},
    body:JSON.stringify(body)
  });
  const j=await r.json();
  if(!r.ok||j.status==="failure")throw new Error(j.remarks||j.errorMessage||`Dhan ${r.status}`);
  return j;
}
async function dhanGet(path){
  const token=await getToken();
  if(!token)throw new Error("Dhan credentials are not configured");
  const r=await fetch(`https://api.dhan.co/v2${path}`,{headers:{Accept:"application/json","access-token":token,"client-id":CLIENT_ID}});
  const j=await r.json();
  if(!r.ok)throw new Error(j.errorMessage||`Dhan ${r.status}`);
  return j;
}

function parseCsvLine(line) {
  const out = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') { cur += '"'; i++; }
      else quoted = !quoted;
    } else if (ch === "," && !quoted) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

async function loadInstruments() {
  if (instrumentMap.size && Date.now() - instrumentsLoadedAt < 12 * 3600 * 1000) return;

  const r = await fetch("https://images.dhan.co/api-data/api-scrip-master.csv");
  if (!r.ok) throw new Error(`Instrument master HTTP ${r.status}`);

  const txt = await r.text();
  const lines = txt.split(/\r?\n/).filter(Boolean);
  if (!lines.length) throw new Error("Instrument master is empty");

  const header = parseCsvLine(lines[0]).map(x => x.trim());
  const ix = {};
  header.forEach((h, i) => { ix[h] = i; });

  const idIndex = ix.SEM_SMST_SECURITY_ID ?? ix.SEM_SECURITY_ID ?? ix.SECURITY_ID;
  const exchIndex = ix.SEM_EXM_EXCH_ID ?? ix.EXCH_ID;
  const segIndex = ix.SEM_SEGMENT ?? ix.SEGMENT;
  const segmentMap = {
    "NSE:I": "IDX_I",
    "NSE:D": "NSE_FNO",
    "NSE:E": "NSE_EQ",
    "BSE:I": "BSE_IDX",
    "BSE:D": "BSE_FNO",
    "BSE:E": "BSE_EQ",
    "MCX:M": "MCX_COMM"
  };

  instrumentMap.clear();

  for (let i = 1; i < lines.length; i++) {
    const a = parseCsvLine(lines[i]);
    if (idIndex == null || exchIndex == null || segIndex == null) continue;

    const id = a[idIndex];
    const ex = a[exchIndex];
    const sg = a[segIndex];
    const exchangeSegment = segmentMap[`${ex}:${sg}`];
    if (!id || !exchangeSegment) continue;

    const row = {
      securityId: String(id),
      exchangeSegment,
      exchange: ex || null,
      segmentCode: sg || null,
      tradingSymbol: a[ix.SEM_TRADING_SYMBOL ?? ix.TRADING_SYMBOL] || "",
      customSymbol: a[ix.SEM_CUSTOM_SYMBOL ?? ix.CUSTOM_SYMBOL] || "",
      expiry: a[ix.SEM_EXPIRY_DATE ?? ix.EXPIRY_DATE] || "",
      strike: safeNum(a[ix.SEM_STRIKE_PRICE ?? ix.STRIKE_PRICE]),
      optionType: a[ix.SEM_OPTION_TYPE ?? ix.OPTION_TYPE] || "",
      instrument: a[ix.SEM_INSTRUMENT_NAME ?? ix.INSTRUMENT] || "",
      lotSize: safeNum(a[ix.SEM_LOT_UNITS ?? ix.LOT_UNITS]) ?? 1,
      tickSize: safeNum(a[ix.SEM_TICK_SIZE ?? ix.TICK_SIZE])
    };

    instrumentMap.set(key(exchangeSegment, id), row);
  }

  instrumentsLoadedAt = Date.now();
  console.log(`Loaded ${instrumentMap.size} Dhan instruments`);
}

function expiryISOtoDhan(x){return x}
async function refreshExpiries(){
  const cfg=INDEXES[state.indexKey];
  try{
    const j=await dhanPost("/optionchain/expirylist",{UnderlyingScrip:Number(cfg.securityId),UnderlyingSeg:cfg.segment});
    state.expiries=Array.isArray(j.data)?j.data:[];
    if(!state.expiry||!state.expiries.includes(state.expiry))state.expiry=state.expiries[0]||null;
  }catch(e){state.expiries=[];console.log("expiry:",e.message)}
}

let chainBusy=false,lastChainAt=0;
async function refreshChain(){
  if(chainBusy||!state.expiry)return;
  if(Date.now()-lastChainAt<3100)return;
  chainBusy=true;lastChainAt=Date.now();
  try{
    const cfg=INDEXES[state.indexKey];
    const j=await dhanPost("/optionchain",{
      UnderlyingScrip:Number(cfg.securityId),UnderlyingSeg:cfg.segment,Expiry:expiryISOtoDhan(state.expiry)
    });
    const rows=[];
    for(const [strike,raw] of Object.entries(j.data?.oc||{})){
      const s=safeNum(strike); if(s==null)continue;
      const make=(o,type)=>o?{
        type,securityId:String(o.security_id??""),ltp:safeNum(o.last_price),
        previousClose:safeNum(o.previous_close_price),oi:safeNum(o.oi)||0,previousOI:safeNum(o.previous_oi)||0,
        volume:safeNum(o.volume)||0,previousVolume:safeNum(o.previous_volume)||0,
        iv:safeNum(o.implied_volatility),
        bid:safeNum(o.top_bid_price),bidQty:safeNum(o.top_bid_quantity)||0,
        ask:safeNum(o.top_ask_price),askQty:safeNum(o.top_ask_quantity)||0,
        averagePrice:safeNum(o.average_price),
        greeks:o.greeks||{}
      }:null;
      rows.push({strike:s,ce:make(raw.ce,"CE"),pe:make(raw.pe,"PE")});
    }
    rows.sort((a,b)=>a.strike-b.strike);
    state.spot=safeNum(j.data?.last_price)??state.spot;
    state.chain={rows,spot:state.spot,updatedAt:now(),expiry:state.expiry,index:state.indexKey};
    // Keep a near-ATM live universe for every frontend: underlying + option legs.
    const near=[...rows].sort((a,b)=>Math.abs(a.strike-(state.spot??0))-Math.abs(b.strike-(state.spot??0))).slice(0,25);
    const optionSubs=[]; for(const r of near){ if(r.ce?.securityId) optionSubs.push({ExchangeSegment:INDEXES[state.indexKey].optionSegment,SecurityId:String(r.ce.securityId)}); if(r.pe?.securityId) optionSubs.push({ExchangeSegment:INDEXES[state.indexKey].optionSegment,SecurityId:String(r.pe.securityId)}); }
    state.subscriptions=[...new Map(optionSubs.map(x=>[key(x.ExchangeSegment,x.SecurityId),x])).values()].slice(0,50);
    resubscribeLive(); resubscribeDepth();
    state.analytics=buildAnalytics(rows,state.spot);
    broadcast({type:"optionChain",data:state.chain});
    broadcast({type:"analytics",data:state.analytics});
  }catch(e){console.log("chain:",e.message)}
  finally{chainBusy=false}
}

function buildAnalytics(rows,spot){
  let ceOI=0,peOI=0,ceVol=0,peVol=0,ceWall=null,peWall=null,ceMax=0,peMax=0;
  for(const r of rows){
    ceOI+=r.ce?.oi||0; peOI+=r.pe?.oi||0; ceVol+=r.ce?.volume||0; peVol+=r.pe?.volume||0;
    if((r.ce?.oi||0)>ceMax){ceMax=r.ce.oi;ceWall=r.strike}
    if((r.pe?.oi||0)>peMax){peMax=r.pe.oi;peWall=r.strike}
  }
  let maxPain=null,best=Infinity;
  for(const x of rows){
    let pain=0;
    for(const r of rows){
      pain+=(r.ce?.oi||0)*Math.max(0,x.strike-r.strike);
      pain+=(r.pe?.oi||0)*Math.max(0,r.strike-x.strike);
    }
    if(pain<best){best=pain;maxPain=x.strike}
  }
  const atm=rows.length&&spot!=null?rows.reduce((a,b)=>Math.abs(a.strike-spot)<Math.abs(b.strike-spot)?a:b):null;
  const atmIV=atm?((atm.ce?.iv||0)+(atm.pe?.iv||0))/2:null;
  const smile=rows.filter(r=>r.ce?.iv!=null||r.pe?.iv!=null).map(r=>({strike:r.strike,ceIV:r.ce?.iv??null,peIV:r.pe?.iv??null}));
  const netGEX=rows.reduce((s,r)=>{
    const cg=Number(r.ce?.greeks?.gamma)||0,pg=Number(r.pe?.greeks?.gamma)||0;
    return s+(cg*(r.ce?.oi||0)-pg*(r.pe?.oi||0));
  },0);
  const netDEX=rows.reduce((s,r)=>s+(Number(r.ce?.greeks?.delta)||0)*(r.ce?.oi||0)+(Number(r.pe?.greeks?.delta)||0)*(r.pe?.oi||0),0);
  return {
    pcr:ceOI?+(peOI/ceOI).toFixed(3):null,volumePcr:ceVol?+(peVol/ceVol).toFixed(3):null,
    ceOI,peOI,ceVolume:ceVol,peVolume:peVol,ceOiWall:ceWall,peOiWall:peWall,maxPain,
    atmStrike:atm?.strike??null,atmIV,ivSmile:smile,
    netGEX:Math.round(netGEX),netDEX:Math.round(netDEX),
    gexRegime:netGEX>=0?"POSITIVE":"NEGATIVE",
    dealerHedgePressureScore:Math.max(-100,Math.min(100,Math.round(netGEX===0?0:(netGEX>0?-25:25)))),
    dealerHedgePressureLabel:"MODEL-DERIVED PROXY — not proprietary dealer positioning",
    hiddenGreeks:{vanna:"model-derived",vomma:"model-derived",charm:"model-derived",color:"model-derived",speed:"model-derived",zomma:"model-derived"},
    disclaimer:"GEX/dealer-pressure/hidden Greeks are model-derived proxies. They are not verified proprietary dealer positions."
  };
}

function normalizeBuffer(data){
  if(Buffer.isBuffer(data))return data;
  if(data instanceof ArrayBuffer)return Buffer.from(data);
  if(ArrayBuffer.isView(data))return Buffer.from(data.buffer,data.byteOffset,data.byteLength);
  return Buffer.from(data);
}
function liveDecode(buf){
  const out=[];
  let p=0;
  while(p+8<=buf.length){
    const len=buf.readInt16LE(p);
    const total=len>0&&p+len<=buf.length?len:buf.length-p;
    if(total<8||p+total>buf.length)break;
    const code=buf.readUInt8(p+2),segCode=buf.readUInt8(p+3),sid=String(buf.readInt32LE(p+4));
    const seg=Object.entries(SEGMENT_CODE).find(([,v])=>v===segCode)?.[0]||`CODE_${segCode}`;
    if(code===2 && total>=17)out.push({type:"tick",exchangeSegment:seg,securityId:sid,ltp:buf.readFloatLE(p+8),ltt:buf.readInt32LE(p+12)*1000});
    else if(code===4 && total>=51)out.push({type:"quote",exchangeSegment:seg,securityId:sid,ltp:buf.readFloatLE(p+8),ltq:buf.readInt16LE(p+12),ltt:buf.readInt32LE(p+14)*1000,atp:buf.readFloatLE(p+18),volume:buf.readInt32LE(p+22),totalSellQty:buf.readInt32LE(p+26),totalBuyQty:buf.readInt32LE(p+30),open:buf.readFloatLE(p+34),close:buf.readFloatLE(p+38),high:buf.readFloatLE(p+42),low:buf.readFloatLE(p+46)});
    else if(code===8 && total>=162){
      const d=[];for(let i=0;i<5;i++){const q=p+63+i*20;d.push({bidQty:buf.readInt32LE(q),askQty:buf.readInt32LE(q+4),bidOrders:buf.readInt16LE(q+8),askOrders:buf.readInt16LE(q+10),bidPrice:buf.readFloatLE(q+12),askPrice:buf.readFloatLE(q+16)})}
      out.push({type:"full",exchangeSegment:seg,securityId:sid,ltp:buf.readFloatLE(p+8),ltq:buf.readInt16LE(p+12),ltt:buf.readInt32LE(p+14)*1000,atp:buf.readFloatLE(p+18),volume:buf.readInt32LE(p+22),totalSellQty:buf.readInt32LE(p+26),totalBuyQty:buf.readInt32LE(p+30),oi:buf.readInt32LE(p+34),oiDayHigh:buf.readInt32LE(p+38),oiDayLow:buf.readInt32LE(p+42),open:buf.readFloatLE(p+46),close:buf.readFloatLE(p+50),high:buf.readFloatLE(p+54),low:buf.readFloatLE(p+58),depth5:d});
    }
    p+=total;
  }
  return out;
}
function depthDecode(buf){
  const out=[];let p=0;
  while(p+12<=buf.length){
    const len=buf.readInt16LE(p);
    const total=len>0&&p+len<=buf.length?len:buf.length-p;
    if(total<332||p+total>buf.length)break;
    const code=buf.readUInt8(p+2),segCode=buf.readUInt8(p+3),sid=String(buf.readInt32LE(p+4));
    const seg=Object.entries(SEGMENT_CODE).find(([,v])=>v===segCode)?.[0]||`CODE_${segCode}`;
    const side=code===41?"bids":code===51?"asks":null;
    if(side){const levels=[];for(let i=0;i<20;i++){const q=p+12+i*16;levels.push({price:buf.readDoubleLE(q),quantity:buf.readUInt32LE(q+8),orders:buf.readUInt32LE(q+12)})}out.push({exchangeSegment:seg,securityId:sid,side,levels})}
    p+=total;
  }
  return out;
}
function safeSend(ws, payload){
  if(ws?.readyState===WebSocket.OPEN) ws.send(JSON.stringify(payload));
}
function subscribeChunks(ws,requestCode,list,size){
  if(!ws || ws.readyState!==WebSocket.OPEN || !list.length) return;
  for(let i=0;i<list.length;i+=size){
    const part=list.slice(i,i+size);
    safeSend(ws,{RequestCode:requestCode,InstrumentCount:part.length,InstrumentList:part});
  }
}
function scheduleLiveReconnect(delay=3000){
  clearTimeout(liveReconnectTimer);
  liveReconnectTimer=setTimeout(()=>liveConnect(),delay);
}
function scheduleDepthReconnect(delay=4000){
  clearTimeout(depthReconnectTimer);
  depthReconnectTimer=setTimeout(()=>depthConnect(),delay);
}
function liveConnect(){
  if(liveWS && (liveWS.readyState===WebSocket.OPEN || liveWS.readyState===WebSocket.CONNECTING)) return;
  clearTimeout(liveReconnectTimer);
  markFeed("live",{status:"CONNECTING",lastError:null});
  getToken().then(token=>{
    if(!token||!CLIENT_ID) throw new Error("Missing Dhan token/client ID");
    const u=`wss://api-feed.dhan.co?version=2&token=${encodeURIComponent(token)}&clientId=${encodeURIComponent(CLIENT_ID)}&authType=2`;
    const ws=new WebSocket(u); liveWS=ws;
    ws.on("open",()=>{
      markFeed("live",{status:"CONNECTED",lastOpenAt:now(),lastError:null,closeCode:null,closeReason:null});
      state.dhanConnected=true;
      broadcast({type:"status",data:{dhanConnected:true,feed:feedSnapshot().live}});
      resubscribeLive();
    });
    ws.on("message",raw=>{
      markFeed("live",{status:"CONNECTED",lastMessageAt:now(),lastError:null});
      state.server.packets++; feedDiagnostics.live.packets++;
      const arr=liveDecode(normalizeBuffer(raw));
      for(const t of arr){
        state.server.ticks++; state.lastTick=t;
        state.ticks.push(t); if(state.ticks.length>5000)state.ticks.shift();
        if(t.exchangeSegment==="IDX_I"&&t.securityId===INDEXES[state.indexKey].securityId) state.spot=t.ltp;
        if(t.type==="full") updateDepth5(t);
        broadcast({type:"tick",data:t});
      }
    });
    ws.on("error",err=>{
      const msg=err?.message||String(err); markFeed("live",{status:"ERROR",lastError:msg});
      console.log("Dhan live websocket error:",msg);
    });
    ws.on("close",(code,reason)=>{
      const why=Buffer.isBuffer(reason)?reason.toString():String(reason||"");
      markFeed("live",{status:"DISCONNECTED",closeCode:code,closeReason:why,reconnects:feedDiagnostics.live.reconnects+1});
      state.dhanConnected=false; state.server.reconnects++;
      broadcast({type:"status",data:{dhanConnected:false,feed:feedSnapshot().live}});
      if(liveWS===ws) liveWS=null;
      scheduleLiveReconnect(code===1000?3000:2000);
    });
  }).catch(e=>{
    markFeed("live",{status:"AUTH_WAIT",lastError:e.message});
    console.log("live connect:",e.message);
    scheduleLiveReconnect(8000);
  });
}
function updateDepth5(t){
  const k=key(t.exchangeSegment,t.securityId);
  const d=state.depth[k]||{levels:20,bids:[],asks:[]};
  d.bids=t.depth5.map(x=>({price:x.bidPrice,quantity:x.bidQty,orders:x.bidOrders}));
  d.asks=t.depth5.map(x=>({price:x.askPrice,quantity:x.askQty,orders:x.askOrders}));
  d.updatedAt=now(); state.depth[k]=d;
}
function depthConnect(){
  if(depthWS && (depthWS.readyState===WebSocket.OPEN || depthWS.readyState===WebSocket.CONNECTING)) return;
  clearTimeout(depthReconnectTimer);
  markFeed("depth",{status:"CONNECTING",lastError:null});
  getToken().then(token=>{
    if(!token||!CLIENT_ID) throw new Error("Missing Dhan token/client ID");
    const u=`wss://depth-api-feed.dhan.co/twentydepth?token=${encodeURIComponent(token)}&clientId=${encodeURIComponent(CLIENT_ID)}&authType=2`;
    const ws=new WebSocket(u); depthWS=ws;
    ws.on("open",()=>{
      markFeed("depth",{status:"CONNECTED",lastOpenAt:now(),lastError:null,closeCode:null,closeReason:null});
      state.depthConnected=true;
      broadcast({type:"status",data:{depthConnected:true,feed:feedSnapshot().depth}});
      resubscribeDepth();
    });
    ws.on("message",raw=>{
      markFeed("depth",{status:"CONNECTED",lastMessageAt:now(),lastError:null});
      state.server.depthPackets++; feedDiagnostics.depth.packets++;
      const arr=depthDecode(normalizeBuffer(raw));
      for(const x of arr){
        const k=key(x.exchangeSegment,x.securityId);
        const d=state.depth[k]||{levels:20,bids:[],asks:[]};
        d.levels=20; d[x.side]=x.levels; d.updatedAt=now(); state.depth[k]=d;
        broadcast({type:"depth",data:{...x,depth:d}});
      }
    });
    ws.on("error",err=>{
      const msg=err?.message||String(err); markFeed("depth",{status:"ERROR",lastError:msg});
      console.log("Dhan depth websocket error:",msg);
    });
    ws.on("close",(code,reason)=>{
      const why=Buffer.isBuffer(reason)?reason.toString():String(reason||"");
      markFeed("depth",{status:"DISCONNECTED",closeCode:code,closeReason:why,reconnects:feedDiagnostics.depth.reconnects+1});
      state.depthConnected=false;
      broadcast({type:"status",data:{depthConnected:false,feed:feedSnapshot().depth}});
      if(depthWS===ws) depthWS=null;
      scheduleDepthReconnect(code===1000?4000:2500);
    });
  }).catch(e=>{
    markFeed("depth",{status:"AUTH_WAIT",lastError:e.message});
    console.log("depth connect:",e.message);
    scheduleDepthReconnect(8000);
  });
}

function resubscribeLive(){
  const list=[{ExchangeSegment:"IDX_I",SecurityId:INDEXES[state.indexKey].securityId},...state.subscriptions];
  if(liveWS?.readyState===WebSocket.OPEN)subscribeChunks(liveWS,21,list,100);
}
function resubscribeDepth(){
  const list=state.subscriptions.slice(0,50);
  if(depthWS?.readyState===WebSocket.OPEN)subscribeChunks(depthWS,23,list,50);
}
function subscribe(instruments){
  const uniq=[];const seen=new Set();
  for(const x of instruments||[]){if(!x?.ExchangeSegment||!x?.SecurityId)continue;const k=key(x.ExchangeSegment,String(x.SecurityId));if(!seen.has(k)){seen.add(k);uniq.push({ExchangeSegment:x.ExchangeSegment,SecurityId:String(x.SecurityId)})}}
  state.subscriptions=uniq.slice(0,600);
  resubscribeLive();resubscribeDepth();
  broadcast({type:"state",data:state});
}

function intradayBody(q){
  const id=String(q.securityId||INDEXES[state.indexKey].securityId);
  const seg=q.segment||q.exchangeSegment||"IDX_I";
  const instrument=q.instrument||"INDEX";
  const interval=String(q.interval||"1");
  const to=new Date();
  const from=new Date(Date.now()-7*24*3600*1000);
  return {securityId:id,exchangeSegment:seg,instrument,interval,oi:q.oi==="true"||q.oi===true,fromDate:q.fromDate||from.toISOString().slice(0,19).replace("T"," "),toDate:q.toDate||to.toISOString().slice(0,19).replace("T"," ")};
}

function startFeedWatchdogs(){
  clearInterval(liveWatchdogTimer); clearInterval(depthWatchdogTimer);
  liveWatchdogTimer=setInterval(()=>{
    const last=feedDiagnostics.live.lastMessageAt?Date.parse(feedDiagnostics.live.lastMessageAt):0;
    if(state.dhanConnected && last && Date.now()-last>45_000){
      markFeed("live",{status:"STALE",lastError:"No live feed packet received for >45s"});
      try{liveWS?.terminate();}catch{}
    }
  },10_000);
  depthWatchdogTimer=setInterval(()=>{
    const last=feedDiagnostics.depth.lastMessageAt?Date.parse(feedDiagnostics.depth.lastMessageAt):0;
    if(state.depthConnected && last && Date.now()-last>45_000){
      markFeed("depth",{status:"STALE",lastError:"No depth packet received for >45s"});
      try{depthWS?.terminate();}catch{}
    }
  },10_000);
}

async function initializeDhan() {
  // Authenticate exactly once for startup. Both WebSockets and REST calls share
  // the same token cache/promise, so Render cannot accidentally request multiple
  // Dhan tokens at the same time.
  try {
    await getToken();
    try { await loadInstruments(); }
    catch (e) { console.log("instrument master:", e.message); }

    liveConnect();
    depthConnect();
    startFeedWatchdogs();

    await refreshExpiries();
    await refreshChain();

    // Dhan option-chain requests are throttled; do not poll the expiry list every second.
    setInterval(() => refreshChain().catch(e => console.log("chain loop:", e.message)), 3500);
    setInterval(() => refreshExpiries().catch(e => console.log("expiry loop:", e.message)), 60_000);
  } catch (e) {
    console.log("Dhan startup auth:", e.message);
    // Retry only after the Dhan token-generation cooldown if auth failed.
    const delay = Math.max(10_000, tokenRetryAfter ? tokenRetryAfter - Date.now() + 1000 : 120_000);
    setTimeout(initializeDhan, delay);
  }
}

app.get("/",(_q,r)=>r.json({ok:true,name:"Bharati Universal Backend",version:state.version,websocket:"/ws",depthLevels:20}));
app.get("/api/health",(_q,r)=>r.json({
  ok:true,
  version:state.version,
  dhanConnected:state.dhanConnected,
  depthConnected:state.depthConnected,
  auth:authState,
  feed:feedSnapshot(),
  lastTickAt:state.lastTick?.ltt?new Date(state.lastTick.ltt).toISOString():null,
  chainUpdatedAt:state.chain.updatedAt,
  time:now()
}));
app.get("/api/status",(_q,r)=>r.json({
  ok:true,
  version:state.version,
  dhanConnected:state.dhanConnected,
  depthConnected:state.depthConnected,
  auth:authState,
  index:state.indexKey,
  expiry:state.expiry,
  spot:state.spot,
  ticks:state.server.ticks,
  packets:state.server.packets,
  depthPackets:state.server.depthPackets,
  subscriptions:state.subscriptions.length,
  chainRows:state.chain.rows.length,
  depthLevels:20,
  feed:feedSnapshot(),
  lastTickAt:state.lastTick?.ltt?new Date(state.lastTick.ltt).toISOString():null,
  chainUpdatedAt:state.chain.updatedAt,
  time:now()
}));
app.get("/api/auth-status",(_q,r)=>r.json({ok:true,...authState,tokenCached:Boolean(tokenCache.token),tokenExpiresAt:tokenCache.expiresAt?new Date(tokenCache.expiresAt).toISOString():null}));
app.get("/api/feed-status",(_q,r)=>r.json({ok:true,dhanConnected:state.dhanConnected,depthConnected:state.depthConnected,feed:feedSnapshot(),server:state.server,lastTick:state.lastTick,lastChainAt:state.chain.updatedAt}));
app.get("/api/config",(_q,r)=>r.json({ok:true,version:state.version,indexes:Object.keys(INDEXES),defaultIndex:state.indexKey,depthLevels:20,l20:true,bidAsk:true,ws:"/ws",capabilities:state.capabilities}));
app.get("/api/state",(_q,r)=>r.json(state));
app.get("/api/ticks",(_q,r)=>r.json({ok:true,ticks:state.ticks,lastTick:state.lastTick}));
app.get("/api/tick",(q,r)=>{
  const seg=String(q.query.segment||q.query.exchangeSegment||"");
  const sid=String(q.query.securityId||"");
  const item=state.ticks.slice().reverse().find(x=>(!seg||x.exchangeSegment===seg)&&(!sid||String(x.securityId)===sid))||null;
  r.json({ok:true,tick:item});
});

app.get("/api/option-chain",(_q,r)=>r.json({ok:true,index:state.indexKey,expiry:state.expiry,spot:state.spot,...state.chain}));
app.get("/api/analytics",(_q,r)=>r.json({ok:true,index:state.indexKey,expiry:state.expiry,...state.analytics}));
app.get("/api/depth",(q,r)=>{const k=key(q.query.segment||q.query.exchangeSegment||"NSE_FNO",String(q.query.securityId||""));r.json({ok:true,segment:q.query.segment||q.query.exchangeSegment||null,securityId:q.query.securityId||null,levels:20,bidAsk:true,depth:state.depth[k]||{levels:20,bids:[],asks:[]}})});
app.get("/api/history",async(q,r)=>{
  try{const body=intradayBody(q.query);const j=await dhanPost("/charts/intraday",body);const candles=[];const o=j.open||[],h=j.high||[],l=j.low||[],c=j.close||[],v=j.volume||[],ts=j.timestamp||[];
    for(let i=0;i<c.length;i++)candles.push({time:Number(ts[i])*1000,open:o[i],high:h[i],low:l[i],close:c[i],volume:v[i]??0,openInterest:j.open_interest?.[i]??null});
    r.json({ok:true,segment:body.exchangeSegment,securityId:body.securityId,interval:body.interval,candles});
  }catch(e){r.status(502).json({ok:false,error:e.message})}
});
app.get("/api/instruments",async(q,r)=>{try{await loadInstruments();const term=String(q.query.search||"").toLowerCase();const limit=Math.min(100,Number(q.query.limit||20));const out=[];for(const x of instrumentMap.values()){const s=`${x.tradingSymbol} ${x.customSymbol}`.toLowerCase();if(!term||s.includes(term)){out.push(x);if(out.length>=limit)break}}r.json({ok:true,items:out})}catch(e){r.status(502).json({ok:false,error:e.message})}});
app.post("/api/index",(q,r)=>{const idx=String(q.body?.index||"").toUpperCase();if(!INDEXES[idx])return r.status(400).json({ok:false,error:"Unsupported index"});state.indexKey=idx;state.expiry=null;state.chain={rows:[],updatedAt:null,spot:null};resubscribeLive();refreshExpiries();broadcast({type:"state",data:state});r.json({ok:true,index:idx})});
app.post("/api/expiry",async(_q,r)=>{await refreshExpiries();r.json({ok:true,expiry:state.expiry,expiries:state.expiries})});
app.post("/api/expiry/select",(q,r)=>{const x=String(q.body?.expiry||"");if(!state.expiries.includes(x))return r.status(400).json({ok:false,error:"Expiry not available"});state.expiry=x;refreshChain();broadcast({type:"state",data:state});r.json({ok:true,expiry:x})});
app.post("/api/subscribe",(q,r)=>{subscribe(q.body?.instruments||[]);r.json({ok:true,subscribed:state.subscriptions.length,instruments:state.subscriptions})});
app.get("/api/history/health",(_q,r)=>r.json({ok:true}));

const server=app.listen(PORT,"0.0.0.0",()=> {
  console.log(`Bharati Universal Backend listening on ${PORT}`);
  initializeDhan();
});
const gateway=new WebSocketServer({server,path:"/ws"});
gateway.on("connection",ws=>{
  clients.add(ws);
  ws.send(JSON.stringify({type:"hello",data:{version:state.version,capabilities:state.capabilities}}));
  ws.send(JSON.stringify({type:"state",data:state}));
  ws.on("close",()=>clients.delete(ws));
  ws.on("message",raw=>{try{const m=JSON.parse(raw.toString());if(m.type==="subscribe")subscribe(m.instruments||[])}catch{ws.send(JSON.stringify({type:"error",error:"Invalid JSON"}))}});
});
