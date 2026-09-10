import express from "express";
import cors from "cors";
import WebSocket, { WebSocketServer } from "ws";
import { authenticator } from "otplib";

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));
app.use((_req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

const PORT = Number(process.env.PORT || 10000);
const CLIENT_ID = (process.env.DHAN_CLIENT_ID || "").trim();
const PIN = (process.env.DHAN_PIN || "").trim();
const TOTP_SECRET = (process.env.DHAN_TOTP_SECRET || "").replace(/\s+/g, "").toUpperCase();
const STATIC_TOKEN = (process.env.DHAN_ACCESS_TOKEN || "").trim();
const DEFAULT_INDEX = (process.env.DEFAULT_INDEX || "NIFTY").toUpperCase();

const INDEXES = {
  NIFTY: { securityId: "13", segment: "IDX_I", optionSegment: "NSE_FNO" },
  BANKNIFTY: { securityId: "25", segment: "IDX_I", optionSegment: "NSE_FNO" },
  FINNIFTY: { securityId: "27", segment: "IDX_I", optionSegment: "NSE_FNO" },
  MIDCPNIFTY: { securityId: "442", segment: "IDX_I", optionSegment: "NSE_FNO" },
  SENSEX: { securityId: "51", segment: "IDX_I", optionSegment: "BSE_FNO" }
};

const state = {
  version: "Bharati-Simple-RSI-1.0",
  indexKey: INDEXES[DEFAULT_INDEX] ? DEFAULT_INDEX : "NIFTY",
  expiry: null,
  expiries: [],
  spot: null,
  lastTick: null,
  ticks: [],
  optionTicks: {},
  chain: { rows: [], spot: null, updatedAt: null, expiry: null, index: null },
  analytics: {},
  candles: [],
  currentCandle: null,
  subscriptions: [],
  server: { quoteRequests: 0, quoteSuccess: 0, quoteErrors: 0, ticks: 0, lastQuoteAt: null, lastError: null },
  dataConnected: false,
  capabilities: {
    mode: "REST_QUOTE",
    ltp: true,
    approximateUpdateSeconds: 1,
    optionChain: true,
    history: true,
    websocketToFrontend: true,
    dhanWebSocket: false,
    l20: false,
    depthLevels: 0
  }
};

let tokenCache = { token: null, expiresAt: 0 };
let tokenPromise = null;
let tokenRetryAfter = 0;
const clients = new Set();
const instrumentMap = new Map();
let instrumentsLoadedAt = 0;
let chainBusy = false;
let lastChainAt = 0;
let quoteBusy = false;
let historyBusy = false;

let authState = {
  mode: STATIC_TOKEN ? "STATIC_TOKEN" : "TOTP",
  status: STATIC_TOKEN ? "READY" : "WAITING",
  lastSuccessAt: null,
  lastError: null,
  retryAfter: null
};

function now() { return new Date().toISOString(); }
function safeNum(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }
function key(segment, securityId) { return `${segment}:${securityId}`; }
function broadcast(payload) {
  const msg = JSON.stringify(payload);
  for (const ws of clients) if (ws.readyState === WebSocket.OPEN) ws.send(msg);
}

async function getToken() {
  if (STATIC_TOKEN) {
    authState = { ...authState, mode: "STATIC_TOKEN", status: "READY", lastError: null, retryAfter: null };
    return STATIC_TOKEN;
  }
  if (!CLIENT_ID || !PIN || !TOTP_SECRET) {
    authState = { ...authState, status: "CONFIG_ERROR", lastError: "Set DHAN_CLIENT_ID, DHAN_PIN and DHAN_TOTP_SECRET" };
    throw new Error(authState.lastError);
  }
  if (tokenCache.token && Date.now() < tokenCache.expiresAt - 5 * 60_000) return tokenCache.token;
  if (Date.now() < tokenRetryAfter) {
    const sec = Math.ceil((tokenRetryAfter - Date.now()) / 1000);
    authState = { ...authState, status: "RATE_LIMIT_COOLDOWN", retryAfter: new Date(tokenRetryAfter).toISOString() };
    throw new Error(`Dhan token cooldown; retry in ${sec}s`);
  }
  if (tokenPromise) return tokenPromise;

  tokenPromise = (async () => {
    authState = { ...authState, status: "GENERATING", lastError: null, retryAfter: null };
    const totp = authenticator.generate(TOTP_SECRET);
    const url = `https://auth.dhan.co/app/generateAccessToken?dhanClientId=${encodeURIComponent(CLIENT_ID)}&pin=${encodeURIComponent(PIN)}&totp=${encodeURIComponent(totp)}`;
    const r = await fetch(url, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" } });
    const text = await r.text();
    let j = {};
    try { j = JSON.parse(text); } catch {}
    const token = j.accessToken || j.access_token || j.token || j.accesstoken;
    if (!r.ok || !token) {
      const msg = j.errorMessage || j.message || j.remarks || text.slice(0, 300) || `Dhan auth ${r.status}`;
      if (/once every 2 minutes|2 minutes|too frequently|rate limit/i.test(msg) || r.status === 429) tokenRetryAfter = Date.now() + 120_000;
      authState = { ...authState, status: `FAILED_${r.status}`, lastError: String(msg), retryAfter: tokenRetryAfter ? new Date(tokenRetryAfter).toISOString() : null };
      throw new Error(String(msg));
    }
    const expiry = j.expiryTime ? new Date(j.expiryTime).getTime() : Date.now() + 23 * 3600_000;
    tokenCache = { token: String(token), expiresAt: Math.max(Date.now() + 120_000, expiry) };
    tokenRetryAfter = 0;
    authState = { ...authState, status: "AUTHENTICATED", lastSuccessAt: now(), lastError: null, retryAfter: null };
    return tokenCache.token;
  })();

  try { return await tokenPromise; } finally { tokenPromise = null; }
}

async function dhanPost(path, body) {
  const token = await getToken();
  const r = await fetch(`https://api.dhan.co/v2${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", "access-token": token, "client-id": CLIENT_ID },
    body: JSON.stringify(body)
  });
  const text = await r.text();
  let j = {};
  try { j = JSON.parse(text); } catch {}
  if (!r.ok || j.status === "failure") throw new Error(j.errorMessage || j.remarks || j.message || `Dhan HTTP ${r.status}`);
  return j;
}

function parseCsvLine(line) {
  const out = []; let cur = ""; let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') { cur += '"'; i++; } else quoted = !quoted;
    } else if (ch === "," && !quoted) { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur); return out;
}

async function loadInstruments() {
  if (instrumentMap.size && Date.now() - instrumentsLoadedAt < 12 * 3600_000) return;
  const r = await fetch("https://images.dhan.co/api-data/api-scrip-master.csv");
  if (!r.ok) throw new Error(`Instrument master HTTP ${r.status}`);
  const txt = await r.text();
  const lines = txt.split(/\r?\n/).filter(Boolean);
  if (!lines.length) throw new Error("Instrument master empty");
  const header = parseCsvLine(lines[0]);
  const ix = {}; header.forEach((h, i) => ix[h.trim()] = i);
  for (let n = 1; n < lines.length; n++) {
    const a = parseCsvLine(lines[n]);
    const id = a[ix.SECURITY_ID ?? ix.SEM_SECURITY_ID];
    const exchangeSegment = a[ix.SEGMENT ?? ix.SEM_SEGMENT] || "";
    if (!id || !exchangeSegment) continue;
    instrumentMap.set(key(exchangeSegment, id), {
      securityId: String(id), exchangeSegment,
      tradingSymbol: a[ix.SEM_TRADING_SYMBOL ?? ix.TRADING_SYMBOL] || "",
      customSymbol: a[ix.SEM_CUSTOM_SYMBOL ?? ix.CUSTOM_SYMBOL] || "",
      expiry: a[ix.SEM_EXPIRY_DATE ?? ix.EXPIRY_DATE] || "",
      strike: safeNum(a[ix.SEM_STRIKE_PRICE ?? ix.STRIKE_PRICE]),
      optionType: a[ix.SEM_OPTION_TYPE ?? ix.OPTION_TYPE] || "",
      instrument: a[ix.SEM_INSTRUMENT_NAME ?? ix.INSTRUMENT] || "",
      lotSize: safeNum(a[ix.SEM_LOT_UNITS ?? ix.LOT_UNITS]) ?? 1,
      tickSize: safeNum(a[ix.SEM_TICK_SIZE ?? ix.TICK_SIZE])
    });
  }
  instrumentsLoadedAt = Date.now();
  console.log(`Loaded ${instrumentMap.size} instruments`);
}

async function refreshExpiries() {
  const cfg = INDEXES[state.indexKey];
  try {
    const j = await dhanPost("/optionchain/expirylist", { UnderlyingScrip: Number(cfg.securityId), UnderlyingSeg: cfg.segment });
    state.expiries = Array.isArray(j.data) ? j.data : [];
    if (!state.expiry || !state.expiries.includes(state.expiry)) state.expiry = state.expiries[0] || null;
  } catch (e) { state.expiries = []; state.server.lastError = `expiry: ${e.message}`; console.log(state.server.lastError); }
}

function buildAnalytics(rows, spot) {
  let ceOI = 0, peOI = 0, ceVol = 0, peVol = 0, ceWall = null, peWall = null, ceMax = 0, peMax = 0;
  for (const r of rows) {
    ceOI += r.ce?.oi || 0; peOI += r.pe?.oi || 0; ceVol += r.ce?.volume || 0; peVol += r.pe?.volume || 0;
    if ((r.ce?.oi || 0) > ceMax) { ceMax = r.ce.oi; ceWall = r.strike; }
    if ((r.pe?.oi || 0) > peMax) { peMax = r.pe.oi; peWall = r.strike; }
  }
  let maxPain = null, best = Infinity;
  for (const x of rows) {
    let pain = 0;
    for (const r of rows) {
      pain += (r.ce?.oi || 0) * Math.max(0, x.strike - r.strike);
      pain += (r.pe?.oi || 0) * Math.max(0, r.strike - x.strike);
    }
    if (pain < best) { best = pain; maxPain = x.strike; }
  }
  const atm = rows.length && spot != null ? rows.reduce((a, b) => Math.abs(a.strike - spot) < Math.abs(b.strike - spot) ? a : b) : null;
  const atmIV = atm ? ((atm.ce?.iv || 0) + (atm.pe?.iv || 0)) / 2 : null;
  return {
    pcr: ceOI ? +(peOI / ceOI).toFixed(3) : null,
    volumePcr: ceVol ? +(peVol / ceVol).toFixed(3) : null,
    ceOI, peOI, ceVolume: ceVol, peVolume: peVol, ceOiWall: ceWall, peOiWall: peWall,
    maxPain, atmStrike: atm?.strike ?? null, atmIV,
    gexRegime: null, netGEX: null,
    disclaimer: "Simple RSI backend: no L20/dealer-position model is used."
  };
}

async function refreshChain() {
  if (chainBusy || !state.expiry || Date.now() - lastChainAt < 3100) return;
  chainBusy = true; lastChainAt = Date.now();
  try {
    const cfg = INDEXES[state.indexKey];
    const j = await dhanPost("/optionchain", { UnderlyingScrip: Number(cfg.securityId), UnderlyingSeg: cfg.segment, Expiry: state.expiry });
    const rows = [];
    for (const [strike, raw] of Object.entries(j.data?.oc || {})) {
      const s = safeNum(strike); if (s == null) continue;
      const make = (o, type) => o ? {
        type, securityId: String(o.security_id ?? ""), ltp: safeNum(o.last_price), previousClose: safeNum(o.previous_close_price),
        oi: safeNum(o.oi) || 0, previousOI: safeNum(o.previous_oi) || 0, volume: safeNum(o.volume) || 0, previousVolume: safeNum(o.previous_volume) || 0,
        iv: safeNum(o.implied_volatility), bid: safeNum(o.top_bid_price), bidQty: safeNum(o.top_bid_quantity) || 0,
        ask: safeNum(o.top_ask_price), askQty: safeNum(o.top_ask_quantity) || 0, averagePrice: safeNum(o.average_price), greeks: o.greeks || {}
      } : null;
      rows.push({ strike: s, ce: make(raw.ce, "CE"), pe: make(raw.pe, "PE") });
    }
    rows.sort((a, b) => a.strike - b.strike);
    state.spot = safeNum(j.data?.last_price) ?? state.spot;
    state.chain = { rows, spot: state.spot, updatedAt: now(), expiry: state.expiry, index: state.indexKey };
    const near = [...rows].sort((a, b) => Math.abs(a.strike - (state.spot ?? 0)) - Math.abs(b.strike - (state.spot ?? 0))).slice(0, 10);
    const subs = [];
    for (const r of near) {
      if (r.ce?.securityId) subs.push({ ExchangeSegment: cfg.optionSegment, SecurityId: r.ce.securityId });
      if (r.pe?.securityId) subs.push({ ExchangeSegment: cfg.optionSegment, SecurityId: r.pe.securityId });
    }
    state.subscriptions = subs.slice(0, 20);
    state.analytics = buildAnalytics(rows, state.spot);
    broadcast({ type: "optionChain", data: state.chain });
    broadcast({ type: "analytics", data: state.analytics });
  } catch (e) { state.server.lastError = `option-chain: ${e.message}`; console.log(state.server.lastError); }
  finally { chainBusy = false; }
}

function quoteBody() {
  const cfg = INDEXES[state.indexKey];
  const body = { IDX_I: [Number(cfg.securityId)] };
  const ids = state.subscriptions.map(x => Number(x.SecurityId)).filter(Number.isFinite);
  if (ids.length) body[cfg.optionSegment] = ids;
  return body;
}

function addTick(tick) {
  state.lastTick = tick;
  state.ticks.push(tick);
  if (state.ticks.length > 3000) state.ticks.splice(0, state.ticks.length - 3000);
  state.server.ticks++;
  if (tick.exchangeSegment === "IDX_I") {
    state.spot = tick.ltp;
    updateMinuteCandle(tick.ltp, tick.ltt || Date.now());
  } else {
    state.optionTicks[key(tick.exchangeSegment, tick.securityId)] = tick;
  }
  broadcast({ type: "tick", data: tick });
}

function updateMinuteCandle(price, epochMs) {
  const d = new Date(epochMs);
  const start = new Date(d); start.setSeconds(0, 0);
  const t = start.getTime();
  if (!state.currentCandle || state.currentCandle.time !== t) {
    if (state.currentCandle) {
      state.candles.push({ ...state.currentCandle, closed: true });
      if (state.candles.length > 1000) state.candles.splice(0, state.candles.length - 1000);
    }
    state.currentCandle = { time: t, open: price, high: price, low: price, close: price, volume: 0, closed: false };
  } else {
    state.currentCandle.high = Math.max(state.currentCandle.high, price);
    state.currentCandle.low = Math.min(state.currentCandle.low, price);
    state.currentCandle.close = price;
  }
  broadcast({ type: "candle", data: state.currentCandle });
}

async function pollQuotes() {
  if (quoteBusy) return;
  quoteBusy = true;
  state.server.quoteRequests++;
  try {
    const j = await dhanPost("/marketfeed/ltp", quoteBody());
    const data = j.data || {};
    let count = 0;
    for (const [segment, items] of Object.entries(data)) {
      if (!items || typeof items !== "object") continue;
      for (const [securityId, raw] of Object.entries(items)) {
        const ltp = safeNum(raw?.last_price);
        if (ltp == null) continue;
        addTick({ type: "tick", exchangeSegment: segment, securityId: String(securityId), ltp, ltt: Date.now(), source: "Dhan REST Market Quote" });
        count++;
      }
    }
    state.server.quoteSuccess++;
    state.server.lastQuoteAt = now();
    state.server.lastError = count ? null : "Dhan quote returned no LTP";
    state.dataConnected = count > 0;
    broadcast({ type: "status", data: { dataConnected: state.dataConnected, mode: "REST_QUOTE", lastQuoteAt: state.server.lastQuoteAt } });
  } catch (e) {
    state.server.quoteErrors++;
    state.server.lastError = e.message;
    state.dataConnected = false;
    broadcast({ type: "status", data: { dataConnected: false, mode: "REST_QUOTE", error: e.message } });
  } finally { quoteBusy = false; }
}

async function seedHistory() {
  if (historyBusy) return;
  historyBusy = true;
  try {
    const cfg = INDEXES[state.indexKey];
    const to = new Date();
    const from = new Date(Date.now() - 5 * 24 * 3600_000);
    const j = await dhanPost("/charts/intraday", {
      securityId: cfg.securityId, exchangeSegment: cfg.segment, instrument: "INDEX", interval: "1", oi: false,
      fromDate: from.toISOString().slice(0, 19).replace("T", " "), toDate: to.toISOString().slice(0, 19).replace("T", " ")
    });
    const candles = [];
    const o = j.open || [], h = j.high || [], l = j.low || [], c = j.close || [], v = j.volume || [], ts = j.timestamp || [];
    for (let i = 0; i < c.length; i++) candles.push({ time: Number(ts[i]) * 1000, open: o[i], high: h[i], low: l[i], close: c[i], volume: v[i] ?? 0, closed: true });
    state.candles = candles.slice(-1000);
    broadcast({ type: "state", data: state });
  } catch (e) { state.server.lastError = `history seed: ${e.message}`; console.log(state.server.lastError); }
  finally { historyBusy = false; }
}

function setIndex(idx) {
  state.indexKey = idx; state.expiry = null; state.spot = null; state.chain = { rows: [], spot: null, updatedAt: null, expiry: null, index: idx };
  state.candles = []; state.currentCandle = null; state.subscriptions = []; state.optionTicks = {};
  state.server.lastError = null;
  broadcast({ type: "state", data: state });
  refreshExpiries().then(refreshChain).then(seedHistory).catch(() => {});
}

app.get("/", (_q, r) => r.json({ ok: true, name: "Bharati Simple RSI Backend", version: state.version, websocket: "/ws", mode: "REST_QUOTE", l20: false }));
app.get("/api/health", (_q, r) => r.json({ ok: true, version: state.version, dataConnected: state.dataConnected, auth: authState, lastQuoteAt: state.server.lastQuoteAt, lastError: state.server.lastError, time: now() }));
app.get("/api/feed-status", (_q, r) => r.json({ ok: true, mode: "REST_QUOTE", dataConnected: state.dataConnected, approximateUpdateSeconds: 1, server: state.server, auth: authState }));
app.get("/api/status", (_q, r) => r.json({ ok: true, version: state.version, mode: "REST_QUOTE", dataConnected: state.dataConnected, auth: authState, index: state.indexKey, expiry: state.expiry, spot: state.spot, candles: state.candles.length, currentCandle: state.currentCandle, subscriptions: state.subscriptions.length, chainRows: state.chain.rows.length, server: state.server, time: now() }));
app.get("/api/auth-status", (_q, r) => r.json({ ok: true, ...authState, tokenCached: Boolean(tokenCache.token), tokenExpiresAt: tokenCache.expiresAt ? new Date(tokenCache.expiresAt).toISOString() : null }));
app.get("/api/config", (_q, r) => r.json({ ok: true, version: state.version, indexes: Object.keys(INDEXES), defaultIndex: state.indexKey, mode: "REST_QUOTE", ltp: true, optionChain: true, history: true, l20: false, depthLevels: 0, ws: "/ws" }));
app.get("/api/state", (_q, r) => r.json(state));
app.get("/api/ticks", (_q, r) => r.json({ ok: true, ticks: state.ticks, lastTick: state.lastTick }));
app.get("/api/tick", (q, r) => {
  const seg = String(q.query.segment || q.query.exchangeSegment || "");
  const sid = String(q.query.securityId || "");
  const item = state.ticks.slice().reverse().find(x => (!seg || x.exchangeSegment === seg) && (!sid || String(x.securityId) === sid)) || null;
  r.json({ ok: true, tick: item });
});
app.get("/api/option-chain", (_q, r) => r.json({ ok: true, index: state.indexKey, expiry: state.expiry, spot: state.spot, ...state.chain }));
app.get("/api/analytics", (_q, r) => r.json({ ok: true, index: state.indexKey, expiry: state.expiry, ...state.analytics }));
app.get("/api/depth", (_q, r) => r.json({ ok: true, enabled: false, levels: 0, bidAsk: false, depth: { levels: 0, bids: [], asks: [] } }));
app.get("/api/history", async (q, r) => {
  try {
    const cfg = INDEXES[state.indexKey];
    const segment = q.query.segment || q.query.exchangeSegment || cfg.segment;
    const securityId = q.query.securityId || cfg.securityId;
    const instrument = q.query.instrument || (segment === "NSE_FNO" || segment === "BSE_FNO" ? "OPTIDX" : "INDEX");
    const interval = String(q.query.interval || "1");
    const to = new Date(); const from = new Date(Date.now() - 7 * 24 * 3600_000);
    const j = await dhanPost("/charts/intraday", { securityId: String(securityId), exchangeSegment: segment, instrument, interval, oi: q.query.oi === "true", fromDate: q.query.fromDate || from.toISOString().slice(0, 19).replace("T", " "), toDate: q.query.toDate || to.toISOString().slice(0, 19).replace("T", " ") });
    const candles = []; const o=j.open||[], h=j.high||[], l=j.low||[], c=j.close||[], v=j.volume||[], ts=j.timestamp||[];
    for (let i=0;i<c.length;i++) candles.push({ time:Number(ts[i])*1000, open:o[i], high:h[i], low:l[i], close:c[i], volume:v[i]??0, openInterest:j.open_interest?.[i]??null, closed:true });
    r.json({ ok:true, segment, securityId:String(securityId), instrument, interval, candles });
  } catch(e) { r.status(502).json({ ok:false, error:e.message }); }
});
app.get("/api/candles", (_q, r) => r.json({ ok: true, candles: state.candles, currentCandle: state.currentCandle }));
app.get("/api/instruments", async (q, r) => { try { await loadInstruments(); const term=String(q.query.search||"").toLowerCase(); const limit=Math.min(100, Number(q.query.limit||20)); const out=[]; for(const x of instrumentMap.values()){ const s=`${x.tradingSymbol} ${x.customSymbol}`.toLowerCase(); if(!term||s.includes(term)){out.push(x);if(out.length>=limit)break;} } r.json({ok:true,items:out}); } catch(e){r.status(502).json({ok:false,error:e.message});} });
app.post("/api/index", (q, r) => { const idx=String(q.body?.index||"").toUpperCase(); if(!INDEXES[idx]) return r.status(400).json({ok:false,error:"Unsupported index"}); setIndex(idx); r.json({ok:true,index:idx}); });
app.post("/api/expiry", async (_q, r) => { await refreshExpiries(); r.json({ok:true,expiry:state.expiry,expiries:state.expiries}); });
app.post("/api/expiry/select", async (q, r) => { const x=String(q.body?.expiry||""); if(!state.expiries.includes(x)) return r.status(400).json({ok:false,error:"Expiry not available"}); state.expiry=x; await refreshChain(); r.json({ok:true,expiry:x}); });
app.post("/api/subscribe", (q, r) => { const incoming=Array.isArray(q.body?.instruments)?q.body.instruments:[]; state.subscriptions=incoming.filter(x=>x?.ExchangeSegment&&x?.SecurityId).slice(0,100); r.json({ok:true,subscribed:state.subscriptions.length,instruments:state.subscriptions}); });

const server = app.listen(PORT, "0.0.0.0", () => console.log(`Bharati Simple RSI Backend listening on ${PORT}`));
const gateway = new WebSocketServer({ server, path: "/ws" });
gateway.on("connection", ws => {
  clients.add(ws);
  ws.send(JSON.stringify({ type:"hello", data:{version:state.version, capabilities:state.capabilities} }));
  ws.send(JSON.stringify({ type:"state", data:state }));
  ws.on("close", () => clients.delete(ws));
  ws.on("message", raw => { try { const m=JSON.parse(raw.toString()); if(m.type==="subscribe" && Array.isArray(m.instruments)) { state.subscriptions=m.instruments.filter(x=>x?.ExchangeSegment&&x?.SecurityId).slice(0,100); } } catch { ws.send(JSON.stringify({type:"error",error:"Invalid JSON"})); } });
});

async function startup() {
  try {
    await getToken();
    try { await loadInstruments(); } catch(e) { console.log("instrument master:", e.message); }
    await refreshExpiries();
    await refreshChain();
    await seedHistory();
    await pollQuotes();
    setInterval(() => pollQuotes().catch(()=>{}), 1000);
    setInterval(() => refreshChain().catch(()=>{}), 3500);
    setInterval(() => refreshExpiries().catch(()=>{}), 60_000);
    setInterval(() => seedHistory().catch(()=>{}), 60_000);
  } catch (e) {
    console.log("Dhan startup:", e.message);
    const delay = Math.max(15_000, tokenRetryAfter ? tokenRetryAfter - Date.now() + 1000 : 30_000);
    setTimeout(startup, delay);
  }
}
startup();
