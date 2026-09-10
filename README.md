# Bharati Simple RSI Backend

A deliberately simple DhanHQ backend for the Bharati RSI PWA.

## What it uses
- Dhan REST Market Quote `/marketfeed/ltp` once per second.
- Dhan Option Chain about every 3.5 seconds.
- Dhan Intraday History for 1-minute candle backfill.
- A normal WebSocket from this backend to the PWA, so the PWA does not need Dhan credentials.
- Server-side 1-minute candle building from the REST LTP stream.

## What it does NOT use
- No Dhan Live Market Feed WebSocket.
- No 20-level market depth.
- No binary Dhan packet decoder.
- No order placement.

This is sufficient for RSI crossover + HMA + pullback style signals. It is not a replacement for tick-level/order-book strategies.

## Important
Dhan's Market Quote API is real-time at request time and is limited to 1 request/second. This backend therefore targets approximately 1-second LTP updates, not exchange tick-by-tick delivery.

For the most reliable authentication, you can set `DHAN_ACCESS_TOKEN` directly. Otherwise the backend generates a token with TOTP and caches it; it does not repeatedly hit the token endpoint.

## Frontend contract
- GET `/api/health`
- GET `/api/status`
- GET `/api/config`
- GET `/api/state`
- GET `/api/tick`
- GET `/api/ticks`
- GET `/api/history`
- GET `/api/option-chain`
- GET `/api/analytics`
- GET `/api/feed-status`
- POST `/api/index` `{ "index": "NIFTY" }`
- POST `/api/expiry/select` `{ "expiry": "YYYY-MM-DD" }`
- WebSocket `/ws`

WebSocket event types:
`hello`, `state`, `status`, `tick`, `candle`, `optionChain`, `analytics`, `error`.

## Signal-engine recommendation
For RSI(5), RSI EMA/SMA, HMA and pullback signals, evaluate signals on CLOSED 1-minute candles. Use the live LTP only for the current forming candle and for display/early-warning. This prevents intrabar RSI/HMA flicker from becoming false confirmed signals.
