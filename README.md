# Bharati Universal Backend — L20 Feed Diagnostic

Universal DhanHQ market-data gateway for multiple frontends.

## Core design
- Dhan credentials remain server-side in Render Environment Variables.
- TOTP token generation is serialized and cached; the auth endpoint is not hammered.
- Live Market Feed uses Dhan v2 WebSocket + FULL packet (RequestCode 21).
- Dedicated 20-level Full Market Depth uses RequestCode 23.
- Option Chain and historical intraday data are exposed over REST.
- Multiple frontends can connect to the same backend `/ws` endpoint.
- No order placement is included.

## Feed reliability additions
- Independent live-feed and L20-depth connection state.
- Automatic reconnect with backoff.
- WebSocket error/close reason diagnostics.
- Last-message timestamps and packet counters.
- Stale-feed watchdog: a feed with no packets for >45 seconds is terminated and reconnected.
- `/api/feed-status` exposes the detailed feed state.
- `/api/health` and `/api/status` include feed diagnostics.
- Correct Dhan v2 binary header decoding: message length is bytes 1–2 and response code is byte 3.

## Render Environment Variables
Set these in Render:
- `DHAN_CLIENT_ID`
- `DHAN_PIN`
- `DHAN_TOTP_SECRET`
- `DEFAULT_INDEX=NIFTY`

Optional:
- `DHAN_ACCESS_TOKEN` — if supplied, it is used instead of TOTP generation.

## Main endpoints
- `/api/health`
- `/api/status`
- `/api/feed-status`
- `/api/auth-status`
- `/api/config`
- `/api/state`
- `/api/ticks`
- `/api/tick`
- `/api/option-chain`
- `/api/analytics`
- `/api/depth`
- `/api/history`
- `/api/instruments`
- `/ws`

## Important frontend rule
The frontend should treat WebSocket ticks as an event stream, maintain its own stable candle buffers, and use REST history as the initial/backfill source. It should not replace the whole chart dataset on every tick.
