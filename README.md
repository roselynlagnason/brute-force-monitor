# Vigilix — Brute Force Monitor

A login page that records **who is visiting and trying to sign in** (IP address, ISP, location), plus an admin console to investigate and block them.

## What it does

**Login page**
- Records every visit and every sign-in attempt with the visitor's real IP, ISP and location.
- No account can sign in. Every attempt is logged as failed (it is a monitor / honeypot). Only the *username* is stored, never the password.
- Lockout is enforced on the **server**: 5 failed attempts in 60 s locks that IP (and that username) until the window passes.

**Admin console**
- **Overview**: totals, activity-over-time chart (with table view), location map, recent activity, most targeted usernames.
- **Threat map**: world map of attackers and a "Top sources" table with threat flags.
- **IP details** (click any IP): ASN, ISP, organization, domain, country/region/city, postal, coordinates, timezone, mini map, full history from that IP, usernames tried, investigation status + notes, **Block / Unblock**.
- **Threat flags**: VPN / proxy / Tor, data center, mobile network, password spraying, targeted brute force.
- **Login activity**: search, filters, pagination, CSV export, date range (24 h / 7 d / 30 d / all / custom).
- **Blocked IPs**: manage the block list.
- **Alerts**: notifications to Discord / Telegram / webhook when one IP reaches 10 failures in 5 minutes. History is kept in the dashboard.
- Dark mode, mobile friendly.
- Admin password is **hashed**, admin sign-in is rate limited and audited, and the session signs out after 15 minutes of inactivity.

## Run it locally

Requires **Node.js 22.13 or newer** (uses the built-in SQLite).

```bash
npm install
npm run server      # terminal 1: API + database on http://localhost:3001
npm run dev         # terminal 2: the app on http://localhost:5173
```

Open `http://localhost:5173`. Admin console: the **Admin console** link at the top right.

Default admin login (change it, see below): username `admin`, password `Admin123!`

> On your own computer every visitor shows as `127.0.0.1` (no location). Real IPs, ISPs and map dots appear when other people reach the app: over your Wi-Fi (`http://<your-LAN-IP>:5173`, but those are private addresses) or, best, once it is [deployed](DEPLOY.md).

## Configuration (`.env`)

Copy `.env.example` to `.env` and edit. Restart the server after changes.

| Setting | Purpose |
|---|---|
| `ADMIN_USER`, `ADMIN_PASS_HASH` | Admin login. Generate the hash with `npm run hash-password -- "your password"` and paste the printed line. |
| `ADMIN_IDLE_MIN` | Minutes of inactivity before the admin session ends (default 15). |
| `TRUST_PROXY=1` | Set **only** behind a proxy / hosting platform so the real visitor IP is read from `X-Forwarded-For`. |
| `MAX_FAILS`, `LOCK_WINDOW_SEC` | Lockout rule (default 5 failures / 60 s). |
| `ALERT_THRESHOLD`, `ALERT_WINDOW_MIN` | When to raise an alert (default 10 failures / 5 min per IP). |
| `DISCORD_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, `ALERT_WEBHOOK_URL` | Alert channels (all optional). Use **Alerts → Send test alert** to check them. |
| `DATA_DIR` | Where the SQLite database is stored (default `./data`). |

## Notes

- Data lives in `data/loginguard.db` (SQLite). If you have an old `events.json` from the first version, it is imported automatically on first start.
- Location data comes from the free ip-api.com service (needs internet; free tier is for non-commercial use and is rate limited, results are cached). Map tiles come from OpenStreetMap.
- IP geolocation is approximate (usually city level) and points at the visitor's ISP / router, not an exact person or address.
- Email alerts are not built in. Use the webhook channel with an email-forwarding service, or Discord / Telegram.
- Only log and block traffic to a system you own or are authorized to monitor.

## Deploying

See [DEPLOY.md](DEPLOY.md) (Render / Railway / VPS / Docker).
