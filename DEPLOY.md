# Deploying Vigilix

In production **one Node process does everything**: it serves the built React app and the API, and stores data in SQLite. The map and ISP data only become meaningful once the app is reachable from the public internet.

```bash
npm install
npm run build      # builds the React app into dist/
npm start          # serves app + API on $PORT (default 3001)
```

## Required settings (all hosts)

| Variable | Value |
|---|---|
| `TRUST_PROXY` | `1` (hosting platforms put a proxy in front, so the real visitor IP is in `X-Forwarded-For`) |
| `ADMIN_PASS_HASH` | from `npm run hash-password -- "your password"` |
| `DATA_DIR` | a **persistent** folder/disk, otherwise the database is wiped on every redeploy |
| `NODE_VERSION` | 22.13 or newer (24 recommended) |

Optional: `DISCORD_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, `ALERT_WEBHOOK_URL` (see README).

## Render

1. New → **Web Service** → connect your repo.
2. Build command: `npm install && npm run build`. Start command: `npm start`.
3. Add the environment variables above. Set `NODE_VERSION=24`.
4. Add a **Disk** (paid plans) mounted at `/data` and set `DATA_DIR=/data`. Without a disk, data resets on deploy.

## Railway

1. New project → deploy from repo. Railway auto-detects Node.
2. Variables: as in the table. Add a **Volume** mounted at `/data`, set `DATA_DIR=/data`.
3. Build `npm run build`, start `npm start` (set in Settings if not detected).

## Docker / any VPS

```bash
docker build -t loginguard .
docker run -d --name loginguard -p 3001:3001 -v loginguard-data:/data \
  -e TRUST_PROXY=1 -e ADMIN_PASS_HASH='scrypt$...' loginguard
```

Put it behind HTTPS (Caddy or nginx). Minimal nginx server block:

```nginx
server {
  server_name your-domain.example;
  location / {
    proxy_pass http://127.0.0.1:3001;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, never append client-supplied values
  }
}
```

Use `$remote_addr` (not `$proxy_add_x_forwarded_for`) so a visitor cannot forge their IP. With Cloudflare in front, only enable `TRUST_PROXY` if the origin accepts traffic from Cloudflare only.

## After deploying

1. Open the site and the admin console, sign in with your admin password.
2. **Alerts → Send test alert** to confirm your notification channel.
3. Visit the login page from your phone (mobile data) and check that your visit shows a real IP, ISP and a map dot.
4. Back up `DATA_DIR/loginguard.db` periodically.
