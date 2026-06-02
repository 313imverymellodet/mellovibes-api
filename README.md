# MelloVibes API

Tiny backend for MelloVibes: real cross-device accounts, shared invite codes, and
Jellyfin token brokering (so credentials aren't baked into the frontend).

Stack: Node + Express + Postgres.

## Endpoints
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | – | Health check |
| POST | `/api/signup` | – | Create account (needs valid invite code) |
| POST | `/api/login` | – | Log in → returns JWT |
| GET | `/api/me` | JWT | Current user |
| GET | `/api/invite-codes` | Admin | List invite codes |
| POST | `/api/invite-codes` | Admin | Create a code (`{reusable, grantsAdmin, code?}`) |
| DELETE | `/api/invite-codes/:code` | Admin | Delete a code |
| GET | `/api/jellyfin` | JWT | Get a Jellyfin token (creds stay server-side) |

---

## Deploy on Railway (GitHub flow)

### 1. Push this folder to a new GitHub repo
```bash
cd mellovibes-api
git init
git add .
git commit -m "MelloVibes API"
# create an empty repo on github.com first, then:
git remote add origin https://github.com/<you>/mellovibes-api.git
git branch -M main
git push -u origin main
```

### 2. In your Railway project (the one with Postgres)
1. Click **New** → **GitHub Repository** → pick `mellovibes-api`.
2. Railway builds it automatically (`npm install`, `npm start`).

### 3. Link the database
- In the API service → **Variables** → **New Variable** → **Add Reference** → pick the
  Postgres service's `DATABASE_URL`. (This wires the DB connection in.)

### 4. Set the other Variables (API service → Variables)
| Variable | Value |
|---|---|
| `JWT_SECRET` | a long random string |
| `FRONTEND_ORIGIN` | `https://mellovibes.io` (your Netlify URL) |
| `ADMIN_USERNAME` | `mello` |
| `ADMIN_PASSWORD` | a strong password |
| `ADMIN_NAME` | `Mello` |
| `JELLYFIN_URL` | `https://casaos.tailb5d22.ts.net` |
| `JELLYFIN_USERNAME` | `romellom` |
| `JELLYFIN_PASSWORD` | your Jellyfin password |

> You do **not** set `PORT` — Railway provides it automatically.

### 5. Get your public URL
- API service → **Settings** → **Networking** → **Generate Domain**.
- You'll get something like `https://mellovibes-api-production.up.railway.app`.
- Test it: open `<that-url>/health` → should return `{"ok":true}`.

### 6. Send me that URL
Once it's live, give me the Railway domain and I'll wire `index.html` to use it
(signup/login through the API, Jellyfin creds removed from the page).

---

## On first boot the API auto-creates
- an **admin account** from `ADMIN_USERNAME` / `ADMIN_PASSWORD`
- a reusable invite code **`MELLOVIBES`**

so you can log in and start inviting people immediately.

## Local dev (optional)
```bash
cp .env.example .env   # fill in values, point DATABASE_URL at a local Postgres
npm install
npm start              # http://localhost:3000/health
```
