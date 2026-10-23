# SpotSim — Multi-user paper trading backend

Each user **registers an account**. Portfolios are stored on the server. Admins control the **default starting balance** for new users and can reset/manage accounts.

## Quick start

```bash
cd spotsim-backend
npm install
npm start
```

Open **http://localhost:3847**

### Default admin

| Field | Value |
|--------|--------|
| Username | `admin` |
| Password | `admin123` |

Change these with env vars:

```bash
ADMIN_USER=myadmin ADMIN_PASS=secret PORT=3847 node server.js
```

## Features

### Users
- Register / log in
- Personal simulation balance, holdings, history
- Stop-loss / take-profit
- Live Binance prices + WebSocket candles
- Reset own account to **their** starting balance

### Admin panel (Admin button after login)
- Set **default starting balance** for all **new** registrations
- List users (balance, trades)
- Set a user’s starting balance
- Reset a user’s portfolio
- Delete users

## API overview

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/register` | — | Create user |
| POST | `/api/login` | — | Get JWT |
| GET | `/api/me` | user | Current user |
| GET/PUT | `/api/portfolio` | user | Load / save portfolio |
| POST | `/api/portfolio/reset` | user | Reset to starting balance |
| GET/PUT | `/api/admin/settings` | admin | Default starting balance |
| GET | `/api/admin/users` | admin | List users |
| PUT | `/api/admin/users/:id/balance` | admin | Set start / reset user |
| DELETE | `/api/admin/users/:id` | admin | Delete user |

## Data

SQLite database: `data/spotsim.db`

## Security notes

- Change `JWT_SECRET` and admin password in production
- This is for **paper trading only** — not real exchange orders
- Run behind HTTPS if exposed to the internet
