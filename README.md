# Glossy-Gly-Kitchen Backend

Production-focused Node.js + Express API for food ordering, payments, and admin operations.

## Core Security Features
- JWT access + refresh tokens (user and admin domains separated)
- OTP verification flows (signup, login OTP, forgot password OTP)
- Rate limiting and OTP lockout protection
- Role-based admin authorization (admin JWT, no shared admin API key for protected operations)
- Input validation and UUID enforcement across endpoints
- Transactional operations for orders, coupons, and payment critical paths
- Webhook signature verification + replay protection
- Request IDs + structured request logging + admin audit logs

## Stack
- Node.js, Express
- MySQL (`mysql2/promise`)
- JWT (`jsonwebtoken`)
- Password hashing (`bcryptjs`)
- Mail (`nodemailer`)
- Swagger/OpenAPI (`swagger-jsdoc`, `swagger-ui-express`)

## Setup
1. Install dependencies:
```bash
npm install
```
2. Copy env:
```bash
cp .env.example .env
```
3. Start:
```bash
npm run dev
```

## Automatic DB Bootstrap (No Data Wipe)
- On startup, the app now:
1. Creates the database if it does not exist.
2. Creates required tables only if missing (`CREATE TABLE IF NOT EXISTS`).
3. Adds selected missing columns for backward compatibility.
- Existing data is preserved. No `DROP DATABASE` is executed by the app.
- Required DB privileges for first run:
1. `CREATE` on server/database.
2. `ALTER` for compatibility columns.
3. `SELECT/INSERT/UPDATE/DELETE` for normal runtime operations.

## Required Migrations For Existing DBs
Apply in order:
```bash
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-admin-system.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-coupons-and-referrals.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-order-coupon-flow.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-payments.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-saved-cards.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-webhook-replay-protection.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-user-auth-security.sql
mysql -u root -p glossy_gly_kitchen < migrations/2026-02-12-user-account-deletion.sql
```

## API Docs
- Swagger UI: `http://localhost:3000/api-docs`
- OpenAPI JSON: `http://localhost:3000/api-docs.json`
- Written API guide: `API.md`

## Authentication
- User endpoints: `Authorization: Bearer <accessToken>`
- Admin endpoints (`/admin/*`, admin actions in `/foods`, `/orders/:id/status`): `Authorization: Bearer <adminAccessToken>`
- Admin bootstrap only: `x-admin-bootstrap-key: <ADMIN_BOOTSTRAP_KEY>`

## Main Route Groups
- `/auth` user auth/profile/password flows
- `/auth/delete-account/request-otp` + `/auth/delete-account` for OTP-protected account deletion
- `/foods` menu + admin food management
- `/cart` cart management
- `/orders` order lifecycle + coupon handling
- `/payments` payment initialization/verification/saved cards/webhook
- `/admin` admin auth, users, orders, coupons, referrals, disputes, audit logs
- `/health`, `/ready` system probes

## Environment
See `.env.example` for complete keys.

## Notes
- Keep `NODE_ENV=production` in production.
- Use strong `JWT_SECRET`, `ADMIN_BOOTSTRAP_KEY`, and SMTP credentials.
- Restrict `CORS_ORIGIN` in production.
- Set `DB_CONNECT_TIMEOUT_MS` and `DB_BOOTSTRAP_LOCK_TIMEOUT_SEC` to control DB startup behavior.
- Run only one app instance during first bootstrap/migration window, or ensure DB lock timeout is configured.

## Runtime Smoke Checklist
After `npm run dev`, verify:
1. `GET /health` returns `200`.
2. `GET /ready` returns `200`.
3. `GET /api-docs.json` returns `200`.
4. Validation endpoints return expected errors (example `POST /auth/signup` with `{}` returns `400`).
5. Protected endpoints without token return `401` (example `DELETE /auth/delete-account`).
