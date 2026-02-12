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
3. Create database schema:
```bash
mysql -u root -p < schema.sql
```
4. Start:
```bash
npm run dev
```

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
