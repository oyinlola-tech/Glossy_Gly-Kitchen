# Chuks Kitchen Food Ordering System Backend API

## Overview
Chuks Kitchen is a production-ready Node.js + Express backend for a food ordering system with email OTP verification, JWT authentication, cart management, and order processing. It uses MySQL (AMPPs) with `mysql2/promise`, Nodemailer (Gmail SMTP), UUIDs for identifiers, and includes security hardening, logging, audit trails, and readiness checks.

## Features
- Signup with email + password and optional referral code
- OTP email verification and OTP login fallback
- JWT access tokens + refresh token rotation
- Food menu management (admin protected)
- Cart management with upsert and totals
- Order creation and lifecycle management with strict transitions
- Dedicated admin system (JWT auth, user management, disputes, dashboard metrics)
- Request logging and admin audit logs
- Health and readiness endpoints

## Tech Stack
- Node.js + Express
- MySQL (AMPPs) with `mysql2/promise`
- Nodemailer (Gmail SMTP)
- UUID
- dotenv
- JWT (`jsonwebtoken`)
- bcrypt (`bcryptjs`)

## Diagrams
These diagrams are included and align with the current implementation:
- Data model: `diagrams/Data Model for assignment.png`
- User registration & OTP flow: `diagrams/User Registration & OTP Verification Flow for assignments.png`
- Order placement flow: `diagrams/Order Placement Flow.png`
- Order status lifecycle: `diagrams/Order Status Lifecycle.png`

Note: The diagrams cover the core domain model. Two operational tables (`refresh_tokens`, `audit_logs`) were added for production security and logging and do not change the core entities in the diagram.

## Prerequisites
- Node.js (18+ recommended)
- MySQL (AMPPs)
- Gmail account with App Password enabled for SMTP

## Installation
1. Clone the repository.
2. Install dependencies:

```bash
npm install
```

3. Create `.env` (copy from `.env.example` and update values):

```env
# Server
PORT=3000
NODE_ENV=development

# Security
ADMIN_API_KEY=change_me
ADMIN_BOOTSTRAP_KEY=change_me_bootstrap
JWT_SECRET=change_me
JWT_EXPIRES_IN=15m
JWT_ISSUER=chuks-kitchen
ADMIN_JWT_ISSUER=chuks-kitchen-admin
ADMIN_JWT_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_DAYS=30
ADMIN_REFRESH_TOKEN_EXPIRES_DAYS=30
PASSWORD_MIN_LENGTH=8
BCRYPT_ROUNDS=12
RATE_LIMIT_MAX=120
AUTH_RATE_LIMIT_MAX=10
ADMIN_AUTH_RATE_LIMIT_MAX=15
# CORS_ORIGIN=https://example.com,https://app.example.com
TRUST_PROXY=false
LOG_FILE=logs/app.log

# Database (AMPPs MySQL)
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=chuks_kitchen

# Email (Nodemailer – Gmail)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
EMAIL_FROM="Chuks Kitchen <your_email@gmail.com>"
```

4. Import the database schema:

```bash
mysql -u root -p < schema.sql
```

For existing databases, apply the admin-system migration instead of resetting everything:
```bash
mysql -u root -p chuks_kitchen < migrations/2026-02-12-admin-system.sql
```

5. Start the server:

```bash
npm run dev
```

## Environment Variables
| Variable | Description | Example |
| --- | --- | --- |
| `PORT` | API port | `3000` |
| `NODE_ENV` | Environment | `development` |
| `ADMIN_API_KEY` | Admin key for protected endpoints | `change_me` |
| `ADMIN_BOOTSTRAP_KEY` | Key for one-time admin bootstrap endpoint | `change_me_bootstrap` |
| `JWT_SECRET` | JWT signing secret | `change_me` |
| `JWT_EXPIRES_IN` | Access token TTL | `15m` |
| `JWT_ISSUER` | JWT issuer | `chuks-kitchen` |
| `ADMIN_JWT_ISSUER` | Admin JWT issuer | `chuks-kitchen-admin` |
| `ADMIN_JWT_EXPIRES_IN` | Admin access token TTL | `15m` |
| `REFRESH_TOKEN_EXPIRES_DAYS` | Refresh token TTL (days) | `30` |
| `ADMIN_REFRESH_TOKEN_EXPIRES_DAYS` | Admin refresh token TTL (days) | `30` |
| `PASSWORD_MIN_LENGTH` | Minimum password length | `8` |
| `BCRYPT_ROUNDS` | bcrypt salt rounds | `12` |
| `RATE_LIMIT_MAX` | Global requests/min | `120` |
| `AUTH_RATE_LIMIT_MAX` | Auth requests/10 min | `10` |
| `ADMIN_AUTH_RATE_LIMIT_MAX` | Admin auth requests/10 min | `15` |
| `CORS_ORIGIN` | Allowed origins (comma-separated) | `https://example.com` |
| `TRUST_PROXY` | Trust proxy for IPs | `false` |
| `SWAGGER_SERVER_URL` | Optional server URL shown in Swagger UI | `http://localhost:3000` |
| `LOG_FILE` | Log file output | `logs/app.log` |
| `DB_HOST` | MySQL host | `localhost` |
| `DB_USER` | MySQL user | `root` |
| `DB_PASSWORD` | MySQL password | `your_password` |
| `DB_NAME` | MySQL database | `chuks_kitchen` |
| `EMAIL_USER` | Gmail address | `your_email@gmail.com` |
| `EMAIL_PASS` | Gmail App Password | `your_app_password` |
| `EMAIL_FROM` | Sender name | `Chuks Kitchen <your_email@gmail.com>` |

## Running the App
- Development:
  - `NODE_ENV=development`
  - detailed error messages returned
- Production:
  - `NODE_ENV=production`
  - strong secrets in `.env`
  - CORS restricted with `CORS_ORIGIN`
  - logs written to `LOG_FILE`

## API Documentation
Full API reference and examples are in `API.md`.

Interactive Swagger docs are available after starting the app:
- Swagger UI: `http://localhost:3000/api-docs`
- OpenAPI JSON: `http://localhost:3000/api-docs.json`

To test protected endpoints in Swagger:
1. Click **Authorize**.
2. Set `bearerAuth` with your JWT access token as `Bearer <token>`.
3. Set `AdminApiKey` with your `x-admin-key` value for admin endpoints.
4. Set `adminBearerAuth` with your admin JWT for `/admin/*` endpoints.

## Admin API (New)
Major new admin endpoints are now available under `/admin`:
- Auth: `/admin/auth/bootstrap`, `/admin/auth/login`, `/admin/auth/refresh`, `/admin/auth/logout`, `/admin/me`
- Users: `/admin/users`, `/admin/users/:id`, `/admin/users/:id/status`
- Orders: `/admin/orders`, `/admin/orders/:id`, `/admin/orders/:id/status`
- Disputes: `/admin/disputes`, `/admin/disputes/:id`, `/admin/disputes/:id/comments`
- Dashboard: `/admin/dashboard`

## Folder Structure
```
.
├─ app.js
├─ config/
│  └─ db.js
├─ controllers/
├─ routes/
├─ utils/
├─ diagrams/
├─ schema.sql
├─ .env.example
└─ API.md
```

## Testing (Manual Examples)
1. Signup:
```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"StrongPass123!"}'
```

2. Verify OTP:
```bash
curl -X POST http://localhost:3000/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"userId":"3f0f53e2-7b4a-4c56-8b39-8a3cc24b28a1","otp":"123456"}'
```

3. Login:
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"StrongPass123!"}'
```

4. Refresh token:
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'
```

5. Add to cart:
```bash
curl -X POST http://localhost:3000/cart \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <accessToken>" \
  -d '{"foodId":"6f9edc8f-39c0-4d35-92ae-8c7ee6900b72","quantity":2}'
```

## Production Readiness Checklist
- Strong secrets set in `.env`
- `NODE_ENV=production`
- CORS restricted
- Rate limits configured
- Logging enabled (`LOG_FILE`)
- Audit logs stored in DB
- Refresh tokens stored and rotated
- Health and readiness endpoints used in monitoring

## Scalability Considerations
- Add Redis for caching menu and rate limiting.
- Use read replicas for heavy read workloads.
- Move OTP emails to background workers.
- Add CDN/object storage for images.

## System Documentation
### System Overview (End-to-End)
Chuks Kitchen is a backend API that powers user registration, menu browsing, cart management, and order processing. The full end-to-end flow is:

1. User signup with email + password (optional referral code), OTP generated and emailed.
2. OTP verification marks the user verified and issues access + refresh tokens.
3. Authenticated requests use `Authorization: Bearer <accessToken>`.
4. Menu browsing via `GET /foods`, admin endpoints manage food items.
5. Cart management: add, view, update, clear.
6. Order creation: validate availability, create order + items in a transaction, clear cart.
7. Order lifecycle managed with strict status transitions.
8. Observability: request logging, admin audit logs, health/readiness endpoints.

### Flow Explanations (Diagrams)
**User Registration & OTP Verification Flow**
1. Customer submits email/password + optional referral code.
2. Backend checks for duplicates and validates referral code.
3. OTP generated, user stored as unverified.
4. OTP emailed; user submits OTP for verification.
5. Backend validates OTP, marks user verified, issues tokens.

**Order Placement Flow**
1. Client calls `POST /orders` using access token.
2. Backend fetches cart items and food details.
3. If cart empty → 400.
4. If item unavailable → 409.
5. Total calculated, order + items inserted transactionally.
6. Cart cleared, confirmation returned.

**Order Status Lifecycle**
- Pending → Confirmed → Preparing → OutForDelivery → Completed
- Pending → Cancelled (customer/admin)
- Confirmed/Preparing → Cancelled (admin only)

**Data Model**
- User ↔ Orders / CartItems
- FoodItem ↔ CartItems / OrderItems
- Order ↔ OrderItems
- Additional production tables: `refresh_tokens`, `audit_logs`

### Edge Case Handling
- Duplicate email/phone → 409
- Invalid referral code → 400
- Invalid/expired OTP → 400
- Unverified user → 403
- Invalid/missing JWT → 401
- Refresh token invalid/revoked → 401
- Cart empty → 400
- Item unavailable → 409
- Invalid status transition → 400
- Order not found → 404
- Rate limit exceeded → 429
- Wrong content type → 415

### Assumptions
- Email is the primary identifier.
- Phone-only signup is not enabled (no SMS gateway).
- Admin access uses shared `ADMIN_API_KEY`.
- Payments and delivery integrations are out of scope.
- All environment variables in `.env.example` are provided.

### Scaling from 100 → 10,000 Users
1. Add Redis cache for menus and rate limit counters.
2. Add read replicas for read-heavy traffic.
3. Move OTP emails to background jobs.
4. Horizontal scaling with a load balancer.
5. Centralized logs + metrics (ELK, Datadog, OpenTelemetry).
6. Role-based admin accounts instead of shared admin key.

## License
ISC

## Author
OLUWAYEMI OYINLOLA MICHAEL
