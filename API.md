# Glossy_Gly-Kitchen Food Ordering System Backend API

## Base URL
`http://localhost:3000`

## Authentication
This API uses **JWT access tokens**. Tokens are issued on:
- `POST /auth/verify` (OTP verification)
- `POST /auth/login` (email + password)
- `POST /auth/login-otp` (email + OTP)
- `POST /auth/refresh` (refresh token rotation)

Send access tokens in the `Authorization` header:
```
Authorization: Bearer <accessToken>
```

Admin-only endpoints require an admin key:
```
x-admin-key: <ADMIN_API_KEY>
```

## Response Format
All responses are JSON.

**Success**
```json
{
  "message": "Operation successful"
}
```

**Error**
```json
{
  "error": "Invalid or expired OTP"
}
```

## HTTP Status Codes
- `200` OK
- `201` Created
- `400` Bad Request
- `401` Unauthorized
- `403` Forbidden
- `404` Not Found
- `409` Conflict
- `415` Unsupported Media Type
- `429` Too Many Requests
- `500` Internal Server Error

## Common Headers
- `Content-Type: application/json` (required for POST/PUT/PATCH)
- `Authorization: Bearer <accessToken>` (protected endpoints)
- `x-admin-key: <ADMIN_API_KEY>` (admin endpoints)
- `X-Request-Id` (optional; echo returned by API)

---

## Auth Endpoints

### POST `/auth/signup`
Register a new user and send OTP email.

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `email` | string | Yes | `user@example.com` |
| `phone` | string | No | `+2348012345678` |
| `password` | string | Yes | `StrongPass123!` |
| `referralCode` | string | No | `REF12345` |

**Success (201)**
```json
{
  "message": "User registered successfully. Please verify your account.",
  "userId": "3f0f53e2-7b4a-4c56-8b39-8a3cc24b28a1"
}
```

**Errors**
- `400` invalid email/phone/password
- `409` duplicate email/phone

**Notes**
- Phone-only signup is not supported.

---

### POST `/auth/verify`
Verify OTP and issue access + refresh tokens.

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `userId` | string (UUID) | Yes | `3f0f53e2-7b4a-4c56-8b39-8a3cc24b28a1` |
| `otp` | string | Yes | `123456` |

**Success (200)**
```json
{
  "message": "Account verified successfully.",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "9b3e07b7f3a8..."
}
```

**Errors**
- `400` Invalid or expired OTP

---

### POST `/auth/resend-otp`
Resend OTP to email.

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `email` | string | Yes | `user@example.com` |

**Success (200)**
```json
{ "message": "OTP resent successfully" }
```

**Errors**
- `404` No account found

---

### POST `/auth/login`
Login with email + password.

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `email` | string | Yes | `user@example.com` |
| `password` | string | Yes | `StrongPass123!` |

**Success (200)**
```json
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "9b3e07b7f3a8..."
}
```

**Errors**
- `400` Invalid credentials
- `403` Account not verified
- `404` Account not found

---

### POST `/auth/login-otp`
Login with email + OTP (fallback).

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `email` | string | Yes | `user@example.com` |
| `otp` | string | Yes | `123456` |

**Success (200)**
```json
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "9b3e07b7f3a8..."
}
```

---

### POST `/auth/refresh`
Rotate refresh token and get a new access token.

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `refreshToken` | string | Yes | `9b3e07b7f3a8...` |

**Success (200)**
```json
{
  "message": "Token refreshed",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "f2c420cb1d7f..."
}
```

**Errors**
- `401` Invalid/expired/revoked refresh token

---

### POST `/auth/logout`
Revoke refresh token.

**Headers**
- `Content-Type: application/json`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `refreshToken` | string | Yes | `9b3e07b7f3a8...` |

**Success (200)**
```json
{ "message": "Logged out" }
```

---

### GET `/auth/me`
Get the currently authenticated user's profile.

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "phone": "+2348012345678",
  "verified": true,
  "is_suspended": 0,
  "created_at": "2026-02-12T10:00:00.000Z",
  "updated_at": "2026-02-12T10:05:00.000Z"
}
```

---

### PATCH `/auth/me`
Update current user's profile.

**Headers**
- `Content-Type: application/json`
- `Authorization: Bearer <accessToken>`

**Body (at least one)**
| Field | Type | Notes |
| --- | --- | --- |
| `phone` | string or null | Updates/removes phone |
| `currentPassword` | string | Required for password change |
| `newPassword` | string | Required for password change |

**Success (200)**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "phone": "+2348012345678"
  }
}
```

---

## Foods Endpoints

### GET `/foods`
List available food items.

**Success (200)**
```json
[
  {
    "id": "6f9edc8f-39c0-4d35-92ae-8c7ee6900b72",
    "name": "Jollof Rice",
    "price": "12.99",
    "description": "Classic Nigerian jollof rice with fried plantains",
    "category": "Main",
    "available": 1
  }
]
```

---

### GET `/foods/:id`
Get a single available food item by ID.

**URL Params**
- `id` (UUID)

**Success (200)**
```json
{
  "id": "6f9edc8f-39c0-4d35-92ae-8c7ee6900b72",
  "name": "Jollof Rice",
  "price": "12.99",
  "description": "Classic Nigerian jollof rice with fried plantains",
  "category": "Main",
  "available": 1
}
```

**Errors**
- `404` Food item not found

---

### POST `/foods` (Admin)
Create a food item.

**Headers**
- `Content-Type: application/json`
- `x-admin-key: <ADMIN_API_KEY>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `name` | string | Yes | `Egusi Soup` |
| `price` | number | Yes | `15.99` |
| `description` | string | No | `Ground melon soup with assorted meat` |
| `category` | string | No | `Soup` |

**Success (201)**
```json
{
  "id": "8b6bce6e-3dd7-4a5a-8b97-40c2eac452aa",
  "name": "Egusi Soup",
  "price": "15.99",
  "description": "Ground melon soup with assorted meat",
  "category": "Soup",
  "available": 1
}
```

---

### PUT `/foods/:id` (Admin)
Update a food item.

**Headers**
- `Content-Type: application/json`
- `x-admin-key: <ADMIN_API_KEY>`

**URL Params**
- `id` (UUID)

**Body (any of)**
| Field | Type | Example |
| --- | --- | --- |
| `name` | string | `Pounded Yam` |
| `price` | number | `9.99` |
| `description` | string | `Smooth pounded yam` |
| `category` | string | `Swallow` |
| `available` | boolean | `true` |

**Success (200)**
```json
{
  "id": "8b6bce6e-3dd7-4a5a-8b97-40c2eac452aa",
  "name": "Pounded Yam",
  "price": "9.99",
  "available": 1
}
```

---

### DELETE `/foods/:id` (Admin)
Soft delete a food item (sets `available=0`).

**Headers**
- `x-admin-key: <ADMIN_API_KEY>`

**Success (200)**
```json
{ "message": "Food item marked as unavailable" }
```

---

## Cart Endpoints

> Requires `Authorization: Bearer <accessToken>`

### POST `/cart`
Add item to cart (upsert increments quantity).

**Headers**
- `Content-Type: application/json`
- `Authorization: Bearer <accessToken>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `foodId` | string (UUID) | Yes | `6f9edc8f-39c0-4d35-92ae-8c7ee6900b72` |
| `quantity` | number | Yes | `2` |

**Success (200)**
```json
{ "message": "Item added to cart successfully" }
```

---

### GET `/cart`
View cart items and totals.

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{
  "userId": "3f0f53e2-7b4a-4c56-8b39-8a3cc24b28a1",
  "items": [
    {
      "food_id": "6f9edc8f-39c0-4d35-92ae-8c7ee6900b72",
      "name": "Jollof Rice",
      "price": "12.99",
      "quantity": 2,
      "subtotal": "25.98",
      "available": 1
    }
  ],
  "total": "25.98"
}
```

---

### PUT `/cart`
Update quantity or remove item by setting quantity to 0.

**Headers**
- `Content-Type: application/json`
- `Authorization: Bearer <accessToken>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `foodId` | string (UUID) | Yes | `6f9edc8f-39c0-4d35-92ae-8c7ee6900b72` |
| `quantity` | number | Yes | `1` |

**Success (200)**
```json
{ "message": "Cart updated successfully" }
```

---

### DELETE `/cart`
Clear entire cart.

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{ "message": "Cart cleared successfully" }
```

---

## Orders Endpoints

> Requires `Authorization: Bearer <accessToken>`

### GET `/orders`
List current user's orders with optional pagination/filtering.

**Query Params (optional)**
- `status` (e.g. `pending`)
- `page` (default `1`)
- `limit` (default `20`, max `100`)

**Success (200)**
```json
{
  "page": 1,
  "limit": 20,
  "total": 3,
  "orders": [
    {
      "id": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e",
      "user_id": "3f0f53e2-7b4a-4c56-8b39-8a3cc24b28a1",
      "total_amount": "25.98",
      "status": "pending",
      "created_at": "2026-02-12T10:00:00.000Z",
      "updated_at": "2026-02-12T10:00:00.000Z"
    }
  ]
}
```

---

### POST `/orders`
Create order from cart (transactional, validates availability).

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (201)**
```json
{
  "orderId": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e",
  "status": "pending",
  "total": "25.98"
}
```

---

### GET `/orders/:id`
Fetch order details (only owner can access).

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{
  "id": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e",
  "user_id": "3f0f53e2-7b4a-4c56-8b39-8a3cc24b28a1",
  "status": "pending",
  "total_amount": "25.98",
  "items": [
    {
      "food_id": "6f9edc8f-39c0-4d35-92ae-8c7ee6900b72",
      "quantity": 2,
      "price_at_order": "12.99",
      "name": "Jollof Rice"
    }
  ]
}
```

---

### PATCH `/orders/:id/status` (Admin)
Update order status (valid transitions only).

**Headers**
- `Content-Type: application/json`
- `x-admin-key: <ADMIN_API_KEY>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `status` | string | Yes | `confirmed` |

**Success (200)**
```json
{
  "message": "Order status updated successfully",
  "orderId": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e",
  "newStatus": "confirmed"
}
```

---

### POST `/orders/:id/cancel`
Cancel a pending order (customer).

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{ "message": "Order cancelled successfully" }
```

---

## Payments Endpoints

> Requires `Authorization: Bearer <accessToken>` unless stated otherwise.

### POST `/payments/initialize`
Initialize Paystack transaction for an order.

**Headers**
- `Content-Type: application/json`
- `Authorization: Bearer <accessToken>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `orderId` | string (UUID) | Yes | `5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e` |
| `callbackUrl` | string (URL) | No | `https://your-frontend.app/payments/callback` |
| `saveCard` | boolean | No | `true` |

**Success (201)**
```json
{
  "message": "Payment initialized successfully",
  "orderId": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e",
  "reference": "PSK-5f163fbe-1700000000000",
  "authorizationUrl": "https://checkout.paystack.com/...",
  "accessCode": "ACCESS_xxx",
  "saveCard": true
}
```

---

### POST `/payments/cards`
Save a reusable card from a successful payment reference.

**Headers**
- `Content-Type: application/json`
- `Authorization: Bearer <accessToken>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `reference` | string | Yes | `PSK-5f163fbe-1700000000000` |

**Success (201)**
```json
{
  "message": "Card saved successfully",
  "card": {
    "id": "2b9e9c45-9f30-4b1a-8c84-39d641de72ad",
    "provider": "paystack",
    "last4": "4242",
    "exp_month": "09",
    "exp_year": "2030",
    "card_type": "visa",
    "bank": "GTBank",
    "account_name": "John Doe",
    "is_default": 1
  }
}
```

---

### GET `/payments/cards`
List saved cards for the authenticated user.

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{
  "cards": [
    {
      "id": "2b9e9c45-9f30-4b1a-8c84-39d641de72ad",
      "provider": "paystack",
      "last4": "4242",
      "exp_month": "09",
      "exp_year": "2030",
      "card_type": "visa",
      "bank": "GTBank",
      "account_name": "John Doe",
      "is_default": 1
    }
  ]
}
```

---

### DELETE `/payments/cards/:cardId`
Delete a saved card.

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{ "message": "Card removed successfully" }
```

---

### POST `/payments/pay-with-saved-card`
Automatically debit a saved card for an order.

**Headers**
- `Content-Type: application/json`
- `Authorization: Bearer <accessToken>`

**Body**
| Field | Type | Required | Example |
| --- | --- | --- | --- |
| `orderId` | string (UUID) | Yes | `5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e` |
| `cardId` | string (UUID) | Yes | `2b9e9c45-9f30-4b1a-8c84-39d641de72ad` |

**Success (201)**
```json
{
  "message": "Payment completed with saved card",
  "orderId": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e",
  "reference": "PSK-AUTO-5f163fbe-1700000000000",
  "status": "success"
}
```

---

### GET `/payments/verify/:reference`
Verify transaction status with Paystack and confirm payment internally.

**Headers**
- `Authorization: Bearer <accessToken>`

**Success (200)**
```json
{
  "message": "Payment verification completed",
  "reference": "PSK-5f163fbe-1700000000000",
  "status": "success",
  "orderId": "5f163fbe-8e1b-4b06-a5f0-7d86a74e2a9e"
}
```

---

### POST `/payments/webhook/paystack`
Paystack webhook receiver (public endpoint).

**Headers**
- `x-paystack-signature: <hmac_sha512_signature>`

**Notes**
- Signature is validated against `PAYSTACK_WEBHOOK_SECRET`.
- On successful charge event, payment is marked `success` and order is moved from `pending` to `confirmed`.
- Payment receipts are emailed via Nodemailer for successful and failed/declined attempts.

---

## System Endpoints

### GET `/health`
Basic health check.

**Success (200)**
```json
{ "status": "OK", "timestamp": "2026-02-12T10:00:00.000Z" }
```

### GET `/ready`
Readiness check (verifies DB connectivity).

**Success (200)**
```json
{ "status": "READY", "timestamp": "2026-02-12T10:00:00.000Z" }
```

**Errors**
- `503` Database not ready

---

## Admin Endpoints (Additional System)

> Uses admin JWT auth for `/admin/*` operations.
> Bootstrap requires `x-admin-bootstrap-key: <ADMIN_BOOTSTRAP_KEY>`.

### POST `/admin/auth/bootstrap`
Create the first admin account (or seed admin accounts in controlled setups).

### POST `/admin/auth/login`
Admin login with email/password. If the login is from a new device or changed IP, OTP verification is required.

### POST `/admin/auth/refresh`
Rotate admin refresh token and get new admin access token.

### POST `/admin/auth/logout`
Revoke admin refresh token.

### GET `/admin/me`
Get current admin profile (requires admin bearer token).

### GET `/admin/dashboard`
Admin metrics summary for users, orders, and disputes.

### GET `/admin/users`
List users with filters (`search`, `verified`, `suspended`, `page`, `limit`).

### GET `/admin/users/:id`
Get user details with aggregated order stats.

### PATCH `/admin/users/:id/status`
Update user moderation status using:
- `verified` (boolean)
- `isSuspended` (boolean)

### GET `/admin/orders`
List all orders with filters (`status`, `userId`, `page`, `limit`).

### GET `/admin/orders/:id`
Get order details with order items.

### PATCH `/admin/orders/:id/status`
Update order lifecycle status (valid transitions enforced).

### POST `/admin/disputes`
Create a dispute ticket tied to an order/user (optional linkage).

### GET `/admin/disputes`
List disputes with filters (`status`, `priority`, `assignedAdminId`, `page`, `limit`).

### GET `/admin/disputes/:id`
Get dispute details and comments.

### PATCH `/admin/disputes/:id`
Update dispute fields such as `status`, `priority`, `assignedAdminId`, `resolutionNotes`.

### POST `/admin/disputes/:id/comments`
Add internal/external admin comment to a dispute.

### POST `/admin/disputes/:id/resolve`
Resolve a dispute explicitly with required resolution notes.

### GET `/admin/audit-logs`
List admin activity logs for admin UI/audit pages (supports pagination and filters).

---

## Data Models

### User
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "phone": "+2348012345678",
  "password_hash": "bcrypt_hash",
  "referral_code": "REF12345",
  "referred_by": "uuid",
  "verified": true,
  "otp_code": "123456",
  "otp_expires": "2026-02-12T12:00:00.000Z",
  "created_at": "2026-02-12T10:00:00.000Z",
  "updated_at": "2026-02-12T10:05:00.000Z"
}
```

### FoodItem
```json
{
  "id": "uuid",
  "name": "Jollof Rice",
  "price": "12.99",
  "description": "Classic Nigerian jollof rice with fried plantains",
  "category": "Main",
  "available": 1,
  "created_at": "2026-02-12T10:00:00.000Z",
  "updated_at": "2026-02-12T10:05:00.000Z"
}
```

### CartItem
```json
{
  "food_id": "uuid",
  "name": "Jollof Rice",
  "price": "12.99",
  "quantity": 2,
  "subtotal": "25.98",
  "available": 1
}
```

### Order
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "total_amount": "25.98",
  "status": "pending",
  "created_at": "2026-02-12T10:00:00.000Z",
  "updated_at": "2026-02-12T10:05:00.000Z"
}
```

### OrderItem
```json
{
  "id": "uuid",
  "order_id": "uuid",
  "food_id": "uuid",
  "quantity": 2,
  "price_at_order": "12.99"
}
```

### RefreshToken
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "token_hash": "sha256",
  "expires_at": "2026-03-13T10:00:00.000Z",
  "revoked_at": null
}
```

### AuditLog
```json
{
  "id": "uuid",
  "admin_key_hash": "sha256",
  "action": "food.create",
  "method": "POST",
  "path": "/foods",
  "status_code": 201,
  "ip_address": "127.0.0.1",
  "user_agent": "PostmanRuntime/7.36.0",
  "entity_id": "uuid",
  "duration_ms": 42,
  "request_id": "uuid",
  "created_at": "2026-02-12T10:00:00.000Z"
}
```

---

## Error Codes Reference
| Error Message | Meaning |
| --- | --- |
| `Email or phone number is required` | Missing contact fields on signup |
| `Invalid email address` | Email format invalid |
| `Invalid phone number` | Phone format invalid |
| `Password must be at least X characters` | Password too short |
| `Email or phone already registered` | Duplicate email/phone |
| `Invalid or expired OTP` | OTP failed validation |
| `No account found with this email` | Email not found |
| `Invalid credentials` | Wrong email/password |
| `Authorization token required` | Missing JWT |
| `Invalid token` | JWT invalid/expired |
| `Refresh token expired` | Refresh token expired |
| `Refresh token revoked` | Refresh token revoked |
| `Food item not found` | Invalid food id |
| `Food item is not available` | Unavailable food |
| `Cart is empty` | No items in cart |
| `Some items are no longer available` | Availability changed |
| `Cannot transition order...` | Invalid status transition |
| `Order not found` | Invalid order ID |
| `Unauthorized` | Missing/invalid admin key |
| `Origin not allowed` | CORS origin blocked |
| `Content-Type must be application/json` | Wrong content type |
| `Too many requests` | Rate limit exceeded |
