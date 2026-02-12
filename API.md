# Glossy-Gly-Kitchen API Reference

Base URL: `http://localhost:3000`

## Auth

### POST `/auth/signup`
Body: `email`, `password`, optional `phone`, `referralCode`

### POST `/auth/verify`
Body: `userId`, `otp`

### POST `/auth/resend-otp`
Body: `email`

### POST `/auth/google`
Body: `idToken`, optional `deviceId`, `referralCode`

### POST `/auth/apple`
Body: `identityToken`, optional `deviceId`, `referralCode`

### POST `/auth/login`
Body: `email`, `password`, optional `deviceId`

### POST `/auth/request-login-otp`
Body: `email`

### POST `/auth/login-otp`
Body: `email`, `otp`, optional `deviceId`

### POST `/auth/forgot-password/request`
Body: `email`

### POST `/auth/forgot-password/verify`
Body: `email`, `otp`  
Response includes temporary `resetToken`.

### POST `/auth/forgot-password/reset`
Body: `resetToken`, `newPassword`

### POST `/auth/delete-account/request-otp`
Headers: user bearer token  
Sends OTP to the authenticated user's email for account deletion confirmation.

### DELETE `/auth/delete-account`
Headers: user bearer token  
Body: `otp` (6 digits)  
Deletes account permanently after OTP verification.

### POST `/auth/refresh`
Body: `refreshToken`

### POST `/auth/logout`
Headers: user bearer token  
Body: `refreshToken`

### POST `/auth/logout-all`
Headers: user bearer token

### GET `/auth/me`
Headers: user bearer token

### PATCH `/auth/me`
Headers: user bearer token  
Body supports:
- `phone`
- `currentPassword` + `newPassword` (for in-app password change)

### POST `/auth/referral-code/generate`
Headers: user bearer token

## Foods

### GET `/foods`

### GET `/foods/:id`

### POST `/foods`
Headers: admin bearer token  
Body: `name`, `price`, optional `description`, `category`

### PUT `/foods/:id`
Headers: admin bearer token

### DELETE `/foods/:id`
Headers: admin bearer token

## Cart

All cart routes require user bearer token.

### POST `/cart`
Body: `foodId`, `quantity`

### GET `/cart`

### PUT `/cart`
Body: `foodId`, `quantity`

### DELETE `/cart`

## Orders

User routes require user bearer token.

### POST `/orders`

### GET `/orders`

### GET `/orders/:id`

### POST `/orders/:id/coupon/validate`
Body: `couponCode`

### POST `/orders/:id/coupon/apply`
Body: `couponCode`

### DELETE `/orders/:id/coupon`

### POST `/orders/:id/cancel`

### PATCH `/orders/:id/status`
Headers: admin bearer token  
Body: `status`

## Payments

User payment routes require user bearer token.

### POST `/payments/initialize`
Body: `orderId`, optional `callbackUrl`, `saveCard`

### GET `/payments/verify/:reference`

### POST `/payments/cards`
Body: `reference`

### GET `/payments/cards`

### PATCH `/payments/cards/:cardId/default`

### DELETE `/payments/cards/:cardId`

### POST `/payments/pay-with-saved-card`
Body: `orderId`, `cardId`

### POST `/payments/webhook/paystack`
Public webhook. Signature required via `x-paystack-signature`.

## Admin

### POST `/admin/auth/bootstrap`
Headers: `x-admin-bootstrap-key`  
Body: `email`, `password`, `fullName`, optional `role`

### POST `/admin/auth/login`
Body: `email`, `password`, optional `otp`, `deviceId`, `deviceLabel`

### POST `/admin/auth/refresh`
Body: `refreshToken`

### POST `/admin/auth/logout`
Headers: admin bearer token  
Body: `refreshToken`

### POST `/admin/auth/logout-all`
Headers: admin bearer token

### GET `/admin/me`
Headers: admin bearer token

### GET `/admin/dashboard`
Headers: admin bearer token

### POST `/admin/admins`
Headers: admin bearer token (super admin)

### GET `/admin/users`
Headers: admin bearer token

### GET `/admin/users/:id`
Headers: admin bearer token

### PATCH `/admin/users/:id/status`
Headers: admin bearer token

### GET `/admin/orders`
Headers: admin bearer token

### GET `/admin/orders/:id`
Headers: admin bearer token

### PATCH `/admin/orders/:id/status`
Headers: admin bearer token

### POST `/admin/coupons`
Headers: admin bearer token

### GET `/admin/coupons`
Headers: admin bearer token

### POST `/admin/referral-codes`
Headers: admin bearer token

### GET `/admin/referral-codes`
Headers: admin bearer token

### POST `/admin/disputes`
Headers: admin bearer token

### GET `/admin/disputes`
Headers: admin bearer token

### GET `/admin/disputes/:id`
Headers: admin bearer token

### PATCH `/admin/disputes/:id`
Headers: admin bearer token

### POST `/admin/disputes/:id/resolve`
Headers: admin bearer token

### POST `/admin/disputes/:id/comments`
Headers: admin bearer token

### GET `/admin/audit-logs`
Headers: admin bearer token

## System

### GET `/health`

### GET `/ready`
