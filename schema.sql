-- Drop database if exists (be careful in production!)
DROP DATABASE IF EXISTS glossy_gly_kitchen;
CREATE DATABASE glossy_gly_kitchen;
USE glossy_gly_kitchen;

-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password_hash VARCHAR(255),      -- not used in this prototype
    referral_code VARCHAR(20) UNIQUE,
    referred_by VARCHAR(36),
    verified BOOLEAN DEFAULT FALSE,
    otp_code VARCHAR(6),
    otp_expires DATETIME,
    is_suspended BOOLEAN DEFAULT FALSE,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (referred_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Social login identities
CREATE TABLE user_social_accounts (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider ENUM('google','apple') NOT NULL,
    provider_user_id VARCHAR(191) NOT NULL,
    email VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_provider_user (provider, provider_user_id),
    UNIQUE KEY unique_user_provider (user_id, provider),
    INDEX idx_social_accounts_user (user_id)
);

-- Food items
CREATE TABLE food_items (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    available BOOLEAN DEFAULT TRUE,
    created_at DATETIME,
    updated_at DATETIME
);

-- Cart items (composite unique key prevents duplicate entries)
CREATE TABLE cart_items (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    food_id VARCHAR(36) NOT NULL,
    quantity INT NOT NULL,
    added_at DATETIME,
    UNIQUE KEY unique_user_food (user_id, food_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (food_id) REFERENCES food_items(id) ON DELETE CASCADE
);

-- Orders
CREATE TABLE orders (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    total_amount DECIMAL(10,2) NOT NULL,
    discount_amount DECIMAL(10,2) DEFAULT 0,
    payable_amount DECIMAL(10,2),
    coupon_id VARCHAR(36),
    coupon_code VARCHAR(40),
    coupon_discount_type ENUM('percentage','fixed'),
    coupon_discount_value DECIMAL(10,2),
    status ENUM('pending','confirmed','preparing','out_for_delivery','completed','cancelled') DEFAULT 'pending',
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_orders_coupon_id (coupon_id),
    INDEX idx_orders_coupon_code (coupon_code)
);

-- Order items (snapshot of price at order time)
CREATE TABLE order_items (
    id VARCHAR(36) PRIMARY KEY,
    order_id VARCHAR(36) NOT NULL,
    food_id VARCHAR(36) NOT NULL,
    quantity INT NOT NULL,
    price_at_order DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (food_id) REFERENCES food_items(id)
);

-- Payments
CREATE TABLE payments (
    id VARCHAR(36) PRIMARY KEY,
    order_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    provider ENUM('paystack') DEFAULT 'paystack',
    reference VARCHAR(120) NOT NULL UNIQUE,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'NGN',
    status ENUM('initialized','success','failed','abandoned') DEFAULT 'initialized',
    gateway_response TEXT,
    paid_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_payments_order (order_id),
    INDEX idx_payments_user (user_id),
    INDEX idx_payments_status (status)
);

-- Coupons
CREATE TABLE coupons (
    id VARCHAR(36) PRIMARY KEY,
    code VARCHAR(40) NOT NULL UNIQUE,
    description VARCHAR(255),
    discount_type ENUM('percentage','fixed') NOT NULL,
    discount_value DECIMAL(10,2) NOT NULL,
    max_redemptions INT,
    redemptions_count INT DEFAULT 0,
    starts_at DATETIME,
    expires_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    created_by_admin_id VARCHAR(36),
    created_at DATETIME,
    updated_at DATETIME,
    INDEX idx_coupons_created_by_admin (created_by_admin_id),
    INDEX idx_coupons_active (is_active),
    INDEX idx_coupons_expires_at (expires_at)
);

CREATE TABLE coupon_redemptions (
    id VARCHAR(36) PRIMARY KEY,
    coupon_id VARCHAR(36) NOT NULL,
    order_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    status ENUM('reserved','consumed','released') DEFAULT 'reserved',
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (coupon_id) REFERENCES coupons(id) ON DELETE CASCADE,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_coupon_order (coupon_id, order_id),
    UNIQUE KEY unique_order_coupon_assignment (order_id),
    INDEX idx_coupon_redemptions_coupon_status (coupon_id, status),
    INDEX idx_coupon_redemptions_user (user_id)
);

-- Webhook event receipts (replay protection)
CREATE TABLE webhook_event_receipts (
    id VARCHAR(36) PRIMARY KEY,
    provider ENUM('paystack') NOT NULL,
    event_id VARCHAR(120),
    reference VARCHAR(120),
    signature_hash VARCHAR(64) NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    first_seen_at DATETIME NOT NULL,
    processed_at DATETIME,
    UNIQUE KEY unique_provider_signature (provider, signature_hash),
    INDEX idx_webhook_event_ref (provider, reference),
    INDEX idx_webhook_event_event_id (provider, event_id)
);

-- Saved payment cards (tokenized by Paystack authorization code)
CREATE TABLE user_payment_cards (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider ENUM('paystack') DEFAULT 'paystack',
    authorization_code VARCHAR(255) NOT NULL,
    signature VARCHAR(255) NOT NULL,
    last4 VARCHAR(4),
    exp_month VARCHAR(2),
    exp_year VARCHAR(4),
    card_type VARCHAR(50),
    bank VARCHAR(120),
    account_name VARCHAR(120),
    reusable BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE,
    last_used_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_card_signature (user_id, signature),
    INDEX idx_user_payment_cards_user (user_id)
);

-- Audit logs for admin actions
CREATE TABLE audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    admin_key_hash VARCHAR(64) NOT NULL,
    action VARCHAR(100) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(255) NOT NULL,
    status_code INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    entity_id VARCHAR(36),
    duration_ms INT,
    request_id VARCHAR(36),
    created_at DATETIME
);

-- Refresh tokens
CREATE TABLE refresh_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    created_ip VARCHAR(45),
    user_agent VARCHAR(255),
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_token_hash (token_hash)
);

-- User trusted devices (for login anomaly alerts)
CREATE TABLE user_trusted_devices (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    last_ip VARCHAR(45),
    last_user_agent VARCHAR(255),
    last_seen_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_device (user_id, device_hash),
    INDEX idx_user_devices_user (user_id)
);

-- Password reset OTP challenges
CREATE TABLE user_password_reset_otps (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    otp_expires DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_password_reset_otps_lookup (user_id, consumed_at, otp_expires)
);

-- Password reset one-time sessions after OTP verification
CREATE TABLE user_password_reset_sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_password_reset_token_hash (token_hash),
    INDEX idx_password_reset_sessions_user (user_id, consumed_at, expires_at)
);

-- Admin users for role-based back-office access
CREATE TABLE admin_users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin','operations_admin','support_admin') DEFAULT 'support_admin',
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME
);

-- Admin refresh tokens (separate trust domain from customer tokens)
CREATE TABLE admin_refresh_tokens (
    id VARCHAR(36) PRIMARY KEY,
    admin_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    created_ip VARCHAR(45),
    user_agent VARCHAR(255),
    created_at DATETIME,
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_admin_token_hash (token_hash)
);

-- Trusted admin devices to determine when OTP step-up is required
CREATE TABLE admin_trusted_devices (
    id VARCHAR(36) PRIMARY KEY,
    admin_id VARCHAR(36) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    device_label VARCHAR(255),
    last_ip VARCHAR(45),
    last_seen_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_admin_device (admin_id, device_hash)
);

-- OTP challenges for admin step-up login verification
CREATE TABLE admin_login_otps (
    id VARCHAR(36) PRIMARY KEY,
    admin_id VARCHAR(36) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    otp_expires DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME,
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    INDEX idx_admin_otp_lookup (admin_id, device_hash, ip_address, consumed_at)
);

-- Disputes for support/escalation workflows
CREATE TABLE disputes (
    id VARCHAR(36) PRIMARY KEY,
    order_id VARCHAR(36),
    user_id VARCHAR(36),
    raised_by_type ENUM('user','admin','system') DEFAULT 'admin',
    raised_by_id VARCHAR(36),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status ENUM('open','investigating','resolved','rejected','closed') DEFAULT 'open',
    priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
    category VARCHAR(100),
    assigned_admin_id VARCHAR(36),
    resolution_notes TEXT,
    resolved_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_admin_id) REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE TABLE dispute_comments (
    id VARCHAR(36) PRIMARY KEY,
    dispute_id VARCHAR(36) NOT NULL,
    author_type ENUM('admin','user','system') DEFAULT 'admin',
    author_id VARCHAR(36),
    is_internal BOOLEAN DEFAULT TRUE,
    comment TEXT NOT NULL,
    created_at DATETIME,
    FOREIGN KEY (dispute_id) REFERENCES disputes(id) ON DELETE CASCADE
);

-- Sample data (optional)
INSERT INTO food_items (id, name, price, description, category, available, created_at, updated_at)
VALUES 
    (UUID(), 'Jollof Rice', 12.99, 'Classic Nigerian jollof rice with fried plantains', 'Main', true, NOW(), NOW()),
    (UUID(), 'Egusi Soup', 15.99, 'Ground melon soup with assorted meat', 'Soup', true, NOW(), NOW()),
    (UUID(), 'Pounded Yam', 8.99, 'Smooth pounded yam', 'Swallow', true, NOW(), NOW()),
    (UUID(), 'Chicken Suya', 10.99, 'Spicy grilled chicken skewers', 'Grill', true, NOW(), NOW()),
    (UUID(), 'Fried Rice Combo', 13.99, 'Nigerian fried rice served with chicken and coleslaw', 'Main', true, NOW(), NOW()),
    (UUID(), 'Pepper Soup', 11.49, 'Hot and spicy assorted meat pepper soup', 'Soup', true, NOW(), NOW()),
    (UUID(), 'Moi Moi', 4.99, 'Steamed bean pudding rich in flavor', 'Sides', true, NOW(), NOW()),
    (UUID(), 'Plantain & Gizzard', 9.49, 'Fried ripe plantain tossed with spicy gizzard', 'Sides', true, NOW(), NOW()),
    (UUID(), 'Asun Bowl', 12.49, 'Peppered goat meat served with onions and peppers', 'Grill', true, NOW(), NOW()),
    (UUID(), 'Ofada Rice & Sauce', 14.29, 'Ofada rice paired with signature ayamase sauce', 'Main', true, NOW(), NOW()),
    (UUID(), 'Puff Puff (6pcs)', 3.99, 'Freshly fried sweet puff puff balls', 'Dessert', true, NOW(), NOW()),
    (UUID(), 'Zobo Drink', 2.99, 'Chilled hibiscus drink with citrus notes', 'Beverage', true, NOW(), NOW());
