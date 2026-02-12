const mysql = require('mysql2/promise');

const isSafeIdentifier = (value) => typeof value === 'string' && /^[A-Za-z0-9_]+$/.test(value);

const TABLE_DEFINITIONS = [
  `CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password_hash VARCHAR(255),
    referral_code VARCHAR(20) UNIQUE,
    referred_by VARCHAR(36),
    verified BOOLEAN DEFAULT FALSE,
    otp_code VARCHAR(6),
    otp_expires DATETIME,
    is_suspended BOOLEAN DEFAULT FALSE,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (referred_by) REFERENCES users(id) ON DELETE SET NULL
  )`,
  `CREATE TABLE IF NOT EXISTS user_social_accounts (
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
  )`,
  `CREATE TABLE IF NOT EXISTS food_items (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    available BOOLEAN DEFAULT TRUE,
    created_at DATETIME,
    updated_at DATETIME
  )`,
  `CREATE TABLE IF NOT EXISTS orders (
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
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_orders_coupon_id (coupon_id),
    INDEX idx_orders_coupon_code (coupon_code)
  )`,
  `CREATE TABLE IF NOT EXISTS cart_items (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    food_id VARCHAR(36) NOT NULL,
    quantity INT NOT NULL,
    added_at DATETIME,
    UNIQUE KEY unique_user_food (user_id, food_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (food_id) REFERENCES food_items(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS order_items (
    id VARCHAR(36) PRIMARY KEY,
    order_id VARCHAR(36) NOT NULL,
    food_id VARCHAR(36) NOT NULL,
    quantity INT NOT NULL,
    price_at_order DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (food_id) REFERENCES food_items(id)
  )`,
  `CREATE TABLE IF NOT EXISTS coupons (
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
  )`,
  `CREATE TABLE IF NOT EXISTS coupon_redemptions (
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
  )`,
  `CREATE TABLE IF NOT EXISTS payments (
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
  )`,
  `CREATE TABLE IF NOT EXISTS webhook_event_receipts (
    id CHAR(36) NOT NULL,
    provider ENUM('paystack') NOT NULL,
    event_id VARCHAR(120) NULL,
    reference VARCHAR(120) NULL,
    signature_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    payload_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    first_seen_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    processed_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_webhook_receipts_provider_signature (provider, signature_hash),
    UNIQUE KEY uq_webhook_receipts_provider_event (provider, event_id),
    UNIQUE KEY uq_webhook_receipts_provider_payload (provider, payload_hash),
    INDEX idx_webhook_receipts_provider_reference (provider, reference),
    INDEX idx_webhook_receipts_processed_at (processed_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
  `CREATE TABLE IF NOT EXISTS user_payment_cards (
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
  )`,
  `CREATE TABLE IF NOT EXISTS audit_logs (
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
  )`,
  `CREATE TABLE IF NOT EXISTS refresh_tokens (
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
  )`,
  `CREATE TABLE IF NOT EXISTS user_trusted_devices (
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
  )`,
  `CREATE TABLE IF NOT EXISTS user_password_reset_otps (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    otp_expires DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_password_reset_otps_lookup (user_id, consumed_at, otp_expires)
  )`,
  `CREATE TABLE IF NOT EXISTS user_password_reset_sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_password_reset_token_hash (token_hash),
    INDEX idx_password_reset_sessions_user (user_id, consumed_at, expires_at)
  )`,
  `CREATE TABLE IF NOT EXISTS user_account_deletion_otps (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    otp_expires DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_account_deletion_otps_lookup (user_id, consumed_at, otp_expires)
  )`,
  `CREATE TABLE IF NOT EXISTS admin_users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin','operations_admin','support_admin') DEFAULT 'support_admin',
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME
  )`,
  `CREATE TABLE IF NOT EXISTS admin_refresh_tokens (
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
  )`,
  `CREATE TABLE IF NOT EXISTS admin_trusted_devices (
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
  )`,
  `CREATE TABLE IF NOT EXISTS admin_login_otps (
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
  )`,
  `CREATE TABLE IF NOT EXISTS disputes (
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
  )`,
  `CREATE TABLE IF NOT EXISTS dispute_comments (
    id VARCHAR(36) PRIMARY KEY,
    dispute_id VARCHAR(36) NOT NULL,
    author_type ENUM('admin','user','system') DEFAULT 'admin',
    author_id VARCHAR(36),
    is_internal BOOLEAN DEFAULT TRUE,
    comment TEXT NOT NULL,
    created_at DATETIME,
    FOREIGN KEY (dispute_id) REFERENCES disputes(id) ON DELETE CASCADE
  )`,
];

const ensureColumnExists = async ({ connection, dbName, tableName, columnName, definition }) => {
  const [rows] = await connection.query(
    `SELECT 1
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = ?
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [dbName, tableName, columnName]
  );

  if (rows.length === 0) {
    await connection.query(`ALTER TABLE \`${tableName}\` ADD COLUMN ${definition}`);
  }
};

const ensureDatabaseAndTables = async () => {
  const host = process.env.DB_HOST;
  const port = Number(process.env.DB_PORT) || 3306;
  const user = process.env.DB_USER;
  const password = process.env.DB_PASSWORD;
  const dbName = process.env.DB_NAME;
  if (!isSafeIdentifier(dbName)) {
    throw new Error('Invalid DB_NAME. Use only letters, numbers, and underscore.');
  }
  const connectTimeout = Number(process.env.DB_CONNECT_TIMEOUT_MS) > 0
    ? Number(process.env.DB_CONNECT_TIMEOUT_MS)
    : 10000;
  const bootstrapLockTimeoutSec = Number(process.env.DB_BOOTSTRAP_LOCK_TIMEOUT_SEC) > 0
    ? Number(process.env.DB_BOOTSTRAP_LOCK_TIMEOUT_SEC)
    : 30;
  const bootstrapLockName = `bootstrap:${dbName}`;

  const adminConnection = await mysql.createConnection({
    host,
    port,
    user,
    password,
    connectTimeout,
    multipleStatements: false,
  });

  try {
    const [lockRows] = await adminConnection.query('SELECT GET_LOCK(?, ?) AS lock_acquired', [bootstrapLockName, bootstrapLockTimeoutSec]);
    const lockAcquired = Array.isArray(lockRows) && lockRows[0] && Number(lockRows[0].lock_acquired) === 1;
    if (!lockAcquired) {
      throw new Error(`Failed to acquire bootstrap lock within ${bootstrapLockTimeoutSec}s`);
    }

    await adminConnection.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
    await adminConnection.query(`USE \`${dbName}\``);

    for (const tableSql of TABLE_DEFINITIONS) {
      await adminConnection.query(tableSql);
    }

    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'users',
      columnName: 'is_suspended',
      definition: 'is_suspended BOOLEAN DEFAULT FALSE',
    });
    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'orders',
      columnName: 'discount_amount',
      definition: 'discount_amount DECIMAL(10,2) DEFAULT 0',
    });
    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'orders',
      columnName: 'payable_amount',
      definition: 'payable_amount DECIMAL(10,2)',
    });
    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'orders',
      columnName: 'coupon_id',
      definition: 'coupon_id VARCHAR(36)',
    });
    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'orders',
      columnName: 'coupon_code',
      definition: 'coupon_code VARCHAR(40)',
    });
    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'orders',
      columnName: 'coupon_discount_type',
      definition: "coupon_discount_type ENUM('percentage','fixed')",
    });
    await ensureColumnExists({
      connection: adminConnection,
      dbName,
      tableName: 'orders',
      columnName: 'coupon_discount_value',
      definition: 'coupon_discount_value DECIMAL(10,2)',
    });
  } finally {
    try {
      await adminConnection.query('SELECT RELEASE_LOCK(?)', [bootstrapLockName]);
    } catch (_) {
      // Ignore release failures; connection close will eventually release lock.
    }
    await adminConnection.end();
  }
};

module.exports = {
  ensureDatabaseAndTables,
};
