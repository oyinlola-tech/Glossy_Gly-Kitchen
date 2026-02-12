USE glossy_gly_kitchen;

ALTER TABLE users
  ADD COLUMN is_suspended BOOLEAN DEFAULT FALSE;

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
