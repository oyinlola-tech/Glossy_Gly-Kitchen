CREATE TABLE IF NOT EXISTS user_trusted_devices (
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

CREATE TABLE IF NOT EXISTS user_password_reset_otps (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  otp_code VARCHAR(6) NOT NULL,
  otp_expires DATETIME NOT NULL,
  consumed_at DATETIME,
  created_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_password_reset_otps_lookup (user_id, consumed_at, otp_expires)
);

CREATE TABLE IF NOT EXISTS user_password_reset_sessions (
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
