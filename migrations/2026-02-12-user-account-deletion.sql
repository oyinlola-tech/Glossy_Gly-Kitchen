CREATE TABLE IF NOT EXISTS user_account_deletion_otps (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  otp_code VARCHAR(6) NOT NULL,
  otp_expires DATETIME NOT NULL,
  consumed_at DATETIME,
  created_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_account_deletion_otps_lookup (user_id, consumed_at, otp_expires)
);
