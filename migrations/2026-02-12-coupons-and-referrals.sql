USE glossy_gly_kitchen;

CREATE TABLE IF NOT EXISTS coupons (
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

