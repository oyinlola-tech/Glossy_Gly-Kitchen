USE glossy_gly_kitchen;

ALTER TABLE orders
  ADD COLUMN IF NOT EXISTS discount_amount DECIMAL(10,2) DEFAULT 0 AFTER total_amount,
  ADD COLUMN IF NOT EXISTS payable_amount DECIMAL(10,2) NULL AFTER discount_amount,
  ADD COLUMN IF NOT EXISTS coupon_id VARCHAR(36) NULL AFTER payable_amount,
  ADD COLUMN IF NOT EXISTS coupon_code VARCHAR(40) NULL AFTER coupon_id,
  ADD COLUMN IF NOT EXISTS coupon_discount_type ENUM('percentage','fixed') NULL AFTER coupon_code,
  ADD COLUMN IF NOT EXISTS coupon_discount_value DECIMAL(10,2) NULL AFTER coupon_discount_type;

UPDATE orders
SET discount_amount = 0,
    payable_amount = total_amount
WHERE payable_amount IS NULL;

ALTER TABLE orders
  ADD INDEX IF NOT EXISTS idx_orders_coupon_id (coupon_id),
  ADD INDEX IF NOT EXISTS idx_orders_coupon_code (coupon_code);

CREATE TABLE IF NOT EXISTS coupon_redemptions (
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
