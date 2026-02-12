USE glossy_gly_kitchen;

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
