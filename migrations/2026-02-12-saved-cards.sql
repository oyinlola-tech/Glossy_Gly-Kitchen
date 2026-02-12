USE glossy_gly_kitchen;

CREATE TABLE IF NOT EXISTS user_payment_cards (
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
