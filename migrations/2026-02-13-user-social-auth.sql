CREATE TABLE IF NOT EXISTS user_social_accounts (
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
