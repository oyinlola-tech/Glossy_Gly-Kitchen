CREATE TABLE IF NOT EXISTS webhook_event_receipts (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
